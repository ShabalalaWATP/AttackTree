"""
LLM integration service.
Communicates with OpenAI-compatible endpoints server-side.
API keys and TLS materials never reach the frontend.
"""
import json
import re
import ssl
import time
import logging
from pathlib import Path
from typing import Optional

# Pattern to strip reasoning/thinking tokens from model responses
_THINK_PATTERN = re.compile(r"<think>[\s\S]*?</think>\s*", re.IGNORECASE)


def _strip_thinking(text: str) -> str:
    """Remove <think>...</think> blocks emitted by reasoning models."""
    return _THINK_PATTERN.sub("", text).strip()
import httpx

from ..services.crypto import decrypt_value
from ..services.environment_catalog_service import build_environment_catalog_outline_for_context
from ..services.reference_search_service import format_reference_candidates_for_prompt

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent.parent / "templates_data"
_AGENT_TEMPLATE_EXAMPLE_MAX_NODES = 6


def _model_prefers_max_completion_tokens(model: str) -> bool:
    model_lower = model.lower()
    return any(tag in model_lower for tag in ("o1", "o3", "o4", "gpt-5"))


def _apply_token_budget(payload: dict, max_tokens: int | None, *, use_max_completion_tokens: bool) -> dict:
    request_payload = dict(payload)
    request_payload.pop("max_tokens", None)
    request_payload.pop("max_completion_tokens", None)
    if max_tokens:
        if use_max_completion_tokens:
            request_payload["max_completion_tokens"] = max_tokens
        else:
            request_payload["max_tokens"] = max_tokens
    return request_payload


def _should_retry_with_alternate_token_param(response_text: str, *, used_max_completion_tokens: bool) -> bool:
    lowered = response_text.lower()
    if "unsupported parameter" not in lowered:
        return False
    if used_max_completion_tokens:
        return "max_completion_tokens" in lowered and "max_tokens" in lowered
    return "max_tokens" in lowered and "max_completion_tokens" in lowered


def _build_ssl_context(config: dict) -> Optional[ssl.SSLContext]:
    """Build SSL context from provider config."""
    if not config.get("tls_verify", True):
        return False  # type: ignore

    ctx = ssl.create_default_context()
    ca_path = config.get("ca_bundle_path", "")
    if ca_path:
        ctx.load_verify_locations(ca_path)

    client_cert = config.get("client_cert_path", "")
    client_key = config.get("client_key_path", "")
    if client_cert:
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key or None)

    return ctx


def _build_headers(config: dict, api_key: str) -> dict:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    custom = config.get("custom_headers", {})
    if custom:
        headers.update(custom)
    return headers


async def test_connection(config: dict) -> dict:
    """Test connection to the LLM endpoint. Returns status dict."""
    api_key = decrypt_value(config.get("api_key_encrypted", ""))
    base_url = config.get("base_url", "").rstrip("/")
    model = config.get("model", "")
    timeout = config.get("timeout", 30)

    headers = _build_headers(config, api_key)
    ssl_ctx = _build_ssl_context(config)

    start = time.time()
    try:
        async with httpx.AsyncClient(verify=ssl_ctx if ssl_ctx is not None else True, timeout=timeout) as client:
            # Try models endpoint first
            resp = await client.get(f"{base_url}/models", headers=headers)
            elapsed = int((time.time() - start) * 1000)

            if resp.status_code == 200:
                return {
                    "status": "success",
                    "message": f"Connected successfully ({elapsed}ms). Model: {model}",
                    "elapsed_ms": elapsed,
                }
            else:
                return {
                    "status": "error",
                    "message": f"HTTP {resp.status_code}: {resp.text[:200]}",
                    "elapsed_ms": elapsed,
                }
    except httpx.ConnectError as e:
        return {"status": "error", "message": f"Connection failed: {str(e)}"}
    except ssl.SSLError as e:
        return {"status": "error", "message": f"TLS/SSL error: {str(e)}"}
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}


async def chat_completion(config: dict, messages: list[dict], temperature: float = 0.7,
                          max_tokens: int | None = None, timeout_override: int | None = None) -> dict:
    """Send a chat completion request to the configured endpoint."""
    api_key = decrypt_value(config.get("api_key_encrypted", ""))
    base_url = config.get("base_url", "").rstrip("/")
    model = config.get("model", "")
    timeout = timeout_override or config.get("timeout", 120)

    headers = _build_headers(config, api_key)
    ssl_ctx = _build_ssl_context(config)

    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    use_max_completion_tokens = _model_prefers_max_completion_tokens(model)
    request_payload = _apply_token_budget(
        payload,
        max_tokens,
        use_max_completion_tokens=use_max_completion_tokens,
    )

    start = time.time()
    try:
        async with httpx.AsyncClient(verify=ssl_ctx if ssl_ctx is not None else True, timeout=timeout) as client:
            resp = await client.post(
                f"{base_url}/chat/completions",
                headers=headers,
                json=request_payload,
            )
            if resp.status_code == 400 and _should_retry_with_alternate_token_param(
                resp.text,
                used_max_completion_tokens=use_max_completion_tokens,
            ):
                use_max_completion_tokens = not use_max_completion_tokens
                request_payload = _apply_token_budget(
                    payload,
                    max_tokens,
                    use_max_completion_tokens=use_max_completion_tokens,
                )
                resp = await client.post(
                    f"{base_url}/chat/completions",
                    headers=headers,
                    json=request_payload,
                )
            elapsed = int((time.time() - start) * 1000)

            if resp.status_code == 200:
                data = resp.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                content = _strip_thinking(content)
                usage = data.get("usage", {})
                return {
                    "status": "success",
                    "content": content,
                    "model": data.get("model", model),
                    "tokens": usage.get("total_tokens", 0),
                    "elapsed_ms": elapsed,
                }
            else:
                return {
                    "status": "error",
                    "content": "",
                    "message": f"HTTP {resp.status_code}: {resp.text[:500]}",
                    "elapsed_ms": elapsed,
                }
    except Exception as e:
        logger.error(f"LLM request failed: {e}", exc_info=False)
        return {"status": "error", "content": "", "message": str(e)}


def _coerce_vulnerability_cards(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _summarise_vulnerability_cards(cards: list[dict]) -> str:
    if not cards:
        return ""

    summaries = []
    for index, card in enumerate(cards[:5], start=1):
        fragments = []
        for key, label in (
            ("title", "title"),
            ("software_family", "software"),
            ("software_version", "version"),
            ("affected_component", "component"),
            ("vulnerability_type", "class"),
            ("attack_surface", "surface"),
            ("entry_point", "entry"),
            ("root_cause", "root cause"),
            ("primitive", "primitive"),
            ("reproduction_steps", "repro"),
            ("exploitation_notes", "notes"),
            ("references", "refs"),
        ):
            value = str(card.get(key, "")).strip()
            if value:
                fragments.append(f"{label}: {value}")
        if fragments:
            summaries.append(f"{index}. " + " | ".join(fragments))
    return "\n".join(summaries)


def _derive_suggestion_profile(node_data: dict, technical_depth: str, prompt_profile: str) -> tuple[bool, str]:
    extended_metadata = node_data.get("extended_metadata")
    extended_metadata = extended_metadata if isinstance(extended_metadata, dict) else {}
    metadata_profile = str(extended_metadata.get("prompt_profile", "")).strip().lower()
    effective_profile = (prompt_profile or metadata_profile or "standard").strip().lower()

    project_context = node_data.get("project_context")
    project_context = project_context if isinstance(project_context, dict) else {}
    context_blob = " ".join(
        str(value)
        for value in (
            node_data.get("title", ""),
            node_data.get("description", ""),
            node_data.get("platform", ""),
            node_data.get("attack_surface", ""),
            node_data.get("notes", ""),
            node_data.get("cve_references", ""),
            project_context.get("context_preset", ""),
            project_context.get("root_objective", ""),
            extended_metadata.get("research_domain", ""),
            extended_metadata.get("investigation_summary", ""),
        )
        if value
    ).lower().replace("_", " ").replace("-", " ")

    cards = _coerce_vulnerability_cards(extended_metadata.get("vulnerability_cards"))
    explicit_deep = technical_depth.strip().lower() in {"deep", "deep_technical", "research", "expert"}
    profile_deep = effective_profile in {
        "deep",
        "deep_technical",
        "reverse_engineering",
        "vulnerability_research",
        "exploit_development",
    }
    keyword_deep = any(
        keyword in context_blob
        for keyword in (
            "reverse engineering",
            "reverse-engineering",
            "vulnerability research",
            "binary diff",
            "patch diff",
            "patch-diff",
            "ida",
            "ghidra",
            "binary ninja",
            "frida",
            "win_dbg",
            "windbg",
            "x64dbg",
            "disassembly",
            "decompile",
            "exploit primitive",
            "memory corruption",
            "type confusion",
            "heap overflow",
            "use-after-free",
            "deserialization",
            "browser extension",
            "thick client",
            "desktop client",
            "updater",
            "firmware",
            "ota",
        )
    )
    return explicit_deep or profile_deep or keyword_deep or bool(cards), effective_profile


def build_branch_suggestion_prompt(
    node_data: dict,
    tree_context: str,
    suggestion_type: str,
    additional_context: str = "",
    technical_depth: str = "standard",
    prompt_profile: str = "",
) -> list[dict]:
    """Build a prompt for branch suggestions."""
    node_title = node_data.get("title", "Unknown")
    node_type = node_data.get("node_type", "attack_step")
    node_desc = node_data.get("description", "")
    platform = node_data.get("platform", "")
    attack_surface = node_data.get("attack_surface", "")
    threat_category = node_data.get("threat_category", "")
    required_access = node_data.get("required_access", "")
    required_privileges = node_data.get("required_privileges", "")
    required_tools = node_data.get("required_tools", "")
    required_skill = node_data.get("required_skill", "")
    notes = node_data.get("notes", "")
    cve_references = node_data.get("cve_references", "")
    extended_metadata = node_data.get("extended_metadata")
    extended_metadata = extended_metadata if isinstance(extended_metadata, dict) else {}
    project_context = node_data.get("project_context")
    project_context = project_context if isinstance(project_context, dict) else {}
    reference_candidates = node_data.get("reference_candidates")
    reference_candidates = reference_candidates if isinstance(reference_candidates, list) else []

    deep_technical, effective_profile = _derive_suggestion_profile(
        node_data,
        technical_depth,
        prompt_profile,
    )
    vulnerability_cards = _coerce_vulnerability_cards(
        extended_metadata.get("vulnerability_cards")
    )
    card_summary = _summarise_vulnerability_cards(vulnerability_cards)

    context_lines = [
        f'Node: "{node_title}"',
        f"Type: {node_type}",
        f"Description: {node_desc}",
        f"Platform/Context: {platform or 'Not specified'}",
    ]
    if attack_surface:
        context_lines.append(f"Attack Surface: {attack_surface}")
    if threat_category:
        context_lines.append(f"Threat Category: {threat_category}")
    if required_access:
        context_lines.append(f"Required Access: {required_access}")
    if required_privileges:
        context_lines.append(f"Required Privileges: {required_privileges}")
    if required_tools:
        context_lines.append(f"Known Tools / Tooling Constraints: {required_tools}")
    if required_skill:
        context_lines.append(f"Required Skill Level: {required_skill}")
    if project_context:
        preset_label = _context_preset_label(project_context.get("context_preset", ""))
        context_lines.append(
            "Workspace Context: "
            f"{project_context.get('name', '')} | preset={preset_label or project_context.get('context_preset', 'general')} | "
            f"objective={project_context.get('root_objective', '')}"
        )
    if effective_profile and effective_profile != "standard":
        context_lines.append(f"Prompt Profile: {effective_profile}")
    if notes:
        context_lines.append(f"Analyst Notes: {notes}")
    if cve_references:
        context_lines.append(f"CVE / Advisory References: {cve_references}")
    if extended_metadata.get("research_domain"):
        context_lines.append(f"Research Domain: {extended_metadata.get('research_domain')}")
    if extended_metadata.get("investigation_summary"):
        context_lines.append(
            f"Investigation Summary: {extended_metadata.get('investigation_summary')}"
        )
    if card_summary:
        context_lines.append("Vulnerability Cards:\n" + card_summary)
    if additional_context.strip():
        context_lines.append("Additional Analyst Context:\n" + additional_context.strip())
    if reference_candidates:
        context_lines.append(format_reference_candidates_for_prompt(reference_candidates))
    context_lines.append("Tree context:")
    context_lines.append(tree_context)
    context_block = "\n".join(context_lines)

    deep_guidance = ""
    if deep_technical:
        deep_guidance = """
Deep technical requirements:
- Respond like a vulnerability researcher and reverse engineer, not a generic threat modeller.
- When relevant, reason in terms of exploit primitives, parser states, trust boundaries, update/signing flows, IPC/RPC surfaces, memory corruption hypotheses, sandbox escapes, or auth/crypto implementation defects.
- Reference concrete tooling and workflows where useful: IDA Pro, Ghidra, Binary Ninja, Frida, WinDbg, x64dbg, LLDB, jadx, apktool, radare2, Burp Suite, AFL++, libFuzzer, QEMU, diffing, patch analysis, hook-based tracing, and crash triage.
- Use the vulnerability cards as evidence and extend them into adjacent attack paths, exploit-development tasks, code-level mitigations, or low-noise detections.
- Avoid generic phrasing such as "exploit vulnerability" without naming the likely bug class, reversing task, or abuse path.
""".strip()

    type_prompts = {
        "branches": f"""You are an expert red-team cyber security analyst. Given the following attack tree node, suggest 3-6 likely child attack steps or sub-goals that an attacker would need to accomplish.

{context_block}

{deep_guidance}

For each suggestion, write a detailed description (4-6 sentences) from the attacker's perspective: what exactly they do, which tools or scripts they use, what vulnerability or misconfiguration they exploit, what they gain on success, and how they evade detection. Reference real tools, CVEs, exploit classes, and MITRE ATT&CK technique IDs where applicable.

Return a JSON array of objects with these fields:
- title: specific attack step title (include technique name)
- description: detailed 4-6 sentence attacker-perspective description
- node_type: one of goal, sub_goal, attack_step, precondition, weakness, pivot_point
- logic_type: OR or AND
- threat_category: MITRE ATT&CK-aligned category
- likelihood: estimated likelihood 1-10
- impact: estimated impact 1-10

Return ONLY valid JSON array, no markdown formatting.""",

        "mitigations": f"""You are an expert cyber security analyst with red-team and blue-team experience. For the following attack step, suggest 3-5 specific mitigations or security controls.

{context_block}

{deep_guidance}

For each mitigation, provide detailed implementation guidance (2-4 sentences): specific product names, configuration settings, compiler or linker hardening, sandboxing, parser isolation, secure coding changes, update-signing controls, policy settings, firewall rules, or code changes. Explain what attacker behaviour it blocks and any limitations.

Return a JSON array of objects:
- title: specific mitigation title
- description: detailed implementation guidance (2-4 sentences)
- effectiveness: 0.0 to 1.0

Return ONLY valid JSON array.""",

        "detections": f"""You are an expert detection engineer and threat hunter. For the following attack step, suggest 3-5 specific detection opportunities.

{context_block}

{deep_guidance}

For each detection, provide specific details (2-4 sentences): exact log sources and event IDs to monitor, runtime telemetry, crash signals, ETW/EDR traces, debugger or instrumentation indicators, example detection queries (Sigma, KQL, or SPL snippets), the attacker behaviour it catches, and false positive considerations.

Return a JSON array of objects:
- title: specific detection title
- description: detailed detection guidance (2-4 sentences)
- coverage: 0.0 to 1.0
- data_source: specific log source and event IDs

Return ONLY valid JSON array.""",

        "mappings": f"""You are a cyber security analyst. For the following attack step, suggest relevant MITRE ATT&CK techniques, CAPEC patterns, CWE weaknesses, and OWASP categories.

{context_block}

{deep_guidance}

Prefer the retrieved candidate references when provided. You may also use Infrastructure Attack Patterns, Software Security Research Patterns, or Environment Catalog anchors if they are materially useful and present in the candidate list.
Prefer concrete weakness IDs that match the exploit primitive or bug class described in the node and vulnerability cards.

Return a JSON array of objects:
- framework: one of "attack", "capec", "cwe", "owasp", "infra_attack_patterns", "software_research_patterns", "environment_catalog"
- ref_id: the reference ID (e.g., T1566, CAPEC-98, CWE-89, A01:2021)
- ref_name: the reference name
- confidence: 0.0 to 1.0
- rationale: brief reason this mapping fits

Return ONLY valid JSON array.""",
    }

    prompt_text = type_prompts.get(suggestion_type, type_prompts["branches"])
    system_prompt = (
        "You are an expert cyber security attack tree analyst. "
        "Respond only with valid JSON."
    )
    if deep_technical:
        system_prompt = (
            "You are an expert cyber security attack tree analyst, vulnerability researcher, and reverse engineer. "
            "Respond only with valid JSON."
        )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt_text},
    ]


def build_summary_prompt(project_data: dict, nodes_data: list[dict], summary_type: str) -> list[dict]:
    """Build prompt for project summary generation."""
    project_name = project_data.get("name", "")
    root_objective = project_data.get("root_objective", "")

    # Build tree summary
    node_summary_lines = []
    for n in nodes_data[:50]:  # Limit context
        risk = n.get("inherent_risk") or n.get("rolled_up_risk") or "unscored"
        node_summary_lines.append(f"- [{n.get('node_type', '')}] {n.get('title', '')} (risk: {risk}, status: {n.get('status', '')})")

    tree_text = "\n".join(node_summary_lines)

    if summary_type == "executive":
        prompt = f"""You are a cyber security consultant writing an executive summary.

Project: {project_name}
Root Objective (attacker goal): {root_objective}

Attack tree nodes:
{tree_text}

Write a concise executive summary (3-5 paragraphs) covering:
1. What the attacker is trying to achieve
2. The most likely and highest-impact attack paths
3. Key gaps in current defences
4. Top recommended mitigations
5. Overall risk posture

Use clear, non-technical language suitable for senior management."""
    else:
        prompt = f"""You are a cyber security analyst writing a technical report section.

Project: {project_name}
Root Objective (attacker goal): {root_objective}

Attack tree nodes:
{tree_text}

Write a detailed technical summary covering:
1. Attack tree overview and scope
2. Critical attack paths with risk scores
3. Key weaknesses and vulnerabilities identified
4. Current mitigation coverage and gaps
5. Detection opportunities
6. Recommendations prioritised by risk reduction

Use precise technical language."""

    return [
        {"role": "system", "content": "You are an expert cyber security analyst."},
        {"role": "user", "content": prompt},
    ]


def _template_metadata_lines(template: dict | None) -> list[str]:
    if not template:
        return []

    lines = []
    template_family = template.get("template_family")
    technical_profile = template.get("technical_profile")
    focus_areas = template.get("focus_areas", [])
    prompt_hints = template.get("prompt_hints", [])

    if template_family:
        lines.append(f"Template Family: {template_family}")
    if technical_profile:
        lines.append(f"Technical Profile: {technical_profile}")
    if focus_areas:
        lines.append("Focus Areas: " + ", ".join(str(item) for item in focus_areas[:6]))
    if prompt_hints:
        lines.append("Prompt Hints:")
        lines.extend(f"- {hint}" for hint in prompt_hints[:4])
    return lines


def _template_needs_deep_guidance(template: dict | None) -> bool:
    if not template:
        return False
    technical_profile = str(template.get("technical_profile", "")).strip().lower()
    return technical_profile in {
        "deep",
        "deep_technical",
        "reverse_engineering",
        "vulnerability_research",
        "exploit_development",
    }


def _build_technical_generation_guidance() -> str:
    return """
Deep technical generation requirements:
- Model the operation at exploit-development and reverse-engineering depth where relevant.
- Prefer concrete workflows such as patch diffing, decompilation, disassembly, runtime instrumentation, protocol reversing, crash triage, fuzzing, exploit primitive extraction, trust-boundary abuse, and update-chain analysis.
- Name realistic tooling, debug surfaces, bug classes, and likely operator decision points instead of generic attacker actions.
- Where useful, reference concrete exploit classes such as type confusion, memory corruption, deserialization, sandbox escape, insecure update validation, client-side trust abuse, or parser state-machine flaws.
""".strip()


_GENERATION_PROFILE_LABELS = {
    "planning_first": "Planning-first",
    "balanced": "Balanced",
    "reference_heavy": "Reference-heavy",
}


def normalize_planning_profile(value: str) -> str:
    return _normalize_generation_profile(value)


def get_planning_profile_label(value: str) -> str:
    return _GENERATION_PROFILE_LABELS.get(normalize_planning_profile(value), "Balanced")


def get_context_preset_label(value: str) -> str:
    return _context_preset_label(value)


def detect_planning_domain(objective: str, scope: str = "", context_preset: str = "") -> str:
    return _detect_domain(objective, scope, context_preset)


def get_domain_decomposition_guidance(domain: str) -> str:
    return _get_domain_decomposition_guidance(domain)


def get_planning_profile_guidance(planning_profile: str, domain: str) -> str:
    return _get_generation_profile_guidance(normalize_planning_profile(planning_profile), domain)


def build_agent_tree_prompt(objective: str, scope: str, depth: int, breadth: int,
                            template_example: dict | None = None,
                            reference_arch: str = "",
                            generation_profile: str = "balanced",
                            context_preset: str = "") -> list[dict]:
    """Build a prompt for the AI Agent to generate a full attack tree.

    Args:
        objective: The attacker's goal
        scope: Target description
        depth: Max tree depth
        breadth: Max children per parent
        template_example: Optional template dict to use as few-shot example
        reference_arch: Optional reference architecture description
        generation_profile: planning_first | balanced | reference_heavy
        context_preset: Project workspace context preset
    """
    # --- Domain detection for specialised system prompts ---
    generation_profile = _normalize_generation_profile(generation_profile)
    domain = _detect_domain(objective, scope, context_preset)
    system = _get_domain_system_prompt(domain)
    profile_label = _GENERATION_PROFILE_LABELS.get(generation_profile, "Balanced")
    deep_guidance_added = False
    context_label = _context_preset_label(context_preset)

    # --- Build user prompt ---
    user_parts = [f"""Generate a complete attack tree for the following objective.

**Attacker Objective:** {objective}
**Scope / Target Description:** {scope}
**Generation Profile:** {profile_label}
{f"**Workspace Context Preset:** {context_label}\n" if context_label else ""}**Tree Depth:** up to {depth} levels deep
**Breadth:** up to {breadth} child nodes per parent"""]
    user_parts.append(_get_domain_decomposition_guidance(domain))
    user_parts.append(_get_generation_profile_guidance(generation_profile, domain))
    environment_catalog_context = build_environment_catalog_outline_for_context(objective, scope, context_preset)
    if environment_catalog_context:
        user_parts.append(environment_catalog_context)

    if domain == "software_research":
        user_parts.append(_build_technical_generation_guidance())
        deep_guidance_added = True

    # --- Reference architecture context ---
    if reference_arch:
        user_parts.append(f"\n**Reference Architecture:**\n{reference_arch}")
    else:
        arch = _get_reference_architecture(domain)
        if arch:
            user_parts.append(f"\n**Reference Architecture:**\n{arch}")

    # --- Few-shot template example ---
    if template_example:
        example_text = json.dumps(
            _template_to_tree_example(
                template_example,
                max_nodes=_AGENT_TEMPLATE_EXAMPLE_MAX_NODES,
            ),
            indent=2,
        )
        metadata_lines = _template_metadata_lines(template_example)
        if metadata_lines:
            user_parts.append("\n**Template metadata:**\n" + "\n".join(metadata_lines))
        if _template_needs_deep_guidance(template_example) and not deep_guidance_added:
            user_parts.append(_build_technical_generation_guidance())
            deep_guidance_added = True
        user_parts.append(f"""
**Example structure** (compact few-shot example; use this as a reference for quality, depth, and field population — do NOT copy it verbatim, generate original content for the given objective):
```json
{example_text}
```""")

    user_parts.append("""
Return a single JSON object representing the root node. Every node MUST have ALL of these fields:
- "title": concise but specific node title that reflects the concrete action, trust boundary, actor path, or domain branch (e.g. "Abuse Remote Hands Contractor Access" or "Kerberoast Service Account Hashes")
- "description": detailed 4-8 sentence technical description written from the attacker's perspective. For higher-level branches, explain the attack surface, why it matters, and the main technical avenues beneath it. For concrete attack steps, include what the attacker does step-by-step, specific tools or scripts used (e.g. Impacket, Rubeus, sqlmap, Burp Suite, Cobalt Strike, Metasploit), the exact vulnerability class or misconfiguration exploited if one exists, what the attacker gains on success, and real-world CVEs or APT campaigns where applicable. Write as if briefing a red team operator.
- "node_type": one of "goal", "sub_goal", "attack_step", "precondition", "weakness", "pivot_point"
- "logic_type": "AND" or "OR" (AND = all children required in sequence, OR = any one suffices)
- "status": one of "draft", "validated", "mitigated", "accepted" — set "validated" for well-known TTPs, "draft" for speculative paths
- "platform": target platform/environment (e.g. "Windows Server 2022", "Linux/Docker", "AWS Cloud", "Physical Facility", "Cisco IOS", "Azure AD")
- "attack_surface": the attack surface (e.g. "Network Perimeter", "Web Application", "API Endpoint", "Physical Access", "Email/Phishing", "Supply Chain", "Wireless", "USB/Removable Media")
- "threat_category": MITRE-aligned category (e.g. "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact")
- "required_access": access level needed (e.g. "None/Public", "Network Adjacent", "Local", "Physical", "Authenticated User", "VPN")
- "required_privileges": privilege level (e.g. "None", "User", "Administrator/Root", "SYSTEM", "Domain Admin", "Cloud Admin")
- "required_skill": skill level (e.g. "Low", "Medium", "High", "Expert")
- "likelihood": integer 1-10 reflecting real-world feasibility
- "impact": integer 1-10 reflecting damage severity
- "effort": integer 1-10 (attacker effort, 1=trivial, 10=months of work)
- "exploitability": integer 1-10 (how easy to exploit, 10=trivially exploitable)
- "detectability": integer 1-10 (how detectable, 1=stealthy, 10=easily detected)
- "children": array of child nodes (same structure, recursively)

Rules:
1. The root node must be node_type "goal" with logic_type "OR"
2. Second-level nodes should be "sub_goal" nodes representing distinct attack-surface domains, trust boundaries, actor groups, or operational attack paths
3. Third-level and deeper nodes should move from conceptual branches into specific attack_step, precondition, weakness, or pivot_point nodes
4. Use AND logic where multiple steps are ALL required in sequence
5. Use OR logic where alternative approaches exist
6. Be specific and realistic. Use real TTPs, tools, vulnerability classes, CVEs, and attack techniques once a branch is concrete enough to justify them
7. Cover diverse attack vectors: network, physical, social engineering, supply chain, insider threat where applicable
8. Leaf nodes should be concrete, actionable attack steps with enough detail for a red team operator to execute
9. Every single field listed above MUST be populated for every node — no empty strings, no nulls
10. Platform and attack_surface must be specific to each node's context, not generic
11. Descriptions must read like a red team playbook — include tools, techniques, evasion methods, and expected outcomes
12. Reference real CVEs, MITRE ATT&CK technique IDs, CAPEC patterns, or named malware/APT campaigns where relevant, but use them as enrichment and evidence rather than the primary structure for the first layers of the tree
13. Do not use raw CWE, CAPEC, ATT&CK technique IDs, or CVE identifiers as second-level nodes

Return ONLY the JSON object. Do not wrap in markdown code blocks.""")

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": "\n".join(user_parts)},
    ]


def build_template_expand_prompt(template: dict, objective: str, scope: str,
                                  depth: int, breadth: int,
                                  generation_profile: str = "balanced",
                                  context_preset: str = "") -> list[dict]:
    """Build a prompt that takes a template skeleton and asks the AI to expand and customise it."""
    generation_profile = _normalize_generation_profile(generation_profile)
    domain_context = context_preset or str(template.get("context_preset", ""))
    domain = _detect_domain(objective, scope, domain_context)
    system = _get_domain_system_prompt(domain)
    metadata_lines = _template_metadata_lines(template)
    deep_guidance = (
        _build_technical_generation_guidance()
        if domain == "software_research" or _template_needs_deep_guidance(template)
        else ""
    )
    profile_label = _GENERATION_PROFILE_LABELS.get(generation_profile, "Balanced")

    # Convert template to a simplified tree structure for the prompt
    template_tree = json.dumps(_template_nodes_to_tree(template), indent=2)
    metadata_block = ""
    if metadata_lines:
        metadata_block = "\n**Template metadata:**\n" + "\n".join(metadata_lines)
    reference_arch = _get_reference_architecture(domain)
    reference_block = f"\n**Reference Architecture:**\n{reference_arch}" if reference_arch else ""
    decomposition_guidance = _get_domain_decomposition_guidance(domain)
    profile_guidance = _get_generation_profile_guidance(generation_profile, domain)
    environment_catalog_context = build_environment_catalog_outline_for_context(objective, scope, domain_context)
    environment_catalog_block = f"\n{environment_catalog_context}" if environment_catalog_context else ""
    deep_guidance_block = f"\n{deep_guidance}" if deep_guidance else ""
    context_label = _context_preset_label(domain_context)

    user_prompt = f"""You are given an existing attack tree template as a starting skeleton. Your job is to:
1. Keep the overall structure but EXPAND each branch with {breadth-1} to {breadth} additional child nodes per parent
2. CUSTOMISE all node descriptions, platforms, and attack surfaces for the specific target described below
3. ADD missing attack vectors not covered in the template
4. DEEPEN the tree to {depth} levels where the template is shallower
5. Populate ALL required fields with values specific to this target

**Attacker Objective:** {objective}
**Scope / Target Description:** {scope}
**Generation Profile:** {profile_label}
{f"**Workspace Context Preset:** {context_label}\n" if context_label else ""}**Expand to Depth:** {depth} levels
**Expand to Breadth:** {breadth} children per parent
{metadata_block}
{reference_block}
{decomposition_guidance}
{profile_guidance}
{environment_catalog_block}
{deep_guidance_block}

**Starting Template (skeleton — expand this, do NOT just copy it):**
```json
{template_tree}
```

Return a single JSON object representing the expanded root node with the same field requirements:
- "title", "description", "node_type", "logic_type", "status", "platform", "attack_surface",
  "threat_category", "required_access", "required_privileges", "required_skill",
  "likelihood" (1-10), "impact" (1-10), "effort" (1-10), "exploitability" (1-10),
  "detectability" (1-10), "children" (array of child nodes, recursively)
- Preserve a planning-useful top structure. Add missing attack-surface domains, actor paths, trust boundaries, or operational layers if the template is too narrow.
- Do not replace the first layers with a flat list of CWE, CAPEC, ATT&CK, or CVE references.

Return ONLY the JSON object. No markdown, no commentary."""

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user_prompt},
    ]


def build_gap_analysis_prompt(existing_nodes: list[dict], objective: str, scope: str,
                              generation_profile: str = "balanced",
                              context_preset: str = "") -> list[dict]:
    """Build a prompt to analyse an existing tree and suggest missing attack paths."""
    generation_profile = _normalize_generation_profile(generation_profile)
    domain = _detect_domain(objective, scope, context_preset)
    profile_label = _GENERATION_PROFILE_LABELS.get(generation_profile, "Balanced")
    context_label = _context_preset_label(context_preset)

    # Summarise existing tree
    node_lines = []
    for n in existing_nodes[:60]:
        node_lines.append(
            f"  - [{n.get('node_type', '')}] {n.get('title', '')} "
            f"(likelihood={n.get('likelihood', '?')}, impact={n.get('impact', '?')}, "
            f"status={n.get('status', 'draft')})"
        )
    tree_text = "\n".join(node_lines)

    system = (
        "You are an expert red-team analyst conducting a gap analysis on an attack tree. "
        "You identify missing attack paths, overlooked vectors, and coverage blind spots. "
        "Respond ONLY with valid JSON — no markdown, no commentary."
    )
    if domain == "software_research":
        system = (
            "You are an expert vulnerability researcher, reverse engineer, and red-team analyst conducting a gap analysis on an attack tree. "
            "You identify missing exploit-development tasks, reversing steps, trust-boundary abuses, and coverage blind spots. "
            "Respond ONLY with valid JSON — no markdown, no commentary."
        )
    environment_catalog_context = build_environment_catalog_outline_for_context(objective, scope, context_preset)

    user_prompt = f"""Analyse the following attack tree and identify MISSING attack paths, vectors, and weaknesses that are NOT yet covered.

**Attacker Objective:** {objective}
**Scope:** {scope}
**Generation Profile:** {profile_label}
{f"**Workspace Context Preset:** {context_label}\n" if context_label else ""}

{_get_domain_decomposition_guidance(domain)}
{_get_generation_profile_guidance(generation_profile, domain)}
{environment_catalog_context}

**Existing attack tree nodes:**
{tree_text}

Generate ONLY the NEW nodes that should be added to fill gaps. Return a JSON array of new branches, where each branch is a tree object (same recursive structure):
- "title", "description", "node_type", "logic_type", "status", "platform", "attack_surface",
  "threat_category", "required_access", "required_privileges", "required_skill",
  "likelihood" (1-10), "impact" (1-10), "effort" (1-10), "exploitability" (1-10),
  "detectability" (1-10), "children" (array, recursively)
- "attach_to": title of the existing node this branch should be added under (use the root goal title if it's a new top-level path)

Focus on:
1. Missing attack-surface domains, trust boundaries, actor groups, or operational layers
2. Attack vectors not covered (e.g., if only network attacks exist, add physical/social/supply-chain)
3. Missing preconditions and weaknesses
4. Alternative techniques for existing attack steps
5. Detection evasion, persistence, and lateral movement gaps
6. Reference-heavy technical branches only after checking whether the conceptual coverage is already complete

Return ONLY the JSON array. No markdown, no commentary."""

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user_prompt},
    ]


def build_agent_branch_expansion_prompt(
    objective: str,
    scope: str,
    ancestor_chain: list[dict],
    branch_node: dict,
    sibling_titles: list[str],
    remaining_depth: int,
    breadth: int,
    generation_profile: str = "balanced",
    context_preset: str = "",
) -> list[dict]:
    """Build a prompt to expand one branch using only local branch context."""
    generation_profile = _normalize_generation_profile(generation_profile)
    domain = _detect_domain(objective, scope, context_preset)
    system = _get_domain_system_prompt(domain)
    profile_label = _GENERATION_PROFILE_LABELS.get(generation_profile, "Balanced")
    context_label = _context_preset_label(context_preset)
    environment_catalog_context = build_environment_catalog_outline_for_context(
        objective,
        scope,
        context_preset,
    )
    reference_arch = _get_reference_architecture(domain)
    deep_guidance = _build_technical_generation_guidance() if domain == "software_research" else ""

    ancestor_lines = []
    for index, node in enumerate(ancestor_chain, start=1):
        ancestor_lines.append(
            f"{index}. [{node.get('node_type', 'attack_step')}] {node.get('title', 'Untitled')} | "
            f"surface={node.get('attack_surface', 'n/a') or 'n/a'} | "
            f"platform={node.get('platform', 'n/a') or 'n/a'} | "
            f"category={node.get('threat_category', 'n/a') or 'n/a'}"
        )
    ancestor_block = "\n".join(ancestor_lines) if ancestor_lines else "1. [goal] Root objective"

    sibling_block = "\n".join(f"- {title}" for title in sibling_titles if title.strip()) or "- None"
    branch_summary = json.dumps(
        {
            "title": branch_node.get("title", "Untitled"),
            "description": branch_node.get("description", ""),
            "node_type": branch_node.get("node_type", "sub_goal"),
            "logic_type": branch_node.get("logic_type", "OR"),
            "status": branch_node.get("status", "draft"),
            "platform": branch_node.get("platform", ""),
            "attack_surface": branch_node.get("attack_surface", ""),
            "threat_category": branch_node.get("threat_category", ""),
            "required_access": branch_node.get("required_access", ""),
            "required_privileges": branch_node.get("required_privileges", ""),
            "required_skill": branch_node.get("required_skill", ""),
            "likelihood": branch_node.get("likelihood"),
            "impact": branch_node.get("impact"),
            "effort": branch_node.get("effort"),
            "exploitability": branch_node.get("exploitability"),
            "detectability": branch_node.get("detectability"),
        },
        indent=2,
    )

    user_parts = [f"""Expand one branch of an attack tree using only the local branch context below.

**Attacker Objective:** {objective}
**Scope / Target Description:** {scope}
**Generation Profile:** {profile_label}
{f"**Workspace Context Preset:** {context_label}\n" if context_label else ""}**Additional Levels To Generate Below This Branch:** {remaining_depth}
**Breadth:** up to {breadth} child nodes per parent

{_get_generation_profile_guidance(generation_profile, domain)}
{environment_catalog_context}
{f"\n**Reference Architecture:**\n{reference_arch}" if reference_arch else ""}
{f"\n{deep_guidance}" if deep_guidance else ""}

**Ancestor Path Already Established**
{ancestor_block}

**Current Branch Node To Expand**
```json
{branch_summary}
```

**Sibling Branches Already Covered Elsewhere**
{sibling_block}
"""]

    user_parts.append("""
Generate ONLY the new children for the current branch node as a JSON array. Do not regenerate the current branch node itself.

Every generated node MUST populate all of these fields:
- "title"
- "description"
- "node_type"
- "logic_type"
- "status"
- "platform"
- "attack_surface"
- "threat_category"
- "required_access"
- "required_privileges"
- "required_skill"
- "likelihood"
- "impact"
- "effort"
- "exploitability"
- "detectability"
- "children"

Rules:
1. Keep this expansion scoped to the current branch and ancestor path. Do not restate the full tree.
2. Do not duplicate sibling coverage unless it is a necessary dependency unique to this branch.
3. Move from planning-useful child branches into concrete attack steps as the depth increases.
4. Return up to the requested remaining depth below this branch. If only one level remains, return leaf nodes.
5. Use AND logic when multiple prerequisites are all required; use OR logic for alternatives.
6. Write descriptions as technical red-team guidance with concrete tools, exploit classes, and expected attacker outcomes.
7. Keep child titles distinct from the sibling branches listed above.

Return ONLY the JSON array. No markdown, no commentary.""")

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": "\n".join(user_parts)},
    ]


def build_mitigations_detections_pass_prompt(nodes_summary: list[dict]) -> list[dict]:
    """Build a prompt for Pass 4: generate mitigations and detections for leaf nodes."""
    system = (
        "You are an expert blue-team defender and detection engineer with red-team experience. "
        "For each attack step leaf node, suggest specific, detailed mitigations and detection opportunities. "
        "Include specific product/tool names, configuration guidance, detection queries (e.g. Sigma rules, KQL, SPL), "
        "and explain the attacker behaviour each detection catches. "
        "Respond ONLY with valid JSON — no markdown, no commentary."
    )

    nodes_text = json.dumps(nodes_summary, indent=2)
    user_prompt = f"""For each of the following attack tree leaf nodes, suggest detailed mitigations and detections.

{nodes_text}

Return a JSON array with one object per node:
- "index": the original index number
- "mitigations": array of {{"title": "specific control name", "description": "2-4 sentences: what it does, how to implement it, specific products or configurations (e.g. 'Enable Credential Guard via Group Policy', 'Deploy ModSecurity with OWASP CRS v4')", "effectiveness": 0.0-1.0}}
- "detections": array of {{"title": "specific detection name", "description": "2-4 sentences: what attacker behaviour it detects, example detection logic or query, false positive considerations", "coverage": 0.0-1.0, "data_source": "specific log source (e.g. Windows Security Event 4768, Sysmon Event 1, CloudTrail, WAF logs)"}}

Provide 3-5 mitigations and 3-5 detections per node. Be specific — reference real products, event IDs, and detection signatures.
Return ONLY the JSON array."""

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user_prompt},
    ]


def build_reference_mapping_pass_prompt(nodes_summary: list[dict]) -> list[dict]:
    """Build a prompt for Pass 3: validated reference mappings for nodes."""
    system = (
        "You are an expert cyber security analyst who maps attack steps to reference frameworks. "
        "Respond ONLY with valid JSON — no markdown, no commentary."
    )

    nodes_text = json.dumps(nodes_summary, indent=2)
    user_prompt = f"""For each of the following attack tree nodes, suggest the most relevant reference mappings.

Use the supplied candidate references as the primary source of truth. Prefer those candidates over unsupported free-form IDs.
Only return mappings that are strongly justified by the node text and the retrieved candidates.

{nodes_text}

Return a JSON array with one object per node:
- "index": the original index number
- "mappings": array of {{"framework": "attack"|"capec"|"cwe"|"owasp"|"infra_attack_patterns"|"software_research_patterns"|"environment_catalog", "ref_id": "validated local reference id", "ref_name": "human-readable name", "confidence": 0.0-1.0, "rationale": "brief reason"}}

Return ONLY the JSON array."""

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user_prompt},
    ]


def build_enrich_nodes_prompt(nodes_summary: list[dict]) -> list[dict]:
    """Build a prompt to enrich nodes that have missing fields."""
    system = (
        "You are an expert cyber security red-team analyst. "
        "You enrich attack tree nodes with detailed technical metadata. "
        "Respond ONLY with valid JSON — no markdown, no commentary."
    )

    nodes_text = json.dumps(nodes_summary, indent=2)
    user_prompt = f"""The following attack tree nodes have incomplete fields. For each node, fill in ALL missing or empty fields with detailed, attacker-perspective content.

{nodes_text}

Return a JSON array of objects, one per node in the same order. Each object must have:
- "index": the original index number
- "description": detailed 4-8 sentence technical description from the attacker's perspective — include specific tools, exploitation steps, what is gained, and real-world references
- "status": one of "draft", "validated", "mitigated", "accepted"
- "platform": specific platform/environment (e.g. "Windows Server 2022" not just "Windows")
- "attack_surface": specific attack surface (e.g. "Kerberos Authentication Protocol" not just "Network")
- "threat_category": MITRE ATT&CK-aligned category
- "required_access": access level needed
- "required_privileges": privilege level needed
- "required_skill": one of "Low", "Medium", "High", "Expert"
- "effort": integer 1-10
- "exploitability": integer 1-10
- "detectability": integer 1-10

Return ONLY the JSON array."""

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user_prompt},
    ]


def parse_json_object_response(content: str) -> dict:
    """Parse a JSON object from LLM response, with robust recovery for truncated output."""
    content = _strip_markdown_fences(content)

    # Direct parse
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # Find outermost JSON object
    start = content.find("{")
    if start < 0:
        return {}

    # Use bracket counting to find the matching close brace
    depth = 0
    in_str = False
    escape = False
    best_end = -1
    for i in range(start, len(content)):
        ch = content[i]
        if escape:
            escape = False
            continue
        if ch == '\\':
            escape = True
            continue
        if ch == '"' and not escape:
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                best_end = i
                break

    if best_end > start:
        try:
            return json.loads(content[start:best_end + 1])
        except json.JSONDecodeError:
            pass

    # Last resort: try to repair truncated JSON by closing open braces/brackets
    raw = content[start:] if start >= 0 else content
    repaired = _repair_truncated_json(raw)
    if repaired:
        try:
            parsed = json.loads(repaired)
            if isinstance(parsed, dict):
                logger.warning("Used JSON repair to recover truncated LLM response")
                return parsed
        except json.JSONDecodeError:
            pass

    return {}


def parse_json_response(content: str) -> list[dict]:
    """Parse JSON from LLM response, handling common formatting issues."""
    content = _strip_markdown_fences(content)

    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        # Try to find JSON array in the text
        start = content.find("[")
        end = content.rfind("]")
        if start >= 0 and end > start:
            try:
                return json.loads(content[start:end + 1])
            except json.JSONDecodeError:
                pass

    return []


# ── Helper functions ────────────────────────────────────────────

def _strip_markdown_fences(content: str) -> str:
    """Remove markdown code fences from LLM output."""
    content = content.strip()
    if content.startswith("```"):
        lines = content.split("\n")
        content = "\n".join(lines[1:])
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()
    return content


def _repair_truncated_json(raw: str) -> str | None:
    """Attempt to repair truncated JSON by closing open braces and brackets."""
    # Remove any trailing incomplete key-value or string
    raw = raw.rstrip()
    # Remove trailing comma
    raw = raw.rstrip(",").rstrip()
    # Remove incomplete string at end
    if raw.count('"') % 2 != 0:
        last_quote = raw.rfind('"')
        # Find the start of this incomplete key-value
        last_newline = raw.rfind("\n", 0, last_quote)
        if last_newline > 0:
            raw = raw[:last_newline].rstrip().rstrip(",")

    # Count unclosed braces/brackets
    opens = []
    in_str = False
    escape = False
    for ch in raw:
        if escape:
            escape = False
            continue
        if ch == '\\':
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch in ('{', '['):
            opens.append(ch)
        elif ch == '}' and opens and opens[-1] == '{':
            opens.pop()
        elif ch == ']' and opens and opens[-1] == '[':
            opens.pop()

    if not opens:
        return raw

    # Close in reverse order
    closers = []
    for o in reversed(opens):
        closers.append('}' if o == '{' else ']')

    return raw + "".join(closers)


_CONTEXT_PRESET_DOMAIN_MAP = {
    "general": "general",
    "web_application": "web_app",
    "api_microservice": "web_app",
    "android_application": "software_research",
    "thick_client": "software_research",
    "software_reverse_engineering": "software_research",
    "vulnerability_research": "software_research",
    "embedded_firmware_research": "software_research",
    "enterprise": "enterprise",
    "cloud_iam": "cloud",
    "data_centre": "data_centre",
    "data_center": "data_centre",
    "telecoms_base_station": "telecommunications",
    "telecoms_5g_core": "telecommunications",
    "satellite_ground_station": "telecommunications",
    "airport": "ot_ics",
    "ot_ics": "ot_ics",
    "hybrid_it_ot": "ot_ics",
    "electrical_substation": "power_energy",
    "water_treatment_plant": "ot_ics",
    "manufacturing_facility": "ot_ics",
    "defence_manufacturing_plant": "ot_ics",
    "pharma_manufacturing_plant": "ot_ics",
    "ev_charging_network": "ot_ics",
    "military_headquarters": "enterprise",
    "oil_refinery": "ot_ics",
    "drilling_rig": "ot_ics",
    "shipyard_naval_base": "ot_ics",
    "lng_terminal": "ot_ics",
    "port_maritime_terminal": "ot_ics",
    "oil_gas_pipeline": "ot_ics",
    "power_station": "power_energy",
    "nuclear_power_plant": "power_energy",
    "ai_llm": "cloud",
    "supply_chain": "enterprise",
}

_CONTEXT_PRESET_LABEL_MAP = {
    "general": "General",
    "web_application": "Web Application",
    "api_microservice": "API / Microservice",
    "android_application": "Android Application",
    "thick_client": "Thick Client / Desktop",
    "software_reverse_engineering": "Software Reverse Engineering",
    "vulnerability_research": "Vulnerability Research",
    "embedded_firmware_research": "Embedded Firmware Research",
    "enterprise": "Enterprise / Active Directory",
    "cloud_iam": "Cloud / IAM / Kubernetes",
    "data_centre": "Data Centre / Facilities",
    "data_center": "Data Centre / Facilities",
    "telecoms_base_station": "Telecoms Base Station",
    "telecoms_5g_core": "Telecoms 5G Core",
    "satellite_ground_station": "Satellite Ground Station",
    "airport": "Airport",
    "ot_ics": "OT / ICS",
    "hybrid_it_ot": "Hybrid IT/OT",
    "electrical_substation": "Electrical Substation",
    "water_treatment_plant": "Water Treatment Plant",
    "manufacturing_facility": "Manufacturing Facility",
    "defence_manufacturing_plant": "Defence Manufacturing Plant",
    "pharma_manufacturing_plant": "Pharma Manufacturing Plant",
    "ev_charging_network": "EV Charging Network",
    "military_headquarters": "Military Headquarters",
    "oil_refinery": "Oil Refinery",
    "drilling_rig": "Drilling Rig",
    "shipyard_naval_base": "Shipyard / Naval Base",
    "lng_terminal": "LNG Terminal",
    "port_maritime_terminal": "Port / Maritime Terminal",
    "oil_gas_pipeline": "Oil and Gas Pipeline / Compressor Station",
    "power_station": "Power Station / Generation Plant",
    "nuclear_power_plant": "Nuclear Power Plant",
    "ai_llm": "AI / LLM / Agentic System",
    "supply_chain": "Supply Chain / Third Party",
}

_CONTEXT_PRESET_TEMPLATE_HINTS = {
    "data_centre": ("data_centre_disruption", "physical_intrusion_cyber"),
    "telecoms_5g_core": ("telecom_5g_core",),
    "satellite_ground_station": ("satellite_ground_station",),
    "airport": ("port_maritime_terminal", "building_automation_hijack", "data_centre_disruption"),
    "electrical_substation": ("electrical_substation_ied", "power_grid_relay_manipulation"),
    "water_treatment_plant": ("water_treatment_poisoning", "sewage_treatment_scada", "water_dam_scada"),
    "manufacturing_facility": ("pharma_manufacturing", "ot_process_manipulation", "iiot_gateway_compromise"),
    "defence_manufacturing_plant": ("pharma_manufacturing", "ot_process_manipulation", "iiot_gateway_compromise"),
    "pharma_manufacturing_plant": ("pharma_manufacturing",),
    "ev_charging_network": ("ev_charging_network", "grid_derms_attack"),
    "military_headquarters": ("enterprise_phishing", "ad_privilege_escalation", "business_email_compromise"),
    "oil_refinery": ("ot_process_manipulation", "lng_terminal_dcs", "gas_turbine_dcs"),
    "drilling_rig": ("oil_gas_pipeline_scada", "maritime_vessel_ot", "ot_process_manipulation"),
    "shipyard_naval_base": ("port_maritime_terminal", "maritime_vessel_ot", "physical_intrusion_cyber"),
    "lng_terminal": ("lng_terminal_dcs", "ot_process_manipulation"),
    "port_maritime_terminal": ("port_maritime_terminal", "maritime_vessel_ot"),
    "oil_gas_pipeline": ("oil_gas_pipeline_scada", "ot_process_manipulation"),
    "power_station": ("gas_turbine_dcs", "ot_process_manipulation"),
    "nuclear_power_plant": ("nuclear_facility_override", "gas_turbine_dcs"),
}


_DOMAIN_KEYWORDS = {
    "data_centre": [
        "data centre", "data center", "colocation", "colo", "server room",
        "rack", "row", "cold aisle", "hot aisle", "remote hands", "dcim",
        "crac", "crah", "ups", "pdu", "generator", "ipmi", "bmc", "idrac",
        "ilo", "out-of-band", "management plane", "esxi", "vcenter",
        "hypervisor", "top of rack", "leaf switch", "spine switch",
    ],
    "telecommunications": [
        "telecom", "telecommunications", "carrier", "mobile network", "ran",
        "base station", "cell site", "gnodeb", "enodeb", "5g core", "ims",
        "amf", "smf", "upf", "udm", "udr", "diameter", "ss7", "roaming",
        "network slice", "lawful intercept", "oam", "oss", "bss",
        "satellite", "ground station", "teleport", "tt&c", "uplink", "downlink",
    ],
    "ot_ics": [
        "scada", "plc", "hmi", "rtu", "dcs", "ics", "ot ", "ot/", "industrial",
        "modbus", "dnp3", "iec 61850", "bacnet", "profinet", "opc-ua", "opc ua",
        "safety instrumented", "sis ", "triconex", "turbine", "compressor",
        "valve", "reactor", "boiler", "furnace", "centrifuge",
        "manufacturing", "production line", "assembly line", "mes",
        "batch control", "cleanroom", "lims", "ev charging", "charging station",
        "ocpp", "lng", "regasification", "cryogenic",
        "airport", "baggage handling", "aodb", "fids", "airside",
        "refinery", "crude unit", "hydrocracker", "tank farm", "loading rack",
        "drilling rig", "bop", "blowout preventer", "well control", "mud logging",
        "defence manufacturing", "defense manufacturing", "shipyard", "naval base", "dry dock",
    ],
    "power_energy": [
        "grid", "substation", "inverter", "solar farm", "wind farm", "wind turbine",
        "power plant", "generator", "transformer", "relay", "circuit breaker",
        "hydroelectric", "dam ", "derms", "distributed energy", "smart meter",
        "ami ", "ev charg", "lng ", "natural gas", "oil ", "gas pipeline",
        "power grid", "electrical", "energy",
    ],
    "iot": [
        "iot", "smart building", "bms ", "building management", "zigbee", "z-wave",
        "mqtt", "coap", "lorawan", "sensor", "thermostat", "smart home",
        "iiot", "industrial iot", "gateway", "embedded", "firmware",
        "connected device", "wearable",
    ],
    "cloud": [
        "aws", "azure", "gcp", "cloud", "kubernetes", "k8s", "docker",
        "serverless", "lambda", "iam ", "s3 ", "ec2", "terraform",
        "saas", "paas", "iaas",
    ],
    "enterprise": [
        "active directory", "domain controller", "windows domain", "exchange",
        "office 365", "m365", "ransomware", "phishing", "vpn", "endpoint",
        "edr", "siem", "corporate", "enterprise",
        "military headquarters", "defence headquarters", "defense headquarters",
        "command headquarters", "scif", "cross-domain", "coalition network",
    ],
    "web_app": [
        "web app", "api ", "rest api", "graphql", "oauth", "jwt", "xss",
        "sql injection", "ssrf", "csrf", "authentication", "web server",
    ],
    "software_research": [
        "reverse engineering", "reverse-engineering", "reversing", "decompile",
        "disassembly", "binary", "patch diff", "patch-diff", "binary diff",
        "vulnerability research", "exploit development", "exploit dev",
        "crash triage", "fuzzing", "parser", "memory corruption", "type confusion",
        "use-after-free", "heap overflow", "desktop client", "thick client",
        "browser extension", "updater", "code signing", "firmware extraction",
        "ota", "ida", "ghidra", "frida",
    ],
}


def _normalize_identifier(value: str) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace("/", "_").replace(" ", "_")


def _context_preset_label(context_preset: str) -> str:
    normalized = _normalize_identifier(context_preset)
    if not normalized:
        return ""
    if normalized in _CONTEXT_PRESET_LABEL_MAP:
        return _CONTEXT_PRESET_LABEL_MAP[normalized]
    if str(context_preset or "").strip():
        return str(context_preset).strip()
    return normalized.replace("_", " ").title()


def _preferred_template_hints(context_preset: str) -> tuple[str, ...]:
    normalized = _normalize_identifier(context_preset)
    if not normalized:
        return ()
    return _CONTEXT_PRESET_TEMPLATE_HINTS.get(normalized, ())


def _normalize_generation_profile(value: str) -> str:
    normalized = _normalize_identifier(value)
    aliases = {
        "": "balanced",
        "planning": "planning_first",
        "planning_first": "planning_first",
        "planningfirst": "planning_first",
        "strategy_first": "planning_first",
        "balanced": "balanced",
        "default": "balanced",
        "reference_heavy": "reference_heavy",
        "referenceheavy": "reference_heavy",
        "reference_focused": "reference_heavy",
        "references_first": "reference_heavy",
    }
    return aliases.get(normalized, "balanced")


def _context_preset_to_domain(context_preset: str) -> str:
    normalized = _normalize_identifier(context_preset)
    if not normalized:
        return ""
    return _CONTEXT_PRESET_DOMAIN_MAP.get(normalized, normalized)


_DOMAIN_DECOMPOSITION_GUIDANCE = {
    "data_centre": [
        "People and Trusted Roles (operators, remote hands, vendors, security guards, cleaners, facilities staff)",
        "Physical Infrastructure and Facility Access (perimeter, loading bays, CCTV, mantraps, badge/PACS, cages, racks, console access, removable media handling)",
        "Information Technology and Management Plane (AD, vCenter, Kubernetes, storage, backup, PAM, secrets, BMC/IPMI, KVM, DCIM, asset telemetry, jump hosts, orchestration)",
        "Operational Technology / BMS / Power / Cooling (BMS head-end, BACnet gateways, HVAC, chillers, CRAC/CRAH, UPS, PDUs, generators, EPMS, fire suppression)",
        "Remote Access, Vendors, and Supply Chain (VPN, MSP tooling, vendor tunnels, field-service laptops, firmware and hardware dependencies)",
        "Detection, Response, and Process Weaknesses (SIEM, EDR/XDR, monitoring gaps, maintenance windows, change control, failover, incident response)",
    ],
    "telecommunications": [
        "Carrier Operations, Trusted Vendors, and Inter-Operator Relationships",
        "RAN, Radio, GNSS/PTP Timing, Transport, and Core-Network Boundaries",
        "Subscriber Identity, Policy, Charging, Voice, and Sensitive Mediation Services",
        "Cloud-Native Management, OSS/BSS, OAM, and Orchestration Planes",
        "Roaming, Signalling, Exposure, and External Interconnect Edge",
        "Monitoring, Service Assurance, Timing Assurance, Fraud Detection, and Emergency Change or Outage Process",
    ],
    "software_research": [
        "Externally Reachable Entry Points and Attacker-Controlled Inputs",
        "Trust Boundaries and Privileged Transitions",
        "File, Protocol, Parser, IPC, and Serialization Surfaces",
        "Updater, Plugin, Extension, and Supply-Chain Trust Paths",
        "Post-Compromise Objectives such as code execution, persistence, data access, or stealth",
        "Telemetry, Logging, and Defensive Blind Spots",
    ],
    "ot_ics": [
        "People, Remote Maintenance Roles, and Trusted Vendors",
        "Enterprise IT to OT Boundary and Shared Services",
        "Supervisory Control, Engineering Workstations, and Historians",
        "Controllers, Safety Systems, and Field Networks",
        "Physical Process Manipulation and Operational Impact",
        "Detection, Safety, and Recovery Constraints",
    ],
    "power_energy": [
        "Operators, Vendors, and Utility Coordination Paths",
        "Corporate IT, Control Centres, and Inter-Control-Centre Links",
        "Substations, Generation, and Distributed Energy Control Systems",
        "Communications Infrastructure and Remote Access",
        "Protective Relays, Safety, and Physical Process Effects",
        "Recovery, Grid Stability, and Monitoring Gaps",
    ],
    "iot": [
        "Users, Installers, Vendors, and Supply Chain",
        "Cloud Platforms, Device Management, and APIs",
        "Gateways, Mobile Apps, and Local Management Interfaces",
        "Wireless, Mesh, and Edge Networking Layers",
        "Device Firmware, Boot, Update, and Hardware Debug Paths",
        "Monitoring, Logging, and Operational Blind Spots",
    ],
    "cloud": [
        "Human Roles, Third Parties, and Federated Identities",
        "Internet Edge, Public Services, and External Exposure",
        "Identity, Control Plane, and Management Paths",
        "Workloads, Data Stores, and Network Segmentation",
        "Supply Chain, CI/CD, and Infrastructure-as-Code",
        "Logging, Detection, and Response Coverage",
    ],
    "enterprise": [
        "People, Insider, and Social Engineering Paths",
        "Internet Edge, Remote Access, and Email Surfaces",
        "Identity, Active Directory, and Privileged Management",
        "Endpoints, Servers, SaaS, and Lateral Movement Paths",
        "Third Parties, Vendors, and Supply Chain",
        "Detection, Backup, and Response Weaknesses",
    ],
    "web_app": [
        "Users, Admins, Support Roles, and Third Parties",
        "Internet Edge, CDN, WAF, and Reverse Proxy Layers",
        "Authentication, Session, and Authorization Boundaries",
        "Application Logic, APIs, Jobs, and Background Workers",
        "Data Stores, Secrets, Integrations, and Supply Chain",
        "Observability, Logging, and Abuse Detection Gaps",
    ],
    "general": [
        "People, Privileged Roles, and Trusted Relationships",
        "External Exposure and Initial Access Surfaces",
        "Management Planes, Core Platforms, and Internal Boundaries",
        "Third Parties, Supply Chain, and Dependency Paths",
        "Physical or Environmental Dependencies where relevant",
        "Detection, Response, and Process Weaknesses",
    ],
}


def _get_domain_decomposition_guidance(domain: str) -> str:
    axes = _DOMAIN_DECOMPOSITION_GUIDANCE.get(domain, _DOMAIN_DECOMPOSITION_GUIDANCE["general"])
    lines = "\n".join(f"- {axis}" for axis in axes)
    return (
        "Attack-surface decomposition guidance:\n"
        "- Start with meaningful operational domains, trust boundaries, actor groups, or attack-surface layers before drilling into specific weaknesses.\n"
        "- For this target, likely top-level or second-level branches include:\n"
        f"{lines}"
    )


def _get_generation_profile_guidance(generation_profile: str, domain: str) -> str:
    if generation_profile == "planning_first":
        return (
            "Generation profile guidance:\n"
            "- Planning-first means the first two layers must decompose the target into attack-surface domains, trust boundaries, actor groups, or operational layers.\n"
            "- Do not use raw CWE, CAPEC, ATT&CK technique IDs, or CVE identifiers as second-level nodes.\n"
            "- Add references, exploit classes, CVEs, and ATT&CK mappings only once a branch is specific enough to justify them.\n"
            "- Preserve broad planning coverage across people, physical, technical, supply-chain, and defensive-process branches where they matter."
        )
    if generation_profile == "reference_heavy":
        return (
            "Generation profile guidance:\n"
            "- Keep the first layer structurally useful and domain-oriented.\n"
            "- You may align lower layers earlier with ATT&CK tactics, CAPEC patterns, CWE classes, and real CVEs once the branch is anchored to a meaningful attack path.\n"
            "- Do not let the tree collapse into a flat taxonomy dump. References should support the structure, not replace it.\n"
            f"- For the {domain.replace('_', ' ')} domain, keep the conceptual branches usable for planning and operator discussion."
        )
    return (
        "Generation profile guidance:\n"
        "- Balanced mode means the first layer should stay conceptually useful, and the next layers should turn each branch into concrete attack paths.\n"
        "- References, exploit classes, CVEs, and ATT&CK mappings should appear once a node is specific enough to benefit from them.\n"
        "- Keep coverage broad across operational, human, physical, technical, and supply-chain angles where applicable."
    )


def _detect_domain(objective: str, scope: str, context_preset: str = "") -> str:
    """Detect the domain from objective and scope text."""
    context_label = _context_preset_label(context_preset)
    text = f"{objective} {scope} {context_label}".lower()
    preset_domain = _context_preset_to_domain(context_preset)
    scores: dict[str, int] = {}
    for domain, keywords in _DOMAIN_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text)
        if score > 0:
            scores[domain] = score
    if preset_domain and preset_domain != "general":
        scores[preset_domain] = scores.get(preset_domain, 0) + 4
    if not scores:
        return preset_domain or "general"
    return max(scores, key=scores.get)


def _get_domain_system_prompt(domain: str) -> str:
    """Return a domain-specialised system prompt for the AI agent."""
    base = "You are an expert cyber security red-team analyst and attack tree modeller. "

    domain_expertise = {
        "ot_ics": (
            "You specialise in OT/ICS cyber security with deep knowledge of SCADA systems, PLCs, DCS, "
            "safety instrumented systems (SIS), and industrial protocols (Modbus, DNP3, IEC 61850, OPC-UA, "
            "PROFINET, EtherNet/IP). You understand the Purdue Model for ICS network architecture, "
            "IT/OT convergence risks, and real-world ICS attacks (Stuxnet, TRITON/TRISIS, Industroyer, "
            "CRASHOVERRIDE, Pipedream/Incontroller). Reference ICS-specific MITRE ATT&CK techniques. "
        ),
        "telecommunications": (
            "You specialise in telecommunications and carrier-network security across RAN, transport, and core environments. "
            "You understand 4G/5G architecture, SS7 and Diameter interconnect risks, service-based 5G core functions, "
            "lawful intercept systems, OSS/BSS and OAM planes, timing dependencies, and roaming-partner trust. "
            "Reference realistic telecom attack paths involving subscriber data, signalling abuse, cloud-native network functions, "
            "and operational outage impact. "
        ),
        "data_centre": (
            "You specialise in data centre, colocation, and cyber-physical infrastructure security. "
            "You understand facility access control, remote hands workflows, racks and console access, "
            "BMC/IPMI and hypervisor management planes, storage fabrics, backup and orchestration systems, "
            "and building-management dependencies such as HVAC, chillers, UPS, PDUs, generators, and DCIM. "
            "You can reason about people, physical infrastructure, management-plane compromise, OT/BMS pivoting, "
            "vendor access, and operational process failure as one integrated attack surface. "
        ),
        "power_energy": (
            "You specialise in power grid and energy sector cyber security including generation, "
            "transmission, and distribution systems. You understand NERC CIP standards, substation "
            "automation (IEC 61850), protective relay systems, DERMS, smart grid technologies (AMI, "
            "OpenADR), and renewable energy control systems. Reference real-world grid attacks "
            "(Ukraine 2015/2016, Industroyer2). "
        ),
        "iot": (
            "You specialise in IoT and embedded device security including building management systems "
            "(BACnet, KNX, LonWorks), smart home/building protocols (Zigbee, Z-Wave, BLE), IIoT gateways "
            "(MQTT, AMQP, CoAP), and embedded Linux/RTOS firmware. You understand wireless mesh network "
            "attacks, firmware extraction/reverse-engineering, and IoT botnet techniques (Mirai variants). "
        ),
        "cloud": (
            "You specialise in cloud security across AWS, Azure, and GCP including IAM privilege escalation, "
            "container escape, serverless injection, storage misconfiguration, and cloud-native attack paths. "
            "You understand cloud control plane vs data plane attacks, cross-account pivoting, and "
            "cloud-specific MITRE ATT&CK techniques. "
        ),
        "enterprise": (
            "You specialise in enterprise network security including Active Directory attack paths, "
            "ransomware kill chains, business email compromise, lateral movement techniques, and "
            "endpoint security bypass. You understand modern EDR evasion, credential theft methods, "
            "and the full MITRE ATT&CK enterprise matrix. "
        ),
        "web_app": (
            "You specialise in web application and API security including OWASP Top 10, modern auth "
            "bypass techniques (OAuth/OIDC/JWT abuse), API-specific attacks, server-side vulnerabilities, "
            "and application-layer exploitation chains. "
        ),
        "software_research": (
            "You specialise in software vulnerability research, reverse engineering, exploit development, "
            "and binary trust-boundary analysis. You are comfortable with static and dynamic analysis, "
            "patch diffing, fuzzing, crash triage, parser and protocol reversing, secure updater abuse, "
            "memory corruption classes, sandbox boundaries, and code-signing or trust-store validation flaws. "
            "Reference realistic tooling such as IDA Pro, Ghidra, Binary Ninja, WinDbg, x64dbg, LLDB, Frida, "
            "jadx, apktool, AFL++, libFuzzer, and QEMU when appropriate. "
        ),
    }

    expertise = domain_expertise.get(domain, "")
    return (
        base + expertise +
        "You generate comprehensive, realistic attack trees in structured JSON. "
        "Write every description as a detailed red team briefing — include specific tools, "
        "exploitation techniques, trust boundaries, evasion methods, real CVEs where applicable, and step-by-step attacker actions. "
        "Be thorough and technical. A penetration tester should be able to use your output as an operational playbook. "
        "Respond ONLY with valid JSON — no markdown, no commentary."
    )


_REFERENCE_ARCHITECTURES = {
    "data_centre": """Data centre / colocation architecture:
- People and roles: operators, facilities engineers, remote hands, MSPs, security, cleaning and maintenance contractors
- Physical layer: perimeter, loading bays, PACS, badge readers, mantraps, CCTV/VMS, cages, racks, crash carts, console access, removable media workflows
- IT management layer: AD/LDAP/SSO, vCenter/ESXi, Kubernetes/OpenShift, PAM and secrets vaults, BMC/IPMI/iDRAC/iLO, KVM/serial consoles, storage and backup platforms, automation/CMDB/ITSM, DCIM, rack telemetry
- OT / facilities layer: BMS head-end, BACnet gateways, HVAC, chillers, CRAC/CRAH, in-row cooling, UPS, STS/ATS, PDUs, generators, EPMS, fire suppression
- Remote access layer: VPNs, bastions, vendor remote support tunnels, field-service laptops, out-of-band management
- Monitoring layer: SIEM, EDR/XDR, NMS, alert triage, case management, recovery runbooks
- Key boundaries: internet-to-remote-access edge, corporate IT-to-management plane, IT-to-BMS/OT, physical perimeter-to-rack row
- Common weaknesses: over-trusted contractors, exposed BMCs, flat management networks, weak vendor remote access, poor BMS segregation, weak failover procedures""",

    "telecommunications": """Telecommunications carrier architecture:
- Operations and trust: NOC, SOC, roaming partners, lawful-intercept staff, OEMs, managed-service providers
- RAN and transport: base stations, RU/DU/CU, Open RAN control loops, microwave or fibre fronthaul/backhaul, GNSS/PNT receivers, PRTC or ePRTC sources, PTP grandmasters, boundary clocks, SyncE, holdover
- Core layer: AMF, SMF, UPF, NRF, PCF, AUSF, NSSF, CHF/OCS, UDM/UDR, IMS and messaging services
- Management layer: OSS/BSS, EMS/OAM, SON, subscriber provisioning, CI/CD, GitOps, CNF orchestration, service-mesh PKI, carrier time-distribution appliances
- Interconnect layer: SS7, Diameter, SIP, SEPP, IPX, NEF/SCP exposure, roaming exchanges, peering, API gateways
- Sensitive services: lawful intercept, subscriber identity stores, HSM-backed key material, charging and CDR mediation
- Monitoring layer: KPI assurance, trace analytics, timing assurance, GNSS spoofing or jamming alerts, signalling firewalls, fraud detection, outage bridges, release control
- Key boundaries: roaming-partner-to-core, RAN-to-core, OAM-to-production, subscriber-data-to-operations
- Common weaknesses: over-trusted interconnects, exposed OAM, weak API auth, flat management access, weak timing-source resilience, sensitive LI or subscriber stores""",

    "ot_ics": """Purdue Model / IEC 62443 architecture:
- Level 5: Enterprise Network (ERP, email, internet)
- Level 4: Business Planning (MES, production scheduling)
- Level 3.5: IT/OT DMZ (data historian, jump hosts, patch servers)
- Level 3: Site Operations (SCADA master, engineering workstations)
- Level 2: Area Supervisory (HMI, operator workstations, OPC servers)
- Level 1: Basic Control (PLCs, RTUs, DCS controllers, SIS)
- Level 0: Physical Process (sensors, actuators, field instruments)
Key boundaries: IT/OT firewall between L4-L3.5, process network between L2-L1
Common weaknesses: flat OT networks, shared credentials, legacy unpatched systems, default passwords on PLCs""",

    "power_energy": """Utility / Grid architecture (NERC CIP):
- Corporate IT: business systems, email, internet-facing
- Control Centre: EMS/SCADA master, ICCP links to other utilities
- Substation: IEDs, protective relays, RTUs, IEC 61850 process bus
- Generation: DCS, turbine controllers, SIS, excitation systems
- Distribution: DERMS, smart meters (AMI), recloser controllers
- Renewable: inverter controllers, met stations, cellular gateways
Key boundaries: ESP (Electronic Security Perimeter), dial-up/satellite links
Common weaknesses: legacy DNP3 without auth, exposed VNC/RDP, vendor remote access""",

    "iot": """IoT / Smart Building architecture:
- Cloud layer: vendor cloud platforms, device management APIs, OTA updates
- Gateway layer: IIoT gateways, BMS head-end servers, protocol translators
- Network layer: WiFi, BLE, Zigbee/Z-Wave mesh, LoRaWAN, cellular
- Device layer: sensors, actuators, controllers, smart appliances
- Integration: BACnet/IP, KNX, Modbus, MQTT, REST APIs
Key boundaries: cloud-to-gateway, gateway-to-device, IT-to-building OT
Common weaknesses: default credentials, firmware without signing, flat networks, no encryption""",

    "software_research": """Software / client application architecture:
- Delivery layer: installer, package manager, signed updater, CDN, crash-reporting and telemetry endpoints
- Application layer: UI client, local privilege boundary, plugin/extension framework, scripting engine, IPC/RPC interfaces
- Trust layer: certificate store, code-signing checks, update manifests, license enforcement, anti-tamper and anti-debug logic
- Data layer: local caches, SQLite databases, config files, key stores, session tokens, serialized objects
- Network layer: backend APIs, WebSocket/IPC bridges, custom binary protocols, auth tokens, TLS pinning
Key boundaries: updater-to-client trust, privileged helper services, client-to-backend trust, extension/plugin isolation
Common weaknesses: client-side trust decisions, weak update verification, unsafe deserialization, parser memory corruption, insecure IPC, hidden admin features, hardcoded secrets""",
}


def _get_reference_architecture(domain: str) -> str:
    """Return reference architecture for the detected domain."""
    return _REFERENCE_ARCHITECTURES.get(domain, "")


def _template_to_tree_example(template: dict, max_nodes: int | None = None) -> dict:
    """Convert a template to a simplified tree structure for few-shot example."""
    nodes = template.get("nodes", [])
    if not nodes:
        return {}

    if max_nodes and max_nodes > 0 and len(nodes) > max_nodes:
        raw_by_id = {node.get("id"): node for node in nodes if node.get("id")}
        child_ids_by_parent: dict[str, list[str]] = {}
        root_ids: list[str] = []

        for raw_node in nodes:
            node_id = raw_node.get("id")
            if not node_id:
                continue
            parent_id = raw_node.get("parent_id")
            if parent_id and parent_id in raw_by_id:
                child_ids_by_parent.setdefault(parent_id, []).append(node_id)
            else:
                root_ids.append(node_id)

        queue = list(root_ids)
        selected_ids: list[str] = []
        seen_ids: set[str] = set()
        while queue and len(selected_ids) < max_nodes:
            node_id = queue.pop(0)
            if node_id in seen_ids:
                continue
            seen_ids.add(node_id)
            selected_ids.append(node_id)
            queue.extend(child_ids_by_parent.get(node_id, []))

        selected_id_set = set(selected_ids)
        nodes = [node for node in nodes if node.get("id") in selected_id_set]

    # Build lookup
    by_id = {}
    for n in nodes:
        node = {
            "title": n.get("title", ""),
            "description": n.get("description", "")[:100],
            "node_type": n.get("node_type", "attack_step"),
            "logic_type": n.get("logic_type", "OR"),
            "status": n.get("status", "draft"),
            "platform": "...",
            "attack_surface": "...",
            "threat_category": "...",
            "required_access": "...",
            "required_privileges": "...",
            "required_skill": "...",
            "likelihood": n.get("likelihood", 5),
            "impact": n.get("impact", 5),
            "effort": n.get("effort", 5),
            "exploitability": n.get("exploitability", 5),
            "detectability": n.get("detectability", 5),
            "children": [],
        }
        by_id[n["id"]] = node

    # Build tree
    root = None
    for n in nodes:
        pid = n.get("parent_id")
        nid = n["id"]
        if pid and pid in by_id:
            by_id[pid]["children"].append(by_id[nid])
        elif not pid:
            root = by_id[nid]

    return root or {}


def _template_nodes_to_tree(template: dict) -> dict:
    """Convert template nodes into a tree structure for the expand prompt."""
    return _template_to_tree_example(template)


def find_best_template_for_objective(objective: str, scope: str, context_preset: str = "") -> dict | None:
    """Find the most relevant template for a given objective by keyword matching."""
    if not TEMPLATES_DIR.exists():
        return None

    context_label = _context_preset_label(context_preset).lower()
    text = f"{objective} {scope} {context_label}".lower()
    domain = _detect_domain(objective, scope, context_preset)
    requested_preset = _normalize_identifier(context_preset)
    hint_order = _preferred_template_hints(context_preset)
    preferred_template_hints = {
        template_id: max(1, (len(hint_order) - index) * 4)
        for index, template_id in enumerate(hint_order)
    }
    best_score = 0
    best_template = None

    for f in TEMPLATES_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            template_id = f.stem
            name = data.get("name", "").lower()
            desc = data.get("description", "").lower()
            obj = data.get("root_objective", "").lower()
            template_context_preset = data.get("context_preset", "").lower()
            template_family = data.get("template_family", "").lower()
            technical_profile = data.get("technical_profile", "").lower()
            template_domain = _context_preset_to_domain(template_context_preset)
            template_context_label = _context_preset_label(template_context_preset).lower()
            focus_areas = " ".join(str(item) for item in data.get("focus_areas", [])).lower()
            prompt_hints = " ".join(str(item) for item in data.get("prompt_hints", [])).lower()
            node_titles = " ".join(
                str(node.get("title", ""))
                for node in data.get("nodes", [])[:12]
                if isinstance(node, dict)
            ).lower()
            template_text = (
                f"{name} {desc} {obj} {template_context_preset} {template_context_label} {template_family} "
                f"{technical_profile} {focus_areas} {prompt_hints} {node_titles}"
            )

            # Score by word overlap
            words = set(re.findall(r'\b\w{4,}\b', text))
            template_words = set(re.findall(r'\b\w{4,}\b', template_text))
            overlap = len(words & template_words)
            if requested_preset and template_context_preset == requested_preset:
                overlap += 3
            overlap += preferred_template_hints.get(template_id, 0)
            if domain != "general" and (
                template_context_preset == domain or template_family == domain or template_domain == domain or domain in template_text
            ):
                overlap += 2
            if domain == "software_research" and technical_profile in {
                "deep",
                "deep_technical",
                "reverse_engineering",
                "vulnerability_research",
                "exploit_development",
            }:
                overlap += 2
            if overlap > best_score:
                best_score = overlap
                best_template = data
        except Exception:
            continue

    return best_template if best_score >= 2 else None
