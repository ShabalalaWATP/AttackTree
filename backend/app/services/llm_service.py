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
import httpx

from ..services.crypto import decrypt_value

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent.parent / "templates_data"


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
    if max_tokens:
        payload["max_tokens"] = max_tokens

    start = time.time()
    try:
        async with httpx.AsyncClient(verify=ssl_ctx if ssl_ctx is not None else True, timeout=timeout) as client:
            resp = await client.post(
                f"{base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            elapsed = int((time.time() - start) * 1000)

            if resp.status_code == 200:
                data = resp.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
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


def build_branch_suggestion_prompt(node_data: dict, tree_context: str, suggestion_type: str) -> list[dict]:
    """Build a prompt for branch suggestions."""
    node_title = node_data.get("title", "Unknown")
    node_type = node_data.get("node_type", "attack_step")
    node_desc = node_data.get("description", "")
    platform = node_data.get("platform", "")

    type_prompts = {
        "branches": f"""You are a cyber security attack tree analyst. Given the following attack tree node, suggest 3-6 likely child attack steps or sub-goals that an attacker would need to accomplish.

Node: "{node_title}"
Type: {node_type}
Description: {node_desc}
Platform/Context: {platform}

Tree context:
{tree_context}

Return a JSON array of objects with these fields:
- title: short attack step title
- description: brief description
- node_type: one of goal, sub_goal, attack_step, precondition, weakness, pivot_point
- logic_type: OR or AND
- threat_category: category of threat
- likelihood: estimated likelihood 1-10
- impact: estimated impact 1-10

Return ONLY valid JSON array, no markdown formatting.""",

        "mitigations": f"""You are a cyber security analyst. For the following attack step, suggest 3-5 mitigations or security controls.

Attack step: "{node_title}"
Description: {node_desc}
Platform/Context: {platform}

Return a JSON array of objects:
- title: mitigation title
- description: how it works
- effectiveness: 0.0 to 1.0

Return ONLY valid JSON array.""",

        "detections": f"""You are a cyber security analyst. For the following attack step, suggest 3-5 detection opportunities.

Attack step: "{node_title}"
Description: {node_desc}
Platform/Context: {platform}

Return a JSON array of objects:
- title: detection title
- description: how to detect
- coverage: 0.0 to 1.0
- data_source: data source

Return ONLY valid JSON array.""",

        "mappings": f"""You are a cyber security analyst. For the following attack step, suggest relevant MITRE ATT&CK techniques, CAPEC patterns, CWE weaknesses, and OWASP categories.

Attack step: "{node_title}"
Description: {node_desc}

Return a JSON array of objects:
- framework: one of "attack", "capec", "cwe", "owasp"
- ref_id: the reference ID (e.g., T1566, CAPEC-98, CWE-89, A01:2021)
- ref_name: the reference name

Return ONLY valid JSON array.""",
    }

    prompt_text = type_prompts.get(suggestion_type, type_prompts["branches"])

    return [
        {"role": "system", "content": "You are an expert cyber security attack tree analyst. Respond only with valid JSON."},
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


def build_agent_tree_prompt(objective: str, scope: str, depth: int, breadth: int,
                            template_example: dict | None = None,
                            reference_arch: str = "") -> list[dict]:
    """Build a prompt for the AI Agent to generate a full attack tree.

    Args:
        objective: The attacker's goal
        scope: Target description
        depth: Max tree depth
        breadth: Max children per parent
        template_example: Optional template dict to use as few-shot example
        reference_arch: Optional reference architecture description
    """
    # --- Domain detection for specialised system prompts ---
    domain = _detect_domain(objective, scope)
    system = _get_domain_system_prompt(domain)

    # --- Build user prompt ---
    user_parts = [f"""Generate a complete attack tree for the following objective.

**Attacker Objective:** {objective}
**Scope / Target Description:** {scope}
**Tree Depth:** up to {depth} levels deep
**Breadth:** up to {breadth} child nodes per parent"""]

    # --- Reference architecture context ---
    if reference_arch:
        user_parts.append(f"\n**Reference Architecture:**\n{reference_arch}")
    else:
        arch = _get_reference_architecture(domain)
        if arch:
            user_parts.append(f"\n**Reference Architecture:**\n{arch}")

    # --- Few-shot template example ---
    if template_example:
        example_nodes = template_example.get("nodes", [])[:6]  # First 6 nodes for context
        example_text = json.dumps(_template_to_tree_example(template_example), indent=2)
        user_parts.append(f"""
**Example structure** (use this as a reference for quality, depth, and field population — do NOT copy it verbatim, generate original content for the given objective):
```json
{example_text}
```""")

    user_parts.append("""
Return a single JSON object representing the root node. Every node MUST have ALL of these fields:
- "title": concise attack step title
- "description": 2-3 sentence technical description of the attack step
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
2. Second-level nodes should be "sub_goal" representing distinct attack paths
3. Deeper nodes should be "attack_step", "precondition", or "weakness"
4. Use AND logic where multiple steps are ALL required in sequence
5. Use OR logic where alternative approaches exist
6. Be specific and realistic — reference real TTPs, vulnerability classes, and attack techniques
7. Cover diverse attack vectors: network, physical, social engineering, supply chain, insider threat where applicable
8. Leaf nodes should be concrete, actionable attack steps
9. Every single field listed above MUST be populated for every node — no empty strings, no nulls
10. Platform and attack_surface must be specific to each node's context, not generic

Return ONLY the JSON object. Do not wrap in markdown code blocks.""")

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": "\n".join(user_parts)},
    ]


def build_template_expand_prompt(template: dict, objective: str, scope: str,
                                  depth: int, breadth: int) -> list[dict]:
    """Build a prompt that takes a template skeleton and asks the AI to expand and customise it."""
    domain = _detect_domain(objective, scope)
    system = _get_domain_system_prompt(domain)

    # Convert template to a simplified tree structure for the prompt
    template_tree = json.dumps(_template_nodes_to_tree(template), indent=2)

    user_prompt = f"""You are given an existing attack tree template as a starting skeleton. Your job is to:
1. Keep the overall structure but EXPAND each branch with {breadth-1} to {breadth} additional child nodes per parent
2. CUSTOMISE all node descriptions, platforms, and attack surfaces for the specific target described below
3. ADD missing attack vectors not covered in the template
4. DEEPEN the tree to {depth} levels where the template is shallower
5. Populate ALL required fields with values specific to this target

**Attacker Objective:** {objective}
**Scope / Target Description:** {scope}
**Expand to Depth:** {depth} levels
**Expand to Breadth:** {breadth} children per parent

**Starting Template (skeleton — expand this, do NOT just copy it):**
```json
{template_tree}
```

Return a single JSON object representing the expanded root node with the same field requirements:
- "title", "description", "node_type", "logic_type", "status", "platform", "attack_surface",
  "threat_category", "required_access", "required_privileges", "required_skill",
  "likelihood" (1-10), "impact" (1-10), "effort" (1-10), "exploitability" (1-10),
  "detectability" (1-10), "children" (array of child nodes, recursively)

Return ONLY the JSON object. No markdown, no commentary."""

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user_prompt},
    ]


def build_gap_analysis_prompt(existing_nodes: list[dict], objective: str, scope: str) -> list[dict]:
    """Build a prompt to analyse an existing tree and suggest missing attack paths."""
    domain = _detect_domain(objective, scope)

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

    user_prompt = f"""Analyse the following attack tree and identify MISSING attack paths, vectors, and weaknesses that are NOT yet covered.

**Attacker Objective:** {objective}
**Scope:** {scope}

**Existing attack tree nodes:**
{tree_text}

Generate ONLY the NEW nodes that should be added to fill gaps. Return a JSON array of new branches, where each branch is a tree object (same recursive structure):
- "title", "description", "node_type", "logic_type", "status", "platform", "attack_surface",
  "threat_category", "required_access", "required_privileges", "required_skill",
  "likelihood" (1-10), "impact" (1-10), "effort" (1-10), "exploitability" (1-10),
  "detectability" (1-10), "children" (array, recursively)
- "attach_to": title of the existing node this branch should be added under (use the root goal title if it's a new top-level path)

Focus on:
1. Attack vectors not covered (e.g., if only network attacks exist, add physical/social/supply-chain)
2. Missing preconditions and weaknesses
3. Alternative techniques for existing attack steps
4. Detection evasion paths
5. Persistence and lateral movement gaps

Return ONLY the JSON array. No markdown, no commentary."""

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user_prompt},
    ]


def build_mitigations_detections_pass_prompt(nodes_summary: list[dict]) -> list[dict]:
    """Build a prompt for Pass 4: generate mitigations and detections for leaf nodes."""
    system = (
        "You are an expert blue-team defender and detection engineer. "
        "For each attack step leaf node, suggest specific mitigations and detection opportunities. "
        "Respond ONLY with valid JSON — no markdown, no commentary."
    )

    nodes_text = json.dumps(nodes_summary, indent=2)
    user_prompt = f"""For each of the following attack tree leaf nodes, suggest mitigations and detections.

{nodes_text}

Return a JSON array with one object per node:
- "index": the original index number
- "mitigations": array of {{"title": "...", "description": "...", "effectiveness": 0.0-1.0}}
- "detections": array of {{"title": "...", "description": "...", "coverage": 0.0-1.0, "data_source": "..."}}

Return ONLY the JSON array."""

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user_prompt},
    ]


def build_reference_mapping_pass_prompt(nodes_summary: list[dict]) -> list[dict]:
    """Build a prompt for Pass 3: MITRE ATT&CK / CAPEC / CWE mapping for nodes."""
    system = (
        "You are an expert cyber security analyst who maps attack steps to reference frameworks. "
        "Respond ONLY with valid JSON — no markdown, no commentary."
    )

    nodes_text = json.dumps(nodes_summary, indent=2)
    user_prompt = f"""For each of the following attack tree nodes, suggest the most relevant MITRE ATT&CK techniques, CAPEC patterns, and CWE weaknesses.

{nodes_text}

Return a JSON array with one object per node:
- "index": the original index number
- "mappings": array of {{"framework": "attack"|"capec"|"cwe", "ref_id": "T1566"|"CAPEC-98"|"CWE-89", "ref_name": "human-readable name"}}

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
    user_prompt = f"""The following attack tree nodes have incomplete fields. For each node, fill in ALL missing or empty fields.

{nodes_text}

Return a JSON array of objects, one per node in the same order. Each object must have:
- "index": the original index number
- "description": 2-3 sentence technical description
- "status": one of "draft", "validated", "mitigated", "accepted"
- "platform": specific platform/environment
- "attack_surface": specific attack surface
- "threat_category": MITRE-aligned category
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


_DOMAIN_KEYWORDS = {
    "ot_ics": [
        "scada", "plc", "hmi", "rtu", "dcs", "ics", "ot ", "ot/", "industrial",
        "modbus", "dnp3", "iec 61850", "bacnet", "profinet", "opc-ua", "opc ua",
        "safety instrumented", "sis ", "triconex", "turbine", "compressor",
        "valve", "reactor", "boiler", "furnace", "centrifuge",
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
    ],
    "web_app": [
        "web app", "api ", "rest api", "graphql", "oauth", "jwt", "xss",
        "sql injection", "ssrf", "csrf", "authentication", "web server",
    ],
}


def _detect_domain(objective: str, scope: str) -> str:
    """Detect the domain from objective and scope text."""
    text = f"{objective} {scope}".lower()
    scores: dict[str, int] = {}
    for domain, keywords in _DOMAIN_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text)
        if score > 0:
            scores[domain] = score
    if not scores:
        return "general"
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
    }

    expertise = domain_expertise.get(domain, "")
    return (
        base + expertise +
        "You generate comprehensive, realistic attack trees in structured JSON. "
        "Respond ONLY with valid JSON — no markdown, no commentary."
    )


_REFERENCE_ARCHITECTURES = {
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
}


def _get_reference_architecture(domain: str) -> str:
    """Return reference architecture for the detected domain."""
    return _REFERENCE_ARCHITECTURES.get(domain, "")


def _template_to_tree_example(template: dict) -> dict:
    """Convert a template to a simplified tree structure for few-shot example."""
    nodes = template.get("nodes", [])
    if not nodes:
        return {}

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


def find_best_template_for_objective(objective: str, scope: str) -> dict | None:
    """Find the most relevant template for a given objective by keyword matching."""
    if not TEMPLATES_DIR.exists():
        return None

    text = f"{objective} {scope}".lower()
    best_score = 0
    best_template = None

    for f in TEMPLATES_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            name = data.get("name", "").lower()
            desc = data.get("description", "").lower()
            obj = data.get("root_objective", "").lower()
            template_text = f"{name} {desc} {obj}"

            # Score by word overlap
            words = set(re.findall(r'\b\w{4,}\b', text))
            template_words = set(re.findall(r'\b\w{4,}\b', template_text))
            overlap = len(words & template_words)
            if overlap > best_score:
                best_score = overlap
                best_template = data
        except Exception:
            continue

    return best_template if best_score >= 2 else None
