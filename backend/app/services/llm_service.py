"""
LLM integration service.
Communicates with OpenAI-compatible endpoints server-side.
API keys and TLS materials never reach the frontend.
"""
import json
import ssl
import time
import logging
from typing import Optional
import httpx

from ..services.crypto import decrypt_value

logger = logging.getLogger(__name__)


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


async def chat_completion(config: dict, messages: list[dict], temperature: float = 0.7) -> dict:
    """Send a chat completion request to the configured endpoint."""
    api_key = decrypt_value(config.get("api_key_encrypted", ""))
    base_url = config.get("base_url", "").rstrip("/")
    model = config.get("model", "")
    timeout = config.get("timeout", 120)

    headers = _build_headers(config, api_key)
    ssl_ctx = _build_ssl_context(config)

    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }

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


def parse_json_response(content: str) -> list[dict]:
    """Parse JSON from LLM response, handling common formatting issues."""
    content = content.strip()
    # Remove markdown code blocks if present
    if content.startswith("```"):
        lines = content.split("\n")
        content = "\n".join(lines[1:])
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

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
