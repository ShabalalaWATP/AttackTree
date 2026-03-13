"""Ranked search and validation helpers for bundled reference libraries."""

from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from .environment_catalog_service import load_environment_catalogs

REFERENCE_DIR = Path(__file__).parent.parent / "reference_data"
SUPPORTED_REFERENCE_FRAMEWORKS = (
    "attack",
    "capec",
    "cwe",
    "owasp",
    "infra_attack_patterns",
    "software_research_patterns",
    "environment_catalog",
)

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_./:-]{1,}")

_ARTIFACT_FRAMEWORK_BOOSTS: dict[str, dict[str, int]] = {
    "attack_tree": {
        "attack": 8,
        "capec": 6,
        "cwe": 5,
        "owasp": 4,
        "infra_attack_patterns": 7,
        "software_research_patterns": 7,
        "environment_catalog": 5,
    },
    "node_mapping": {
        "attack": 8,
        "capec": 6,
        "cwe": 5,
        "owasp": 4,
        "infra_attack_patterns": 7,
        "software_research_patterns": 7,
        "environment_catalog": 5,
    },
    "threat_model": {
        "attack": 7,
        "capec": 6,
        "cwe": 5,
        "owasp": 4,
        "infra_attack_patterns": 6,
        "software_research_patterns": 5,
        "environment_catalog": 4,
    },
    "kill_chain": {
        "attack": 12,
        "capec": 4,
        "cwe": 3,
        "owasp": 2,
        "infra_attack_patterns": 3,
        "software_research_patterns": 2,
        "environment_catalog": 2,
    },
    "scenario": {
        "attack": 7,
        "capec": 5,
        "cwe": 4,
        "owasp": 4,
        "infra_attack_patterns": 6,
        "software_research_patterns": 5,
        "environment_catalog": 4,
    },
    "infra_map": {
        "environment_catalog": 12,
        "infra_attack_patterns": 9,
        "software_research_patterns": 4,
        "attack": 4,
        "capec": 3,
        "cwe": 3,
        "owasp": 2,
    },
}

_FRAMEWORK_ALIASES = {
    "att&ck": "attack",
    "mitre_attack": "attack",
    "mitre_attck": "attack",
    "software_research": "software_research_patterns",
    "infra_patterns": "infra_attack_patterns",
}


def _normalize_framework(value: str) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return _FRAMEWORK_ALIASES.get(normalized, normalized)


def _tokenize(text: str) -> set[str]:
    return {
        token
        for token in _TOKEN_RE.findall((text or "").lower())
        if len(token) >= 2 and token not in {"the", "and", "for", "with", "from"}
    }


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _flatten_keywords(values: list[Any]) -> str:
    return " ".join(_coerce_text(value) for value in values if _coerce_text(value))


def _load_json_framework(framework: str) -> list[dict[str, Any]]:
    file_path = REFERENCE_DIR / f"{framework}.json"
    if not file_path.exists():
        return []
    with file_path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, list) else []


def _build_framework_items(framework: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for raw in _load_json_framework(framework):
        ref_id = _coerce_text(raw.get("id"))
        ref_name = _coerce_text(raw.get("name"))
        description = _coerce_text(raw.get("description"))
        category = _coerce_text(raw.get("category"))
        tactic = _coerce_text(raw.get("tactic"))
        severity = _coerce_text(raw.get("severity"))
        metadata_text = _flatten_keywords([category, tactic, severity])
        title_tokens = _tokenize(f"{ref_id} {ref_name}")
        metadata_tokens = _tokenize(metadata_text)
        description_tokens = _tokenize(description)
        search_text = _flatten_keywords([ref_id, ref_name, metadata_text, description])
        items.append(
            {
                "framework": framework,
                "ref_id": ref_id,
                "ref_name": ref_name,
                "description": description,
                "category": category or None,
                "tactic": tactic or None,
                "severity": severity or None,
                "search_text": search_text.lower(),
                "title_tokens": title_tokens,
                "metadata_tokens": metadata_tokens,
                "description_tokens": description_tokens,
                "all_tokens": title_tokens | metadata_tokens | description_tokens,
            }
        )
    return items


def _build_environment_catalog_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for catalog in load_environment_catalogs():
        catalog_name = _coerce_text(catalog.get("name"))
        catalog_sector = _coerce_text(catalog.get("sector"))
        catalog_contexts = catalog.get("context_presets", []) or []
        for node in catalog.get("nodes", []) or []:
            ref_id = _coerce_text(node.get("id"))
            ref_name = _coerce_text(node.get("label"))
            description = _coerce_text(node.get("description"))
            category = _coerce_text(node.get("category"))
            metadata_text = _flatten_keywords(
                [
                    category,
                    catalog_name,
                    catalog_sector,
                    *catalog_contexts,
                    *(concept.get("label") for concept in (node.get("shared_concepts") or [])),
                    *(catalog_item.get("name") for catalog_item in (node.get("related_catalogs") or [])),
                    *(node.get("attack_surfaces") or []),
                    *(node.get("telemetry") or []),
                    *(node.get("management_interfaces") or []),
                    *(node.get("dependencies") or []),
                    *(node.get("common_protocols") or []),
                    *(node.get("example_technologies") or []),
                ]
            )
            title_tokens = _tokenize(f"{ref_id} {ref_name}")
            metadata_tokens = _tokenize(metadata_text)
            description_tokens = _tokenize(description)
            search_text = _flatten_keywords([ref_id, ref_name, metadata_text, description])
            items.append(
                {
                    "framework": "environment_catalog",
                    "ref_id": ref_id,
                    "ref_name": ref_name,
                    "description": description,
                    "category": category or None,
                    "tactic": None,
                    "severity": None,
                    "catalog_name": catalog_name,
                    "catalog_sector": catalog_sector,
                    "search_text": search_text.lower(),
                    "title_tokens": title_tokens,
                    "metadata_tokens": metadata_tokens,
                    "description_tokens": description_tokens,
                    "all_tokens": title_tokens | metadata_tokens | description_tokens,
                }
            )
    return items


@lru_cache(maxsize=1)
def _reference_index() -> tuple[dict[tuple[str, str], dict[str, Any]], tuple[dict[str, Any], ...]]:
    items: list[dict[str, Any]] = []
    for framework in SUPPORTED_REFERENCE_FRAMEWORKS:
        if framework == "environment_catalog":
            items.extend(_build_environment_catalog_items())
        else:
            items.extend(_build_framework_items(framework))
    by_key = {
        (_normalize_framework(item["framework"]), item["ref_id"]): item
        for item in items
        if item.get("ref_id")
    }
    return by_key, tuple(items)


def get_reference_record(framework: str, ref_id: str) -> dict[str, Any] | None:
    by_key, _ = _reference_index()
    return by_key.get((_normalize_framework(framework), _coerce_text(ref_id)))


def validate_reference_identifier(framework: str, ref_id: str) -> bool:
    return get_reference_record(framework, ref_id) is not None


def _artifact_boost(artifact_type: str, framework: str, context_text: str) -> int:
    normalized_artifact = _coerce_text(artifact_type).lower().replace("-", "_").replace(" ", "_")
    boost = _ARTIFACT_FRAMEWORK_BOOSTS.get(normalized_artifact, {}).get(framework, 0)
    if normalized_artifact in {"attack_tree", "node_mapping"} and "software" in context_text and framework == "software_research_patterns":
        boost += 3
    if normalized_artifact == "infra_map" and any(keyword in context_text for keyword in ("telecom", "data centre", "data center", "ot", "facility")):
        if framework in {"environment_catalog", "infra_attack_patterns"}:
            boost += 2
    if normalized_artifact == "kill_chain" and "ransomware" in context_text and framework == "attack":
        boost += 2
    return boost


def _cap_per_framework(limit: int, framework_count: int) -> int:
    if framework_count <= 1:
        return limit
    return max(2, min(6, math.ceil(limit / max(2, min(framework_count, 4)))))


def search_references(
    *,
    query: str = "",
    artifact_type: str = "",
    context_preset: str = "",
    objective: str = "",
    scope: str = "",
    target_kind: str = "",
    target_summary: str = "",
    allowed_frameworks: list[str] | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    normalized_limit = max(1, min(int(limit or 10), 50))
    requested_frameworks = [
        _normalize_framework(item)
        for item in (allowed_frameworks or list(SUPPORTED_REFERENCE_FRAMEWORKS))
        if _normalize_framework(item) in SUPPORTED_REFERENCE_FRAMEWORKS
    ]
    if not requested_frameworks:
        requested_frameworks = list(SUPPORTED_REFERENCE_FRAMEWORKS)

    query_text = _coerce_text(query).lower()
    context_text = _flatten_keywords([context_preset, objective, scope, target_kind, target_summary]).lower()
    query_tokens = _tokenize(query_text)
    context_tokens = _tokenize(context_text)

    _, all_items = _reference_index()
    scored: list[dict[str, Any]] = []
    for item in all_items:
        framework = item["framework"]
        if framework not in requested_frameworks:
            continue

        ref_id = item["ref_id"]
        ref_name = item["ref_name"]
        description = item["description"]
        score = 0
        reasons: list[str] = []

        ref_id_lower = ref_id.lower()
        ref_name_lower = ref_name.lower()
        search_text = item["search_text"]

        if query_text:
            if query_text == ref_id_lower:
                score += 1000
                reasons.append("exact id match")
            elif query_text in ref_id_lower:
                score += 350
                reasons.append("id match")

            if query_text == ref_name_lower:
                score += 950
                reasons.append("exact name match")
            elif query_text and query_text in ref_name_lower:
                score += 220
                reasons.append("name match")

            title_hits = len(query_tokens & item["title_tokens"])
            if title_hits:
                score += title_hits * 90
                reasons.append("title keywords")

            metadata_hits = len(query_tokens & item["metadata_tokens"])
            if metadata_hits:
                score += metadata_hits * 60
                reasons.append("category keywords")

            description_hits = len(query_tokens & item["description_tokens"])
            if description_hits:
                score += description_hits * 16
                reasons.append("description keywords")

            if score == 0 and query_text not in search_text:
                continue
            if query_text in search_text:
                score += 12

        if context_tokens:
            context_hits = len(context_tokens & item["all_tokens"])
            if context_hits:
                score += context_hits * 8
                reasons.append("context alignment")

        artifact_score = _artifact_boost(artifact_type, framework, context_text)
        if artifact_score:
            score += artifact_score
            reasons.append("artifact relevance")

        if score <= 0:
            continue

        scored.append(
            {
                "framework": framework,
                "ref_id": ref_id,
                "ref_name": ref_name,
                "description": description,
                "category": item.get("category"),
                "tactic": item.get("tactic"),
                "severity": item.get("severity"),
                "score": score,
                "reasons": sorted(set(reasons)),
            }
        )

    scored.sort(
        key=lambda item: (
            -int(item["score"]),
            item["framework"],
            item["ref_id"],
        )
    )

    framework_cap = _cap_per_framework(normalized_limit, len(set(requested_frameworks)))
    counts: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for item in scored:
        framework = item["framework"]
        if counts.get(framework, 0) >= framework_cap:
            continue
        counts[framework] = counts.get(framework, 0) + 1
        results.append(item)
        if len(results) >= normalized_limit:
            break
    return results


def format_reference_candidates_for_prompt(
    candidates: list[dict[str, Any]],
    *,
    max_per_framework: int = 4,
) -> str:
    if not candidates:
        return ""

    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in candidates:
        grouped.setdefault(item["framework"], []).append(item)

    lines = ["Retrieved Candidate References:"]
    for framework in sorted(grouped):
        lines.append(f"- {framework}:")
        for item in grouped[framework][:max(1, max_per_framework)]:
            detail_bits = [
                item["ref_id"],
                item["ref_name"],
            ]
            if item.get("category"):
                detail_bits.append(f"category={item['category']}")
            if item.get("tactic"):
                detail_bits.append(f"tactic={item['tactic']}")
            if item.get("severity"):
                detail_bits.append(f"severity={item['severity']}")
            if item.get("reasons"):
                detail_bits.append("why=" + ", ".join(item["reasons"][:3]))
            lines.append("  - " + " | ".join(detail_bits))
    return "\n".join(lines)


def candidate_to_reference_link(
    candidate: dict[str, Any],
    *,
    source: str = "ai",
    rationale: str = "",
) -> dict[str, Any]:
    score = int(candidate.get("score", 0) or 0)
    confidence = max(0.1, min(1.0, round(score / 1000, 2)))
    return {
        "framework": candidate.get("framework", ""),
        "ref_id": candidate.get("ref_id", ""),
        "ref_name": candidate.get("ref_name", ""),
        "confidence": confidence,
        "rationale": rationale or "; ".join(candidate.get("reasons", [])[:3]),
        "source": source,
    }


def normalize_reference_link(
    value: dict[str, Any],
    *,
    default_source: str = "manual",
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    framework = _normalize_framework(value.get("framework", ""))
    ref_id = _coerce_text(value.get("ref_id"))
    record = get_reference_record(framework, ref_id)
    if not framework or not ref_id or not record:
        return None
    ref_name = _coerce_text(value.get("ref_name")) or record["ref_name"]
    try:
        raw_confidence = value.get("confidence")
        confidence = float(raw_confidence) if raw_confidence not in (None, "") else None
    except (TypeError, ValueError):
        confidence = None
    if confidence is not None:
        confidence = max(0.0, min(1.0, confidence))
    return {
        "framework": framework,
        "ref_id": ref_id,
        "ref_name": ref_name,
        "confidence": confidence,
        "rationale": _coerce_text(value.get("rationale")),
        "source": _coerce_text(value.get("source")) or default_source,
    }


def dedupe_reference_links(links: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for item in links:
        normalized = normalize_reference_link(item, default_source=_coerce_text(item.get("source")) or "manual")
        if not normalized:
            continue
        key = (normalized["framework"], normalized["ref_id"])
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = normalized
            continue
        existing_conf = existing.get("confidence") if isinstance(existing.get("confidence"), (int, float)) else 0
        new_conf = normalized.get("confidence") if isinstance(normalized.get("confidence"), (int, float)) else 0
        if new_conf > existing_conf:
            deduped[key] = normalized
            continue
        if not existing.get("rationale") and normalized.get("rationale"):
            existing["rationale"] = normalized["rationale"]
        if existing.get("source") == "manual" and normalized.get("source"):
            existing["source"] = normalized["source"]
    return list(deduped.values())
