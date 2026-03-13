"""Helpers for normalizing and comparing attack-tree node titles."""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable, TypeVar

T = TypeVar("T")

_TITLE_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOP_WORDS = {
    "a",
    "an",
    "and",
    "for",
    "in",
    "of",
    "on",
    "the",
    "to",
    "via",
    "with",
}


def _normalize_token(token: str) -> str:
    normalized = token.strip().lower()
    if len(normalized) > 4 and normalized.endswith("ies"):
        return normalized[:-3] + "y"
    if len(normalized) > 3 and normalized.endswith("es"):
        if normalized[-3] in {"s", "x", "z"} or normalized[-4:-2] in {"sh", "ch"}:
            return normalized[:-2]
        if normalized[-3] in {"a", "e", "i", "o", "u"}:
            return normalized[:-1]
    if len(normalized) > 3 and normalized.endswith("s"):
        return normalized[:-1]
    return normalized


def normalized_title_tokens(title: str) -> list[str]:
    return [
        _normalize_token(token)
        for token in _TITLE_TOKEN_RE.findall((title or "").lower())
        if _normalize_token(token) and _normalize_token(token) not in _STOP_WORDS
    ]


def normalize_node_title(title: str) -> str:
    return " ".join(normalized_title_tokens(title))


def title_similarity(left: str, right: str) -> float:
    left_tokens = set(normalized_title_tokens(left))
    right_tokens = set(normalized_title_tokens(right))
    if not left_tokens or not right_tokens:
        return 0.0
    if left_tokens == right_tokens:
        return 1.0
    overlap = len(left_tokens & right_tokens)
    union = len(left_tokens | right_tokens)
    return overlap / union if union else 0.0


def dedupe_titled_items(
    items: Iterable[T],
    *,
    title_getter: Callable[[T], str],
    existing_titles: Iterable[str] | None = None,
) -> tuple[list[T], list[str]]:
    seen = {
        normalize_node_title(title)
        for title in (existing_titles or [])
        if normalize_node_title(title)
    }
    kept: list[T] = []
    dropped_titles: list[str] = []

    for item in items:
        title = str(title_getter(item) or "").strip()
        normalized = normalize_node_title(title)
        if not title:
            continue
        if normalized and normalized in seen:
            dropped_titles.append(title)
            continue
        if normalized:
            seen.add(normalized)
        kept.append(item)

    return kept, dropped_titles


def best_near_duplicate_match(title: str, existing_titles: Iterable[str], *, threshold: float = 0.72) -> dict[str, Any] | None:
    best_title = ""
    best_score = 0.0
    for existing_title in existing_titles:
        score = title_similarity(title, existing_title)
        if score > best_score:
            best_score = score
            best_title = existing_title
    if best_title and best_score >= threshold:
        return {
            "title": best_title,
            "score": round(best_score, 2),
        }
    return None
