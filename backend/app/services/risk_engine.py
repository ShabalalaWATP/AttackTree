"""
Risk scoring engine for attack trees.

Supports two modes:
- Simple: 1-10 scales, configurable formula
- Advanced: probability 0-1, explicit roll-up logic

Roll-up logic:
- OR: P(parent) = 1 - product(1 - P(child_i))
- AND: P(parent) = product(P(child_i))
- SEQUENCE: Same as AND (order is display-only)

Risk formula (simple mode, configurable):
  inherent_risk = (likelihood * impact * exploitability) / (effort * detectability)
  Normalized to 0-10 scale

Residual risk:
  residual = inherent * (1 - max_mitigation_effectiveness)
"""
from typing import Optional


def compute_inherent_risk(
    likelihood: Optional[float],
    impact: Optional[float],
    effort: Optional[float],
    exploitability: Optional[float],
    detectability: Optional[float],
) -> Optional[float]:
    if likelihood is None or impact is None:
        return None
    eff = effort if effort and effort > 0 else 5.0
    expl = exploitability if exploitability else 5.0
    detect = detectability if detectability and detectability > 0 else 5.0

    raw = (likelihood * impact * expl) / (eff * detect)
    # Normalize: max raw = (10*10*10)/(1*1) = 1000, min = (1*1*1)/(10*10) = 0.01
    # Scale to 0-10 using log-ish scaling
    normalized = min(10.0, max(0.0, raw * 10.0 / 100.0))
    return round(normalized, 2)


def compute_advanced_risk(
    probability: Optional[float],
    impact: Optional[float],
    cost_to_attacker: Optional[float],
) -> Optional[float]:
    """Advanced mode: risk = probability * impact * (10 / max(cost, 1)), normalized 0-10."""
    if probability is None or impact is None:
        return None
    cost = max(cost_to_attacker or 1.0, 1.0)
    raw = probability * impact * (10.0 / cost)
    return round(min(10.0, max(0.0, raw / 10.0)), 2)


def compute_residual_risk(
    inherent_risk: Optional[float],
    mitigation_effectiveness: float = 0.0,
) -> Optional[float]:
    if inherent_risk is None:
        return None
    residual = inherent_risk * (1.0 - min(1.0, max(0.0, mitigation_effectiveness)))
    return round(residual, 2)


def rollup_or_probability(child_probabilities: list[float]) -> float:
    """OR: any child can succeed. P = 1 - product(1 - p_i)"""
    if not child_probabilities:
        return 0.0
    product = 1.0
    for p in child_probabilities:
        product *= (1.0 - min(1.0, max(0.0, p)))
    return round(1.0 - product, 4)


def rollup_and_probability(child_probabilities: list[float]) -> float:
    """AND: all children required. P = product(p_i)"""
    if not child_probabilities:
        return 0.0
    product = 1.0
    for p in child_probabilities:
        product *= min(1.0, max(0.0, p))
    return round(product, 4)


def rollup_or_risk(child_risks: list[float]) -> float:
    """OR risk: max of children (worst case for defender)."""
    if not child_risks:
        return 0.0
    return round(max(child_risks), 2)


def rollup_and_risk(child_risks: list[float]) -> float:
    """AND risk: average of children (all required, risk is mean)."""
    if not child_risks:
        return 0.0
    return round(sum(child_risks) / len(child_risks), 2)


def rollup_or_likelihood(child_likelihoods: list[float]) -> float:
    """OR likelihood: take the maximum child likelihood."""
    if not child_likelihoods:
        return 0.0
    return max(child_likelihoods)


def rollup_and_likelihood(child_likelihoods: list[float]) -> float:
    """AND likelihood: take the minimum (weakest link for attacker)."""
    if not child_likelihoods:
        return 0.0
    return min(child_likelihoods)


def compute_node_scores(node_data: dict, children_data: list[dict]) -> dict:
    """
    Compute all scores for a node given its data and children.
    Returns a dict of computed fields.
    """
    result = {}

    # Compute inherent risk from local scores
    inherent = compute_inherent_risk(
        node_data.get("likelihood"),
        node_data.get("impact"),
        node_data.get("effort"),
        node_data.get("exploitability"),
        node_data.get("detectability"),
    )
    result["inherent_risk"] = inherent

    # Compute residual risk from mitigations
    mitigations = node_data.get("mitigations", [])
    max_effectiveness = 0.0
    if mitigations:
        max_effectiveness = max(m.get("effectiveness", 0) for m in mitigations)
    result["residual_risk"] = compute_residual_risk(inherent, max_effectiveness)

    # Roll-up from children
    logic = node_data.get("logic_type", "OR")
    if children_data:
        child_risks = [c.get("inherent_risk") or c.get("rolled_up_risk") for c in children_data
                       if (c.get("inherent_risk") is not None or c.get("rolled_up_risk") is not None)]
        child_likelihoods = [c.get("likelihood") or c.get("rolled_up_likelihood") for c in children_data
                            if (c.get("likelihood") is not None or c.get("rolled_up_likelihood") is not None)]

        if child_risks:
            if logic in ("AND", "SEQUENCE"):
                result["rolled_up_risk"] = rollup_and_risk(child_risks)
            else:
                result["rolled_up_risk"] = rollup_or_risk(child_risks)

        if child_likelihoods:
            if logic in ("AND", "SEQUENCE"):
                result["rolled_up_likelihood"] = rollup_and_likelihood(child_likelihoods)
            else:
                result["rolled_up_likelihood"] = rollup_or_likelihood(child_likelihoods)

    return result


def get_score_explanation(node_data: dict, children_data: list[dict]) -> dict:
    """Return a human-readable explanation of how scores were derived."""
    explanation = {
        "formula": "inherent_risk = (likelihood × impact × exploitability) / (effort × detectability), normalized to 0-10",
        "local_scores": {
            "likelihood": node_data.get("likelihood"),
            "impact": node_data.get("impact"),
            "effort": node_data.get("effort"),
            "exploitability": node_data.get("exploitability"),
            "detectability": node_data.get("detectability"),
        },
        "inherent_risk": node_data.get("inherent_risk"),
        "mitigations_applied": [],
        "residual_risk": node_data.get("residual_risk"),
        "rollup": None,
    }

    mitigations = node_data.get("mitigations", [])
    for m in mitigations:
        explanation["mitigations_applied"].append({
            "title": m.get("title", ""),
            "effectiveness": m.get("effectiveness", 0),
        })

    if children_data:
        logic = node_data.get("logic_type", "OR")
        explanation["rollup"] = {
            "logic": logic,
            "method": f"{'max' if logic == 'OR' else 'average'} of child risks",
            "children_count": len(children_data),
            "child_risks": [
                {"title": c.get("title", ""), "risk": c.get("inherent_risk") or c.get("rolled_up_risk")}
                for c in children_data
            ],
        }

    return explanation
