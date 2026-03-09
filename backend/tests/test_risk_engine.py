"""Tests for the risk scoring engine."""
import pytest
from backend.app.services.risk_engine import (
    compute_inherent_risk,
    compute_residual_risk,
    rollup_or_probability,
    rollup_and_probability,
    rollup_or_risk,
    rollup_and_risk,
    rollup_or_likelihood,
    rollup_and_likelihood,
    compute_node_scores,
    get_score_explanation,
)


class TestInherentRisk:
    def test_basic_computation(self):
        risk = compute_inherent_risk(
            likelihood=7, impact=8, effort=3, exploitability=6, detectability=4,
        )
        assert risk is not None
        assert 0 <= risk <= 10

    def test_high_risk_scenario(self):
        risk = compute_inherent_risk(
            likelihood=9, impact=9, effort=2, exploitability=9, detectability=2,
        )
        assert risk is not None
        assert risk >= 5

    def test_low_risk_scenario(self):
        risk = compute_inherent_risk(
            likelihood=2, impact=2, effort=8, exploitability=2, detectability=8,
        )
        assert risk is not None
        assert risk <= 3

    def test_missing_required_fields(self):
        assert compute_inherent_risk(None, 5, 3, 5, 5) is None
        assert compute_inherent_risk(5, None, 3, 5, 5) is None

    def test_missing_optional_fields(self):
        risk = compute_inherent_risk(7, 8, None, None, None)
        assert risk is not None


class TestResidualRisk:
    def test_no_mitigation(self):
        residual = compute_residual_risk(8.0, 0.0)
        assert residual == 8.0

    def test_full_mitigation(self):
        residual = compute_residual_risk(8.0, 1.0)
        assert residual == 0.0

    def test_partial_mitigation(self):
        residual = compute_residual_risk(8.0, 0.5)
        assert residual == 4.0

    def test_none_inherent(self):
        assert compute_residual_risk(None, 0.5) is None


class TestRollupProbability:
    def test_or_single(self):
        assert rollup_or_probability([0.5]) == 0.5

    def test_or_multiple(self):
        result = rollup_or_probability([0.3, 0.4])
        assert result > 0.4  # OR should be higher than any single child
        assert result < 1.0

    def test_or_empty(self):
        assert rollup_or_probability([]) == 0.0

    def test_and_single(self):
        assert rollup_and_probability([0.5]) == 0.5

    def test_and_multiple(self):
        result = rollup_and_probability([0.8, 0.6])
        assert result == pytest.approx(0.48, abs=0.01)

    def test_and_empty(self):
        assert rollup_and_probability([]) == 0.0


class TestRollupRisk:
    def test_or_takes_max(self):
        assert rollup_or_risk([3.0, 7.0, 5.0]) == 7.0

    def test_and_takes_average(self):
        result = rollup_and_risk([3.0, 7.0, 5.0])
        assert result == 5.0

    def test_or_likelihood_takes_max(self):
        assert rollup_or_likelihood([3.0, 7.0, 5.0]) == 7.0

    def test_and_likelihood_takes_min(self):
        assert rollup_and_likelihood([3.0, 7.0, 5.0]) == 3.0


class TestNodeScores:
    def test_compute_with_children(self):
        node = {"likelihood": 5, "impact": 5, "effort": 5, "exploitability": 5,
                "detectability": 5, "logic_type": "OR", "mitigations": []}
        children = [
            {"title": "C1", "inherent_risk": 8, "rolled_up_risk": None, "likelihood": 7, "rolled_up_likelihood": None},
            {"title": "C2", "inherent_risk": 4, "rolled_up_risk": None, "likelihood": 3, "rolled_up_likelihood": None},
        ]
        result = compute_node_scores(node, children)
        assert "inherent_risk" in result
        assert result["rolled_up_risk"] == 8.0  # OR → max
        assert result["rolled_up_likelihood"] == 7.0  # OR → max

    def test_and_rollup(self):
        node = {"likelihood": 5, "impact": 5, "effort": 5, "exploitability": 5,
                "detectability": 5, "logic_type": "AND", "mitigations": []}
        children = [
            {"title": "C1", "inherent_risk": 8, "rolled_up_risk": None, "likelihood": 7, "rolled_up_likelihood": None},
            {"title": "C2", "inherent_risk": 4, "rolled_up_risk": None, "likelihood": 3, "rolled_up_likelihood": None},
        ]
        result = compute_node_scores(node, children)
        assert result["rolled_up_risk"] == 6.0  # AND → average
        assert result["rolled_up_likelihood"] == 3.0  # AND → min


class TestExplainability:
    def test_explanation_structure(self):
        node = {"likelihood": 7, "impact": 8, "effort": 3, "exploitability": 6,
                "detectability": 4, "inherent_risk": 5.6, "residual_risk": 2.8,
                "logic_type": "OR", "mitigations": [{"title": "WAF", "effectiveness": 0.5}]}
        children = [{"title": "SQLi", "inherent_risk": 7, "rolled_up_risk": None}]

        explanation = get_score_explanation(node, children)
        assert "formula" in explanation
        assert "local_scores" in explanation
        assert explanation["local_scores"]["likelihood"] == 7
        assert len(explanation["mitigations_applied"]) == 1
        assert explanation["rollup"]["logic"] == "OR"
        assert explanation["rollup"]["children_count"] == 1
