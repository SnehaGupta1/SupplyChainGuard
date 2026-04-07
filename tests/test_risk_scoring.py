"""
Tests for Risk Scoring Engine
"""

import pytest
from core.risk_scorer import RiskScorer


class TestRiskScorer:
    """Test suite for RiskScorer"""

    def setup_method(self):
        self.scorer = RiskScorer()

    def test_all_clean_results_low_risk(self):
        """All clean module results should produce LOW risk"""
        result = self.scorer.calculate(
            metadata_result={"risk_score": 0, "risk_factors": []},
            vuln_result={"risk_score": 0, "vulnerabilities": []},
            code_result={"risk_score": 0, "issues": []},
            graph_result={"risk_score": 0, "risk_factors": []}
        )
        assert result["risk_level"] == "LOW"
        assert result["final_score"] < 25

    def test_high_metadata_risk(self):
        """High metadata risk should increase final score"""
        result = self.scorer.calculate(
            metadata_result={
                "risk_score": 80,
                "risk_factors": [
                    {"description": "No author", "score": 15, "severity": "medium"},
                    {"description": "New package", "score": 20, "severity": "high"},
                    {"description": "Install scripts", "score": 30, "severity": "high"}
                ]
            },
            vuln_result={"risk_score": 0, "vulnerabilities": []},
            code_result={"risk_score": 0, "issues": []},
            graph_result={"risk_score": 0, "risk_factors": []}
        )
        assert result["final_score"] > 10
        assert len(result["evidence"]) >= 3

    def test_critical_vulnerability(self):
        """Critical CVE should produce high risk"""
        result = self.scorer.calculate(
            metadata_result={"risk_score": 0, "risk_factors": []},
            vuln_result={
                "risk_score": 80,
                "vulnerabilities": [{
                    "id": "CVE-2024-0001",
                    "summary": "Remote code execution",
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                    "source": "NVD"
                }]
            },
            code_result={"risk_score": 0, "issues": []},
            graph_result={"risk_score": 0, "risk_factors": []}
        )
        assert result["final_score"] > 20
        assert any(e["source"] == "vulnerability" for e in result["evidence"])

    def test_malicious_code_detection(self):
        """Malicious code should produce high risk"""
        result = self.scorer.calculate(
            metadata_result={"risk_score": 0, "risk_factors": []},
            vuln_result={"risk_score": 0, "vulnerabilities": []},
            code_result={
                "risk_score": 90,
                "issues": [
                    {"description": "eval() execution", "score": 35, "severity": "critical"},
                    {"description": "Base64 encoded payload", "score": 25, "severity": "high"},
                    {"description": "subprocess usage", "score": 20, "severity": "high"}
                ]
            },
            graph_result={"risk_score": 0, "risk_factors": []}
        )
        assert result["final_score"] > 20
        assert result["risk_level"] in ["MEDIUM", "HIGH", "CRITICAL"]

    def test_typosquat_bonus(self):
        """Typosquatting detection should add bonus risk"""
        result_without = self.scorer.calculate(
            metadata_result={"risk_score": 20, "risk_factors": []},
            vuln_result={"risk_score": 0, "vulnerabilities": []},
            code_result={"risk_score": 0, "issues": []},
            typosquat_result={"is_typosquat_suspect": False, "risk_score": 0}
        )

        result_with = self.scorer.calculate(
            metadata_result={"risk_score": 20, "risk_factors": []},
            vuln_result={"risk_score": 0, "vulnerabilities": []},
            code_result={"risk_score": 0, "issues": []},
            typosquat_result={
                "is_typosquat_suspect": True,
                "risk_score": 40,
                "closest_legitimate": "express"
            }
        )

        assert result_with["final_score"] > result_without["final_score"]

    def test_combined_all_high(self):
        """All modules high risk should produce CRITICAL"""
        result = self.scorer.calculate(
            metadata_result={
                "risk_score": 80,
                "risk_factors": [{"description": "test", "score": 80, "severity": "high"}]
            },
            vuln_result={
                "risk_score": 90,
                "vulnerabilities": [{
                    "id": "CVE-2024-9999",
                    "summary": "Critical RCE",
                    "severity": "CRITICAL",
                    "cvss_score": 10.0,
                    "source": "NVD"
                }]
            },
            code_result={
                "risk_score": 85,
                "issues": [{"description": "eval", "score": 35, "severity": "critical"}]
            },
            graph_result={
                "risk_score": 50,
                "risk_factors": ["Large dependency tree"]
            },
            typosquat_result={
                "is_typosquat_suspect": True,
                "risk_score": 40,
                "closest_legitimate": "lodash"
            }
        )
        assert result["risk_level"] in ["HIGH", "CRITICAL"]
        assert result["final_score"] >= 50

    def test_score_bounded(self):
        """Final score should never exceed 100"""
        result = self.scorer.calculate(
            metadata_result={"risk_score": 100, "risk_factors": []},
            vuln_result={"risk_score": 100, "vulnerabilities": []},
            code_result={"risk_score": 100, "issues": []},
            graph_result={"risk_score": 100, "risk_factors": []},
            typosquat_result={"is_typosquat_suspect": True, "risk_score": 100},
            behavioral_result={"risk_score": 100, "behavior_summary": []}
        )
        assert result["final_score"] <= 100

    def test_evidence_trail(self):
        """Evidence trail should contain entries from all flagged modules"""
        result = self.scorer.calculate(
            metadata_result={
                "risk_score": 30,
                "risk_factors": [
                    {"description": "No author", "score": 15, "severity": "medium"}
                ]
            },
            vuln_result={
                "risk_score": 40,
                "vulnerabilities": [{
                    "id": "CVE-2024-0001",
                    "summary": "test vuln",
                    "severity": "HIGH",
                    "source": "OSV"
                }]
            },
            code_result={
                "risk_score": 20,
                "issues": [
                    {"description": "eval detected", "score": 20, "severity": "high"}
                ]
            }
        )

        sources = {e["source"] for e in result["evidence"]}
        assert "metadata" in sources
        assert "vulnerability" in sources
        assert "code_analysis" in sources

    def test_result_structure(self):
        """Result should contain all expected keys"""
        result = self.scorer.calculate(
            metadata_result={"risk_score": 0, "risk_factors": []},
            vuln_result={"risk_score": 0, "vulnerabilities": []}
        )

        expected_keys = [
            "final_score", "risk_level", "risk_color",
            "recommended_action", "category_breakdown",
            "bonus_scores", "evidence", "evidence_count", "timestamp"
        ]

        for key in expected_keys:
            assert key in result, f"Missing key: {key}"