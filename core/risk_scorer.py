"""
Advanced Risk Scoring Engine
Aggregates all detection signals into a weighted composite score.
Provides evidence-based risk classification.
"""

from datetime import datetime, timezone
from config.settings import RISK_WEIGHTS, RISK_THRESHOLDS


class RiskScorer:
    """
    Multi-dimensional risk scoring with configurable weights
    and full evidence trail.
    """

    def __init__(self):
        self.weights = RISK_WEIGHTS
        self.thresholds = RISK_THRESHOLDS

    def calculate(self, metadata_result=None, vuln_result=None,
                  code_result=None, behavioral_result=None,
                  typosquat_result=None, graph_result=None):
        """
        Calculate composite risk score from all analysis modules.
        Returns detailed breakdown with evidence.
        """
        evidence = []
        category_scores = {}

        # ── METADATA SCORE ──
        metadata_score = 0
        if metadata_result and "risk_score" in metadata_result:
            metadata_score = metadata_result["risk_score"]
            if metadata_result.get("risk_factors"):
                for factor in metadata_result["risk_factors"]:
                    evidence.append({
                        "source": "metadata",
                        "description": factor.get("description",
                                                   factor.get("check", "")),
                        "score": factor.get("score", 0),
                        "severity": factor.get("severity", "medium")
                    })

        category_scores["metadata"] = {
            "raw_score": metadata_score,
            "normalized": min(metadata_score, 100),
            "weight": self.weights.get("metadata", 0.20),
            "weighted_score": round(
                min(metadata_score, 100) * self.weights.get("metadata", 0.20),
                2
            )
        }

        # ── VULNERABILITY SCORE ──
        vuln_score = 0
        if vuln_result and "risk_score" in vuln_result:
            vuln_score = vuln_result["risk_score"]
            for vuln in vuln_result.get("vulnerabilities", []):
                evidence.append({
                    "source": "vulnerability",
                    "description": f"{vuln.get('id', 'Unknown')}: "
                                   f"{vuln.get('summary', '')[:100]}",
                    "score": vuln.get("cvss_score", 0),
                    "severity": vuln.get("severity", "unknown").lower()
                })

        category_scores["vulnerability"] = {
            "raw_score": vuln_score,
            "normalized": min(vuln_score, 100),
            "weight": self.weights.get("vulnerability", 0.35),
            "weighted_score": round(
                min(vuln_score, 100) * self.weights.get("vulnerability", 0.35),
                2
            )
        }

        # ── CODE ANALYSIS SCORE ──
        code_score = 0
        if code_result and "risk_score" in code_result:
            code_score = code_result["risk_score"]
            for issue in code_result.get("issues", []):
                evidence.append({
                    "source": "code_analysis",
                    "description": issue.get("description", ""),
                    "score": issue.get("score", 0),
                    "severity": issue.get("severity", "medium")
                })

        category_scores["code_analysis"] = {
            "raw_score": code_score,
            "normalized": min(code_score, 100),
            "weight": self.weights.get("code_analysis", 0.30),
            "weighted_score": round(
                min(code_score, 100) * self.weights.get("code_analysis", 0.30),
                2
            )
        }

        # ── DEPENDENCY GRAPH SCORE ──
        graph_score = 0
        if graph_result and "risk_score" in graph_result:
            graph_score = graph_result["risk_score"]
            for factor in graph_result.get("risk_factors", []):
                evidence.append({
                    "source": "dependency_graph",
                    "description": factor if isinstance(factor, str)
                                   else str(factor),
                    "score": 10,
                    "severity": "medium"
                })

        category_scores["dependency_graph"] = {
            "raw_score": graph_score,
            "normalized": min(graph_score, 100),
            "weight": self.weights.get("dependency_graph", 0.15),
            "weighted_score": round(
                min(graph_score, 100) * self.weights.get(
                    "dependency_graph", 0.15
                ),
                2
            )
        }

        # ── BONUS: TYPOSQUAT ──
        typosquat_score = 0
        if typosquat_result and typosquat_result.get("is_typosquat_suspect"):
            typosquat_score = typosquat_result.get("risk_score", 0)
            evidence.append({
                "source": "typosquatting",
                "description": (
                    f"Package name similar to "
                    f"'{typosquat_result.get('closest_legitimate', 'unknown')}'"
                ),
                "score": typosquat_score,
                "severity": "critical"
            })

        # ── BONUS: BEHAVIORAL ──
        behavioral_score = 0
        if behavioral_result and behavioral_result.get("risk_score", 0) > 30:
            behavioral_score = behavioral_result["risk_score"]
            for behavior in behavioral_result.get("behavior_summary", [])[:5]:
                evidence.append({
                    "source": "behavioral",
                    "description": (
                        f"{behavior['description']}: "
                        f"{behavior['count']} detections"
                    ),
                    "score": behavior.get("weighted_score", 0),
                    "severity": "high" if behavior.get(
                        "weighted_score", 0
                    ) > 10 else "medium"
                })

        # ── FINAL COMPOSITE SCORE ──
        weighted_total = sum(
            cs["weighted_score"] for cs in category_scores.values()
        )

        # Add bonus scores (typosquat and behavioral are bonuses on top)
        bonus = (typosquat_score * 0.3) + (behavioral_score * 0.15)
        final_score = min(round(weighted_total + bonus, 2), 100)

        # ── CLASSIFICATION ──
        if final_score >= self.thresholds.get("CRITICAL", 75):
            risk_level = "CRITICAL"
            action = "BLOCK installation. Manual security review required."
            color = "#d50000"
        elif final_score >= self.thresholds.get("HIGH", 50):
            risk_level = "HIGH"
            action = "WARNING. Proceed with extreme caution. Review all flagged issues."
            color = "#ff6d00"
        elif final_score >= self.thresholds.get("MEDIUM", 25):
            risk_level = "MEDIUM"
            action = "Review flagged issues before proceeding with installation."
            color = "#ffd600"
        else:
            risk_level = "LOW"
            action = "No significant risks detected. Safe to proceed."
            color = "#00c853"

        return {
            "final_score": final_score,
            "risk_level": risk_level,
            "risk_color": color,
            "recommended_action": action,
            "category_breakdown": category_scores,
            "bonus_scores": {
                "typosquatting": round(typosquat_score * 0.3, 2),
                "behavioral": round(behavioral_score * 0.15, 2)
            },
            "evidence": evidence,
            "evidence_count": len(evidence),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }