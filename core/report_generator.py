"""
Report Generator Module
Creates structured scan reports in JSON and text formats.
"""

import json
import os
from datetime import datetime, timezone
from config.settings import REPORTS_DIR


class ReportGenerator:
    """
    Generates comprehensive scan reports.
    """

    def __init__(self):
        os.makedirs(REPORTS_DIR, exist_ok=True)

    def generate(self, package_name, ecosystem, metadata_result=None,
                 typosquat_result=None, vuln_result=None,
                 code_result=None, behavioral_result=None,
                 graph_result=None, risk_result=None):
        """
        Generate a complete scan report from all module results.
        """
        report = {
            "report_id": f"SCG-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool": "SupplyChainGuard v1.0",
            "target": {
                "package_name": package_name,
                "ecosystem": ecosystem
            },
            "summary": {},
            "risk_assessment": {},
            "metadata_analysis": {},
            "typosquatting_analysis": {},
            "vulnerability_analysis": {},
            "code_analysis": {},
            "behavioral_analysis": {},
            "dependency_graph_analysis": {},
            "recommendations": []
        }

        # ── RISK ASSESSMENT ──
        if risk_result:
            report["summary"] = {
                "final_score": risk_result.get("final_score", 0),
                "risk_level": risk_result.get("risk_level", "UNKNOWN"),
                "recommended_action": risk_result.get(
                    "recommended_action", ""
                ),
                "evidence_count": risk_result.get("evidence_count", 0)
            }
            report["risk_assessment"] = risk_result

        # ── MODULE RESULTS ──
        if metadata_result:
            report["metadata_analysis"] = {
                "risk_score": metadata_result.get("risk_score", 0),
                "checks_performed": len(
                    metadata_result.get("checks", [])
                ),
                "issues_found": len(
                    metadata_result.get("risk_factors", [])
                ),
                "details": metadata_result
            }

        if typosquat_result:
            report["typosquatting_analysis"] = {
                "is_suspect": typosquat_result.get(
                    "is_typosquat_suspect", False
                ),
                "closest_match": typosquat_result.get(
                    "closest_legitimate"
                ),
                "techniques_triggered": typosquat_result.get(
                    "techniques_triggered", []
                ),
                "details": typosquat_result
            }

        if vuln_result:
            report["vulnerability_analysis"] = {
                "total_vulnerabilities": vuln_result.get("total_count", 0),
                "critical": vuln_result.get("critical_count", 0),
                "high": vuln_result.get("high_count", 0),
                "medium": vuln_result.get("medium_count", 0),
                "low": vuln_result.get("low_count", 0),
                "details": vuln_result
            }

        if code_result:
            report["code_analysis"] = {
                "risk_score": code_result.get("risk_score", 0),
                "total_issues": code_result.get("summary", {}).get(
                    "total_issues", 0
                ),
                "obfuscation_detected": code_result.get(
                    "obfuscation_detected", False
                ),
                "details": code_result
            }

        if behavioral_result:
            report["behavioral_analysis"] = {
                "risk_score": behavioral_result.get("risk_score", 0),
                "dominant_behavior": behavioral_result.get(
                    "dominant_behavior"
                ),
                "assessment": behavioral_result.get("risk_assessment", ""),
                "details": behavioral_result
            }

        if graph_result:
            report["dependency_graph_analysis"] = {
                "total_dependencies": graph_result.get(
                    "total_dependencies", 0
                ),
                "critical_nodes": len(
                    graph_result.get("critical_nodes", [])
                ),
                "details": graph_result
            }

        # ── RECOMMENDATIONS ──
        report["recommendations"] = self._generate_recommendations(report)

        return report

    def _generate_recommendations(self, report):
        """Generate actionable recommendations based on findings"""
        recommendations = []
        summary = report.get("summary", {})
        risk_level = summary.get("risk_level", "LOW")

        if risk_level == "CRITICAL":
            recommendations.append({
                "priority": "CRITICAL",
                "action": "DO NOT install this package. "
                          "It shows strong indicators of malicious activity."
            })

        if risk_level == "HIGH":
            recommendations.append({
                "priority": "HIGH",
                "action": "Review all flagged issues before installation. "
                          "Consider alternatives."
            })

        # Typosquatting
        typo = report.get("typosquatting_analysis", {})
        if typo.get("is_suspect"):
            recommendations.append({
                "priority": "CRITICAL",
                "action": f"Package name is suspiciously similar to "
                          f"'{typo.get('closest_match')}'. "
                          f"Verify you have the correct package name."
            })

        # Vulnerabilities
        vuln = report.get("vulnerability_analysis", {})
        if vuln.get("critical", 0) > 0:
            recommendations.append({
                "priority": "HIGH",
                "action": f"Package has {vuln['critical']} critical "
                          f"vulnerability(ies). Check for patches or alternatives."
            })

        # Code analysis
        code = report.get("code_analysis", {})
        if code.get("obfuscation_detected"):
            recommendations.append({
                "priority": "HIGH",
                "action": "Obfuscated code detected. "
                          "This is unusual for legitimate packages."
            })

        # Metadata
        meta = report.get("metadata_analysis", {})
        if meta.get("risk_score", 0) > 50:
            recommendations.append({
                "priority": "MEDIUM",
                "action": "Package metadata shows multiple anomalies. "
                          "Verify the package source and maintainer."
            })

        if not recommendations:
            recommendations.append({
                "priority": "INFO",
                "action": "No significant issues found. "
                          "Package appears safe for installation."
            })

        return recommendations

    def save_report(self, report, filename=None):
        """Save report to JSON file"""
        if not filename:
            pkg = report["target"]["package_name"]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{pkg}_{timestamp}.json"

        filepath = os.path.join(REPORTS_DIR, filename)

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2, default=str)

        return filepath

    def to_text(self, report):
        """Convert report to readable text format"""
        lines = []
        lines.append("=" * 60)
        lines.append("  SUPPLY CHAIN GUARD - SECURITY SCAN REPORT")
        lines.append("=" * 60)
        lines.append(f"  Report ID: {report.get('report_id', 'N/A')}")
        lines.append(f"  Generated: {report.get('generated_at', 'N/A')}")
        lines.append(f"  Package: {report['target']['package_name']}")
        lines.append(f"  Ecosystem: {report['target']['ecosystem']}")
        lines.append("=" * 60)

        summary = report.get("summary", {})
        lines.append(f"\n  RISK SCORE: {summary.get('final_score', 0)}/100")
        lines.append(f"  RISK LEVEL: {summary.get('risk_level', 'UNKNOWN')}")
        lines.append(f"  ACTION: {summary.get('recommended_action', 'N/A')}")

        lines.append("\n" + "-" * 60)
        lines.append("  RECOMMENDATIONS")
        lines.append("-" * 60)

        for rec in report.get("recommendations", []):
            lines.append(f"  [{rec['priority']}] {rec['action']}")

        lines.append("\n" + "=" * 60)

        return "\n".join(lines)