"""
SBOM (Software Bill of Materials) Generator
Generates CycloneDX-format SBOM documents.
"""

import json
import os
from datetime import datetime, timezone
from config.settings import REPORTS_DIR


class SBOMGenerator:
    """
    Generates CycloneDX 1.5 format SBOM.
    """

    def __init__(self, project_name, project_version="1.0.0"):
        self.sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{
                    "vendor": "SupplyChainGuard",
                    "name": "SBOM Generator",
                    "version": "1.0.0"
                }],
                "component": {
                    "type": "application",
                    "name": project_name,
                    "version": project_version
                }
            },
            "components": [],
            "vulnerabilities": [],
            "dependencies": []
        }

    def add_component(self, name, version, ecosystem, risk_score=0,
                      risk_level="LOW", vulnerabilities=None):
        """Add a scanned component to the SBOM"""
        purl_ecosystem = "npm" if ecosystem == "npm" else "pypi"

        component = {
            "type": "library",
            "name": name,
            "version": version or "unknown",
            "purl": f"pkg:{purl_ecosystem}/{name}@{version or 'unknown'}",
            "properties": [
                {
                    "name": "supplychain:risk_score",
                    "value": str(risk_score)
                },
                {
                    "name": "supplychain:risk_level",
                    "value": risk_level
                },
                {
                    "name": "supplychain:scan_timestamp",
                    "value": datetime.now(timezone.utc).isoformat()
                }
            ]
        }

        self.sbom["components"].append(component)

        if vulnerabilities:
            for vuln in vulnerabilities:
                self.sbom["vulnerabilities"].append({
                    "id": vuln.get("id", "UNKNOWN"),
                    "source": {"name": vuln.get("source", "unknown")},
                    "ratings": [{
                        "severity": vuln.get("severity", "unknown"),
                        "score": vuln.get("cvss_score", 0)
                    }],
                    "affects": [{
                        "ref": f"pkg:{purl_ecosystem}/{name}@{version or 'unknown'}"
                    }],
                    "description": vuln.get("summary", "")
                })

    def add_dependency_relationship(self, parent, child):
        """Add a dependency relationship"""
        # Find or create parent entry
        parent_ref = None
        for dep in self.sbom["dependencies"]:
            if dep["ref"] == parent:
                parent_ref = dep
                break

        if not parent_ref:
            parent_ref = {"ref": parent, "dependsOn": []}
            self.sbom["dependencies"].append(parent_ref)

        if child not in parent_ref["dependsOn"]:
            parent_ref["dependsOn"].append(child)

    def get_summary(self):
        """Get SBOM summary statistics"""
        total = len(self.sbom["components"])
        vuln_count = len(self.sbom["vulnerabilities"])

        high_risk = 0
        for component in self.sbom["components"]:
            for prop in component.get("properties", []):
                if prop["name"] == "supplychain:risk_level":
                    if prop["value"] in ["HIGH", "CRITICAL"]:
                        high_risk += 1

        return {
            "total_components": total,
            "total_vulnerabilities": vuln_count,
            "high_risk_components": high_risk,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

    def export_json(self, filename=None):
        """Export SBOM as JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            project = self.sbom["metadata"]["component"]["name"]
            filename = f"sbom_{project}_{timestamp}.json"

        filepath = os.path.join(REPORTS_DIR, filename)
        os.makedirs(REPORTS_DIR, exist_ok=True)

        with open(filepath, "w") as f:
            json.dump(self.sbom, f, indent=2)

        return filepath

    def to_dict(self):
        """Return SBOM as dictionary"""
        return self.sbom