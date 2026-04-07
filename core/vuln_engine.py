"""
Vulnerability Intelligence Engine
Queries OSV, NVD, and GitHub Advisory databases
to find known vulnerabilities for a package.
"""

import requests
from config.settings import (
    OSV_API_URL,
    NVD_API_URL,
    SCAN_TIMEOUT_SECONDS
)


class VulnerabilityEngine:
    """
    Queries multiple vulnerability databases and aggregates results.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "SupplyChainGuard/1.0"
        })

    # ──────────────────────────────────────────────
    # PUBLIC API
    # ──────────────────────────────────────────────

    def check(self, package_name, version=None, ecosystem="npm"):
        """
        Check a package against all vulnerability databases.
        Returns aggregated vulnerability report.
        """
        results = {
            "package_name": package_name,
            "version": version,
            "ecosystem": ecosystem,
            "vulnerabilities": [],
            "total_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "risk_score": 0,
            "sources_checked": [],
            "errors": []
        }

        # 1. Check OSV Database
        osv_results = self._check_osv(package_name, version, ecosystem)
        if "error" in osv_results:
            results["errors"].append({"source": "OSV", "error": osv_results["error"]})
        else:
            results["vulnerabilities"].extend(osv_results.get("vulnerabilities", []))
            results["sources_checked"].append("OSV")

        # 2. Check NVD Database
        nvd_results = self._check_nvd(package_name)
        if "error" in nvd_results:
            results["errors"].append({"source": "NVD", "error": nvd_results["error"]})
        else:
            results["vulnerabilities"].extend(nvd_results.get("vulnerabilities", []))
            results["sources_checked"].append("NVD")

        # Deduplicate by CVE ID
        seen_ids = set()
        unique_vulns = []
        for vuln in results["vulnerabilities"]:
            vuln_id = vuln.get("id", "")
            if vuln_id not in seen_ids:
                seen_ids.add(vuln_id)
                unique_vulns.append(vuln)
        results["vulnerabilities"] = unique_vulns

        # Count by severity
        for vuln in results["vulnerabilities"]:
            severity = vuln.get("severity", "unknown").lower()
            if severity == "critical":
                results["critical_count"] += 1
            elif severity == "high":
                results["high_count"] += 1
            elif severity == "medium":
                results["medium_count"] += 1
            elif severity == "low":
                results["low_count"] += 1

        results["total_count"] = len(results["vulnerabilities"])

        # Calculate risk score
        results["risk_score"] = self._calculate_vuln_risk_score(results)

        return results

    # ──────────────────────────────────────────────
    # OSV DATABASE
    # ──────────────────────────────────────────────

    def _check_osv(self, package_name, version, ecosystem):
        """Query OSV (Open Source Vulnerabilities) database"""
        try:
            # Map ecosystem names to OSV format
            osv_ecosystem_map = {
                "npm": "npm",
                "pypi": "PyPI"
            }

            osv_ecosystem = osv_ecosystem_map.get(ecosystem, ecosystem)

            payload = {
                "package": {
                    "name": package_name,
                    "ecosystem": osv_ecosystem
                }
            }

            if version:
                payload["version"] = version

            url = f"{OSV_API_URL}/query"
            response = self.session.post(
                url,
                json=payload,
                timeout=SCAN_TIMEOUT_SECONDS
            )

            if response.status_code != 200:
                return {"error": f"OSV returned status {response.status_code}"}

            data = response.json()
            vulns = []

            for osv_vuln in data.get("vulns", []):
                severity = self._extract_osv_severity(osv_vuln)
                vuln = {
                    "id": osv_vuln.get("id", ""),
                    "summary": osv_vuln.get("summary", "No summary available"),
                    "details": osv_vuln.get("details", ""),
                    "severity": severity,
                    "source": "OSV",
                    "references": [
                        ref.get("url") for ref in osv_vuln.get("references", [])
                        if ref.get("url")
                    ][:5],
                    "aliases": osv_vuln.get("aliases", []),
                    "published": osv_vuln.get("published", ""),
                    "modified": osv_vuln.get("modified", "")
                }
                vulns.append(vuln)

            return {"vulnerabilities": vulns}

        except requests.exceptions.Timeout:
            return {"error": "OSV request timed out"}
        except requests.exceptions.RequestException as e:
            return {"error": f"OSV network error: {str(e)}"}
        except Exception as e:
            return {"error": f"OSV unexpected error: {str(e)}"}

    def _extract_osv_severity(self, osv_vuln):
        """Extract severity from OSV vulnerability data"""
        severity_data = osv_vuln.get("database_specific", {})
        severity = severity_data.get("severity", "")

        if severity:
            return severity.upper()

        # Try to extract from CVSS
        for affected in osv_vuln.get("affected", []):
            ecosystem_specific = affected.get("ecosystem_specific", {})
            if "severity" in ecosystem_specific:
                return ecosystem_specific["severity"].upper()

        # Try severity from severity list
        severities = osv_vuln.get("severity", [])
        if severities:
            for sev in severities:
                score_str = sev.get("score", "")
                if score_str:
                    try:
                        # Parse CVSS score
                        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
                        return self._cvss_to_severity(score_str)
                    except Exception:
                        pass

        return "UNKNOWN"

    def _cvss_to_severity(self, cvss_string):
        """Convert CVSS vector string to severity level"""
        # Simple heuristic based on CVSS string
        try:
            # Try extracting numeric score if present
            if "/" in cvss_string:
                parts = cvss_string.split("/")
                # Look for base score indicators
                for part in parts:
                    if part.startswith("C:H") or part.startswith("I:H") or part.startswith("A:H"):
                        return "HIGH"
                    if part.startswith("C:N") and part.startswith("I:N") and part.startswith("A:N"):
                        return "LOW"
            return "MEDIUM"
        except Exception:
            return "UNKNOWN"

    # ──────────────────────────────────────────────
    # NVD DATABASE
    # ──────────────────────────────────────────────

    def _check_nvd(self, package_name):
        """Query NIST National Vulnerability Database"""
        try:
            url = NVD_API_URL
            params = {
                "keywordSearch": package_name,
                "resultsPerPage": 10
            }

            response = self.session.get(
                url,
                params=params,
                timeout=SCAN_TIMEOUT_SECONDS
            )

            if response.status_code != 200:
                return {"error": f"NVD returned status {response.status_code}"}

            data = response.json()
            vulns = []

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")

                # Extract description
                descriptions = cve.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                # Extract CVSS severity
                severity = "UNKNOWN"
                cvss_score = 0.0
                metrics = cve.get("metrics", {})

                # Try CVSS v3.1 first
                cvss_v31 = metrics.get("cvssMetricV31", [])
                if cvss_v31:
                    cvss_data = cvss_v31[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0)
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")

                # Fallback to CVSS v3.0
                if severity == "UNKNOWN":
                    cvss_v30 = metrics.get("cvssMetricV30", [])
                    if cvss_v30:
                        cvss_data = cvss_v30[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0)
                        severity = cvss_data.get("baseSeverity", "UNKNOWN")

                # Fallback to CVSS v2
                if severity == "UNKNOWN":
                    cvss_v2 = metrics.get("cvssMetricV2", [])
                    if cvss_v2:
                        cvss_data = cvss_v2[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0)
                        if cvss_score >= 9.0:
                            severity = "CRITICAL"
                        elif cvss_score >= 7.0:
                            severity = "HIGH"
                        elif cvss_score >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"

                vuln = {
                    "id": cve_id,
                    "summary": description[:300] if description else "No description",
                    "details": description,
                    "severity": severity.upper(),
                    "cvss_score": cvss_score,
                    "source": "NVD",
                    "references": [
                        ref.get("url")
                        for ref in cve.get("references", [])
                        if ref.get("url")
                    ][:5],
                    "published": cve.get("published", ""),
                    "modified": cve.get("lastModified", "")
                }
                vulns.append(vuln)

            return {"vulnerabilities": vulns}

        except requests.exceptions.Timeout:
            return {"error": "NVD request timed out"}
        except requests.exceptions.RequestException as e:
            return {"error": f"NVD network error: {str(e)}"}
        except Exception as e:
            return {"error": f"NVD unexpected error: {str(e)}"}

    # ──────────────────────────────────────────────
    # RISK SCORING
    # ──────────────────────────────────────────────

    def _calculate_vuln_risk_score(self, results):
        """Calculate vulnerability risk score from findings"""
        score = 0
        score += results["critical_count"] * 40
        score += results["high_count"] * 30
        score += results["medium_count"] * 15
        score += results["low_count"] * 5
        return min(score, 100)