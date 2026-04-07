"""
Feature Extractor for ML Model
Extracts numerical feature vectors from package analysis results.
"""

import numpy as np


class FeatureExtractor:
    """
    Extracts features from scan results for ML model input.
    """

    FEATURE_NAMES = [
        "metadata_risk_score",
        "vuln_total_count",
        "vuln_critical_count",
        "vuln_high_count",
        "code_risk_score",
        "code_issue_count",
        "obfuscation_detected",
        "encoded_payloads_count",
        "suspicious_urls_count",
        "entropy_score",
        "behavioral_risk_score",
        "network_behaviors",
        "process_exec_behaviors",
        "code_exec_behaviors",
        "encoding_behaviors",
        "env_access_behaviors",
        "typosquat_suspect",
        "typosquat_distance",
        "dependency_count",
        "version_count",
        "has_author",
        "has_repository",
        "has_license",
        "has_install_scripts",
        "package_age_days",
        "maintainer_count"
    ]

    def extract(self, scan_result):
        """
        Extract feature vector from a complete scan result.
        Returns numpy array.
        """
        features = []

        metadata = scan_result.get("metadata", {})
        vulns = scan_result.get("vulnerabilities", {})
        code = scan_result.get("code_analysis", {})
        behavioral = scan_result.get("behavioral", {})
        typo = scan_result.get("typosquatting", {})
        pkg_info = metadata.get("package_info", {})
        fingerprint = behavioral.get("fingerprint", {})

        features.append(metadata.get("risk_score", 0))
        features.append(vulns.get("total", 0))
        features.append(vulns.get("critical", 0))
        features.append(vulns.get("high", 0))
        features.append(code.get("risk_score", 0))
        features.append(code.get("total_issues", 0))
        features.append(1 if code.get("obfuscation_detected") else 0)
        features.append(len(code.get("encoded_payloads", [])))
        features.append(len(code.get("suspicious_urls", [])))
        features.append(code.get("entropy_score", 0))
        features.append(behavioral.get("risk_score", 0))
        features.append(fingerprint.get("network", 0))
        features.append(fingerprint.get("process_execution", 0))
        features.append(fingerprint.get("code_execution", 0))
        features.append(fingerprint.get("data_encoding", 0))
        features.append(fingerprint.get("environment_access", 0))
        features.append(1 if typo.get("is_suspect") else 0)
        features.append(typo.get("risk_score", 0))
        features.append(pkg_info.get("dependency_count", 0))
        features.append(pkg_info.get("version_count", 0))
        features.append(1 if pkg_info.get("author") else 0)
        features.append(1 if pkg_info.get("has_repository") else 0)
        features.append(1 if pkg_info.get("license") else 0)
        features.append(0)  # install scripts placeholder
        features.append(0)  # package age placeholder
        features.append(pkg_info.get("maintainer_count", 0) if isinstance(
            pkg_info.get("maintainer_count"), (int, float)
        ) else 0)

        return np.array(features, dtype=np.float64)

    def extract_batch(self, scan_results):
        """Extract features from multiple scan results"""
        return np.array([self.extract(r) for r in scan_results])

    def get_feature_names(self):
        """Return feature names for model interpretability"""
        return self.FEATURE_NAMES