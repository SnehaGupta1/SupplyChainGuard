"""
Tests for Metadata Analyzer Module
"""

import pytest
from core.metadata_analyzer import MetadataAnalyzer


class TestMetadataAnalyzer:
    """Test suite for MetadataAnalyzer"""

    def setup_method(self):
        self.analyzer = MetadataAnalyzer()

    # ── NPM TESTS ──

    def test_npm_valid_package(self):
        """Test scanning a known valid npm package"""
        result = self.analyzer.analyze("express", "npm")
        assert "error" not in result
        assert result["package_name"] == "express"
        assert result["ecosystem"] == "npm"
        assert result["metadata"]["name"] == "express"
        assert result["risk_score"] >= 0

    def test_npm_invalid_package(self):
        """Test scanning a non-existent npm package"""
        result = self.analyzer.analyze(
            "this-package-definitely-does-not-exist-xyz123", "npm"
        )
        assert "error" in result

    def test_npm_metadata_fields(self):
        """Test that all expected metadata fields are extracted"""
        result = self.analyzer.analyze("lodash", "npm")
        metadata = result.get("metadata", {})

        expected_fields = [
            "name", "latest_version", "description", "author",
            "maintainers", "maintainer_count", "license",
            "publish_time", "version_count", "dependencies",
            "scripts"
        ]

        for field in expected_fields:
            assert field in metadata, f"Missing field: {field}"

    def test_npm_checks_executed(self):
        """Test that all metadata checks are executed"""
        result = self.analyzer.analyze("express", "npm")
        checks = result.get("checks", [])

        check_names = [c["name"] for c in checks]
        expected_checks = [
            "author_check",
            "package_age_check",
            "install_scripts_check",
            "script_contents_check",
            "dependency_count_check",
            "repository_check",
            "readme_check",
            "version_history_check",
            "maintainer_count_check",
            "license_check",
            "version_anomaly_check"
        ]

        for check in expected_checks:
            assert check in check_names, f"Missing check: {check}"

    # ── PYPI TESTS ──

    def test_pypi_valid_package(self):
        """Test scanning a known valid PyPI package"""
        result = self.analyzer.analyze("requests", "pypi")
        assert "error" not in result
        assert result["package_name"] == "requests"
        assert result["ecosystem"] == "pypi"

    def test_pypi_invalid_package(self):
        """Test scanning a non-existent PyPI package"""
        result = self.analyzer.analyze(
            "this-package-definitely-does-not-exist-xyz123", "pypi"
        )
        assert "error" in result

    # ── RISK SCORING ──

    def test_risk_score_bounded(self):
        """Test that risk score is between 0 and 100"""
        result = self.analyzer.analyze("express", "npm")
        assert 0 <= result["risk_score"] <= 100

    def test_well_known_package_low_risk(self):
        """Well-known packages should generally have lower risk scores"""
        result = self.analyzer.analyze("express", "npm")
        # express is well-established, shouldn't be HIGH risk
        assert result["risk_score"] < 70

    # ── ECOSYSTEM VALIDATION ──

    def test_unsupported_ecosystem(self):
        """Test unsupported ecosystem handling"""
        result = self.analyzer.analyze("test", "rubygems")
        assert "error" in result


class TestMetadataChecks:
    """Test individual metadata check logic"""

    def setup_method(self):
        self.analyzer = MetadataAnalyzer()

    def test_no_author_flagged(self):
        """Packages without author should be flagged"""
        metadata = {"author": None}
        check = self.analyzer._check_author(metadata)
        assert check["flagged"] is True
        assert check["score"] > 0

    def test_with_author_not_flagged(self):
        """Packages with author should not be flagged"""
        metadata = {"author": "John Doe"}
        check = self.analyzer._check_author(metadata)
        assert check["flagged"] is False
        assert check["score"] == 0

    def test_no_repository_flagged(self):
        """Packages without repository should be flagged"""
        metadata = {"repository": None}
        check = self.analyzer._check_repository(metadata)
        assert check["flagged"] is True

    def test_high_dependency_count_flagged(self):
        """Packages with many dependencies should be flagged"""
        metadata = {"dependencies": {f"dep-{i}": "1.0" for i in range(25)}}
        check = self.analyzer._check_dependency_count(metadata)
        assert check["flagged"] is True

    def test_install_scripts_flagged(self):
        """Packages with install scripts should be flagged"""
        metadata = {"scripts": {"postinstall": "node setup.js"}}
        check = self.analyzer._check_install_scripts(metadata)
        assert check["flagged"] is True
        assert check["score"] > 0

    def test_no_scripts_not_flagged(self):
        """Packages without scripts should not be flagged"""
        metadata = {"scripts": {}}
        check = self.analyzer._check_install_scripts(metadata)
        assert check["flagged"] is False