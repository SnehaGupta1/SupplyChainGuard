"""
Tests for Typosquatting Detection Module
"""

import pytest
from core.typosquat_detector import TyposquatDetector


class TestTyposquatDetector:
    """Test suite for TyposquatDetector"""

    def setup_method(self):
        self.detector = TyposquatDetector()

    # ── EXACT MATCH (NOT TYPOSQUAT) ──

    def test_exact_popular_package_npm(self):
        """Known popular package should NOT be flagged"""
        result = self.detector.check("express", "npm")
        assert result["is_typosquat_suspect"] is False

    def test_exact_popular_package_pypi(self):
        """Known popular package should NOT be flagged"""
        result = self.detector.check("requests", "pypi")
        assert result["is_typosquat_suspect"] is False

    # ── LEVENSHTEIN DETECTION ──

    def test_levenshtein_one_char_off(self):
        """One character off from popular package should be detected"""
        result = self.detector.check("expres", "npm")
        assert result["is_typosquat_suspect"] is True
        assert "levenshtein" in result["techniques_triggered"]

    def test_levenshtein_two_chars_off(self):
        """Two characters off should be detected"""
        result = self.detector.check("requets", "pypi")
        assert result["is_typosquat_suspect"] is True

    # ── SEPARATOR SWAP ──

    def test_separator_swap_dash_to_underscore(self):
        """Separator swapping should be detected"""
        result = self.detector.check("babel_core", "npm")
        assert result["is_typosquat_suspect"] is True
        assert "separator_swap" in result["techniques_triggered"]

    def test_separator_swap_removed(self):
        """Removed separator should be detected"""
        result = self.detector.check("babelcore", "npm")
        assert result["is_typosquat_suspect"] is True

    # ── REPEATED CHARACTER ──

    def test_repeated_character(self):
        """Added character should be detected"""
        result = self.detector.check("expresss", "npm")
        assert result["is_typosquat_suspect"] is True
        assert "repeated_char" in result["techniques_triggered"]

    def test_missing_character(self):
        """Missing character should be detected"""
        result = self.detector.check("reques", "pypi")
        assert result["is_typosquat_suspect"] is True

    # ── HOMOGLYPH ──

    def test_homoglyph_zero_for_o(self):
        """Homoglyph substitution should be detected"""
        result = self.detector.check("l0dash", "npm")
        assert result["is_typosquat_suspect"] is True
        assert "homoglyph" in result["techniques_triggered"]

    # ── PREFIX/SUFFIX ──

    def test_suffix_addition(self):
        """Common suffix addition should be detected"""
        result = self.detector.check("express-js", "npm")
        assert result["is_typosquat_suspect"] is True
        assert "prefix_suffix" in result["techniques_triggered"]

    # ── COMPLETELY DIFFERENT NAME ──

    def test_completely_different_name(self):
        """Completely different name should NOT be flagged"""
        result = self.detector.check("my-unique-package-name-xyz", "npm")
        assert result["is_typosquat_suspect"] is False

    # ── RISK SCORE ──

    def test_risk_score_present(self):
        """Suspected typosquat should have risk score"""
        result = self.detector.check("expres", "npm")
        if result["is_typosquat_suspect"]:
            assert result["risk_score"] > 0

    def test_safe_package_zero_risk(self):
        """Non-suspect should have zero risk"""
        result = self.detector.check("express", "npm")
        assert result["risk_score"] == 0