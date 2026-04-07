"""
Core detection modules for Supply Chain Guard
"""

from core.metadata_analyzer import MetadataAnalyzer
from core.typosquat_detector import TyposquatDetector
from core.vuln_engine import VulnerabilityEngine
from core.static_analyzer import StaticCodeAnalyzer
from core.behavioral_profiler import BehavioralProfiler
from core.dependency_graph import DependencyGraphAnalyzer
from core.risk_scorer import RiskScorer
from core.sbom_generator import SBOMGenerator
from core.report_generator import ReportGenerator

__all__ = [
    "MetadataAnalyzer",
    "TyposquatDetector",
    "VulnerabilityEngine",
    "StaticCodeAnalyzer",
    "BehavioralProfiler",
    "DependencyGraphAnalyzer",
    "RiskScorer",
    "SBOMGenerator",
    "ReportGenerator"
]