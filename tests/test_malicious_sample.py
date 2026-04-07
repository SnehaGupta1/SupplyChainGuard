"""
Test script to verify static analyzer detects malicious patterns.
Run: python tests/test_malicious_sample.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.static_analyzer import StaticCodeAnalyzer
from core.behavioral_profiler import BehavioralProfiler


def test_malicious_sample():
    analyzer = StaticCodeAnalyzer()
    profiler = BehavioralProfiler()

    # Read malicious sample
    sample_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "test_scenarios", "malicious_sample", "malicious.py"
    )

    # Fallback: try setup.py if malicious.py doesn't exist
    if not os.path.exists(sample_path):
        sample_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "test_scenarios", "malicious_sample", "setup.py"
        )

    if not os.path.exists(sample_path):
        print(f"ERROR: Sample file not found at {sample_path}")
        return

    with open(sample_path, "r") as f:
        code = f.read()

    print("=" * 60)
    print("MALICIOUS SAMPLE ANALYSIS")
    print("=" * 60)
    print(f"File: {sample_path}")
    print(f"Code length: {len(code)} characters")
    print()

    # Static Analysis
    print("--- STATIC CODE ANALYSIS ---")
    result = analyzer.scan(code, "malicious.py", "python")

    print(f"Risk Score: {result.get('risk_score', 0)}")
    print(f"Issues Found: {len(result.get('issues', []))}")
    print(f"Entropy Score: {result.get('entropy_score', 0):.4f}")
    print(f"Encoded Payloads: {len(result.get('encoded_payloads', []))}")
    print(f"Suspicious URLs: {len(result.get('suspicious_urls', []))}")
    print(f"IP Addresses: {len(result.get('ip_addresses', []))}")
    print()

    if result.get("issues"):
        print("Issues Detected:")
        for i, issue in enumerate(result["issues"], 1):
            severity = issue.get("severity", "unknown")
            desc = issue.get("description", "No description")
            score = issue.get("score", 0)
            print(f"  {i}. [{severity.upper()}] {desc} (score: {score})")
    else:
        print("  No issues found (this may indicate a problem)")

    print()

    # Behavioral Analysis
    print("--- BEHAVIORAL PROFILING ---")
    behavioral = profiler.profile(code, "python")

    print(f"Behavioral Risk Score: {behavioral.get('risk_score', 0)}")

    fingerprint = behavioral.get("fingerprint", {})
    if fingerprint:
        print("Behavioral Fingerprint:")
        for category, count in fingerprint.items():
            if count > 0:
                bar = "█" * count + "░" * (5 - min(count, 5))
                print(f"  {category:25s} [{bar}] {count}")

    print()
    print("=" * 60)

    # Verify expectations
    print("VERIFICATION:")
    risk_score = result.get("risk_score", 0)
    issue_count = len(result.get("issues", []))

    checks = [
        ("Risk score > 0", risk_score > 0),
        ("At least 3 issues detected", issue_count >= 3),
        ("os.environ detected", any(
            "environ" in str(i.get("description", "")).lower()
            for i in result.get("issues", [])
        )),
        ("base64 detected", any(
            "base64" in str(i.get("description", "")).lower()
            for i in result.get("issues", [])
        )),
        ("subprocess detected", any(
            "subprocess" in str(i.get("description", "")).lower()
            for i in result.get("issues", [])
        )),
        ("socket detected", any(
            "socket" in str(i.get("description", "")).lower()
            for i in result.get("issues", [])
        )),
    ]

    all_pass = True
    for check_name, passed in checks:
        status = "PASS" if passed else "FAIL"
        icon = "✓" if passed else "✗"
        print(f"  {icon} {check_name}: {status}")
        if not passed:
            all_pass = False

    print()
    if all_pass:
        print("ALL CHECKS PASSED - Malicious sample correctly detected!")
    else:
        print("SOME CHECKS FAILED - Review static analyzer implementation")

    print("=" * 60)


if __name__ == "__main__":
    test_malicious_sample()