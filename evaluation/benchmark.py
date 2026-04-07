"""
Evaluation Benchmark Script
Tests the system against known packages and generates performance metrics.
Run this to generate data for your research paper.
"""

import time
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.metadata_analyzer import MetadataAnalyzer
from core.typosquat_detector import TyposquatDetector
from core.vuln_engine import VulnerabilityEngine
from core.risk_scorer import RiskScorer


def benchmark():
    """Run benchmark against known packages"""

    # Test packages — mix of safe and known-risky
    test_packages = {
        "npm": {
            "safe": [
                "express", "lodash", "axios", "react", "chalk",
                "commander", "debug", "dotenv", "cors", "uuid"
            ],
            "typosquat_tests": [
                ("expres", True),       # 1 char off from express
                ("expresss", True),     # extra char
                ("l0dash", True),       # homoglyph
                ("axois", True),        # transposed
                ("my-real-package", False),  # not similar
            ]
        },
        "pypi": {
            "safe": [
                "requests", "flask", "numpy", "pandas", "click",
                "jinja2", "pyyaml", "pytest", "boto3", "pillow"
            ],
            "typosquat_tests": [
                ("requets", True),      # missing char
                ("requsets", True),     # transposed
                ("fl4sk", True),        # homoglyph
                ("numpyy", True),       # extra char
                ("my-unique-lib", False),
            ]
        }
    }

    results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "metadata_performance": [],
        "typosquat_performance": {
            "total_tests": 0,
            "correct": 0,
            "accuracy": 0,
            "details": []
        },
        "scan_times": [],
        "risk_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    }

    metadata_analyzer = MetadataAnalyzer()
    typosquat_detector = TyposquatDetector()
    vuln_engine = VulnerabilityEngine()
    risk_scorer = RiskScorer()

    print("=" * 60)
    print("  SupplyChainGuard - Evaluation Benchmark")
    print("=" * 60)

    # ── TEST 1: Metadata + Full Scan Performance ──
    print("\n[1/3] Testing scan performance on known packages...")

    for ecosystem, data in test_packages.items():
        for pkg_name in data["safe"]:
            start = time.time()

            try:
                meta = metadata_analyzer.analyze(pkg_name, ecosystem)
                version = meta.get("metadata", {}).get("latest_version")
                typo = typosquat_detector.check(pkg_name, ecosystem)
                vulns = vuln_engine.check(pkg_name, version, ecosystem)
                risk = risk_scorer.calculate(
                    metadata_result=meta,
                    vuln_result=vulns,
                    typosquat_result=typo
                )

                elapsed = time.time() - start
                risk_level = risk["risk_level"]
                risk_score = risk["final_score"]

                results["scan_times"].append(elapsed)
                results["risk_distribution"][risk_level] += 1
                results["metadata_performance"].append({
                    "package": pkg_name,
                    "ecosystem": ecosystem,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "scan_time": round(elapsed, 3),
                    "vulnerabilities": vulns.get("total_count", 0),
                    "status": "success"
                })

                status_icon = "✓" if risk_level == "LOW" else "⚠"
                print(f"  {status_icon} {pkg_name:20s} ({ecosystem}) "
                      f"→ {risk_level:8s} (score: {risk_score:5.1f}) "
                      f"[{elapsed:.2f}s]")

            except Exception as e:
                elapsed = time.time() - start
                results["metadata_performance"].append({
                    "package": pkg_name,
                    "ecosystem": ecosystem,
                    "status": "error",
                    "error": str(e),
                    "scan_time": round(elapsed, 3)
                })
                print(f"  ✗ {pkg_name:20s} ({ecosystem}) → ERROR: {e}")

    # ── TEST 2: Typosquatting Detection Accuracy ──
    print("\n[2/3] Testing typosquatting detection accuracy...")

    for ecosystem, data in test_packages.items():
        for test_name, expected_suspect in data["typosquat_tests"]:
            result = typosquat_detector.check(test_name, ecosystem)
            actual_suspect = result["is_typosquat_suspect"]
            is_correct = actual_suspect == expected_suspect

            results["typosquat_performance"]["total_tests"] += 1
            if is_correct:
                results["typosquat_performance"]["correct"] += 1

            results["typosquat_performance"]["details"].append({
                "input": test_name,
                "ecosystem": ecosystem,
                "expected": expected_suspect,
                "actual": actual_suspect,
                "correct": is_correct,
                "closest_match": result.get("closest_legitimate"),
                "techniques": result.get("techniques_triggered", [])
            })

            icon = "✓" if is_correct else "✗"
            expected_str = "SUSPECT" if expected_suspect else "CLEAN"
            actual_str = "SUSPECT" if actual_suspect else "CLEAN"
            print(f"  {icon} {test_name:20s} → "
                  f"Expected: {expected_str:8s} | "
                  f"Got: {actual_str:8s}")

    total_typo = results["typosquat_performance"]["total_tests"]
    correct_typo = results["typosquat_performance"]["correct"]
    if total_typo > 0:
        accuracy = correct_typo / total_typo * 100
        results["typosquat_performance"]["accuracy"] = round(accuracy, 2)

    # ── TEST 3: Performance Metrics ──
    print("\n[3/3] Computing performance metrics...")

    scan_times = results["scan_times"]
    if scan_times:
        avg_time = sum(scan_times) / len(scan_times)
        min_time = min(scan_times)
        max_time = max(scan_times)

        performance = {
            "total_scans": len(scan_times),
            "avg_scan_time": round(avg_time, 3),
            "min_scan_time": round(min_time, 3),
            "max_scan_time": round(max_time, 3),
            "total_time": round(sum(scan_times), 3)
        }
        results["performance_metrics"] = performance

        print(f"\n  Total scans:     {performance['total_scans']}")
        print(f"  Average time:    {performance['avg_scan_time']}s")
        print(f"  Fastest scan:    {performance['min_scan_time']}s")
        print(f"  Slowest scan:    {performance['max_scan_time']}s")

    # ── SUMMARY ──
    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    print(f"\n  Risk Distribution:")
    for level, count in results["risk_distribution"].items():
        bar = "█" * count + "░" * (10 - count)
        print(f"    {level:10s} [{bar}] {count}")

    print(f"\n  Typosquatting Detection:")
    print(f"    Accuracy: {results['typosquat_performance']['accuracy']}%")
    print(f"    Correct: {correct_typo}/{total_typo}")

    # Safe packages should be LOW risk
    safe_results = [
        r for r in results["metadata_performance"]
        if r.get("status") == "success"
    ]
    low_risk_safe = sum(
        1 for r in safe_results if r["risk_level"] == "LOW"
    )
    false_positive_rate = 0
    if safe_results:
        false_positive_rate = round(
            (1 - low_risk_safe / len(safe_results)) * 100, 2
        )

    print(f"\n  False Positive Rate (safe packages flagged): "
          f"{false_positive_rate}%")

    # Save results
    os.makedirs("evaluation", exist_ok=True)
    output_path = os.path.join(
        "evaluation",
        f"benchmark_results_{time.strftime('%Y%m%d_%H%M%S')}.json"
    )
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n  Results saved to: {output_path}")
    print("=" * 60)

    return results


if __name__ == "__main__":
    benchmark()