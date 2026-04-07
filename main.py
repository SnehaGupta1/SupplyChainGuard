"""
SupplyChainGuard - CLI Scanner
Command-line interface for scanning packages.
"""

import sys
import json
import argparse
from datetime import datetime

from core.metadata_analyzer import MetadataAnalyzer
from core.typosquat_detector import TyposquatDetector
from core.vuln_engine import VulnerabilityEngine
from core.static_analyzer import StaticCodeAnalyzer
from core.behavioral_profiler import BehavioralProfiler
from core.dependency_graph import DependencyGraphAnalyzer
from core.risk_scorer import RiskScorer
from core.sbom_generator import SBOMGenerator
from core.report_generator import ReportGenerator


# ──────────────────────────────────────────────
# COLORS FOR TERMINAL
# ──────────────────────────────────────────────

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_banner():
    print(f"""{Colors.CYAN}
╔══════════════════════════════════════════════════╗
║                                                  ║
║        SupplyChainGuard v1.0                     ║
║        Real-Time Supply Chain Scanner            ║
║                                                  ║
╚══════════════════════════════════════════════════╝
{Colors.RESET}""")


def print_section(title):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'─' * 50}")
    print(f"  {title}")
    print(f"{'─' * 50}{Colors.RESET}")


def print_risk_level(level, score):
    color_map = {
        "CRITICAL": Colors.RED,
        "HIGH": Colors.RED,
        "MEDIUM": Colors.YELLOW,
        "LOW": Colors.GREEN
    }
    color = color_map.get(level, Colors.WHITE)
    print(f"\n{Colors.BOLD}  RISK SCORE: {color}{score}/100{Colors.RESET}")
    print(f"{Colors.BOLD}  RISK LEVEL: {color}{level}{Colors.RESET}")


def print_finding(icon, text, color=Colors.WHITE):
    print(f"  {color}{icon} {text}{Colors.RESET}")


def run_scan(package_name, ecosystem="npm", scan_deps=True,
             max_depth=2, verbose=False):
    """Run the full scan pipeline via CLI"""

    print_banner()
    print(f"  {Colors.WHITE}Scanning: {Colors.BOLD}{package_name}"
          f"{Colors.RESET}")
    print(f"  {Colors.WHITE}Ecosystem: {ecosystem}{Colors.RESET}")
    print(f"  {Colors.WHITE}Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
          f"{Colors.RESET}")

    # ── STEP 1: Metadata ──
    print_section("METADATA ANALYSIS")
    print(f"  {Colors.CYAN}Fetching package metadata...{Colors.RESET}")

    metadata_analyzer = MetadataAnalyzer()
    metadata_result = metadata_analyzer.analyze(package_name, ecosystem)

    if "error" in metadata_result:
        print(f"  {Colors.RED}✗ Error: {metadata_result['error']}{Colors.RESET}")
        return

    metadata = metadata_result.get("metadata", {})
    print(f"  {Colors.GREEN}✓ Package: {metadata.get('name')}{Colors.RESET}")
    print(f"  {Colors.GREEN}✓ Version: {metadata.get('latest_version')}"
          f"{Colors.RESET}")
    print(f"  {Colors.GREEN}✓ Author: {metadata.get('author', 'N/A')}"
          f"{Colors.RESET}")

    # Print metadata findings
    for factor in metadata_result.get("risk_factors", []):
        severity = factor.get("severity", "medium")
        if severity in ["critical", "high"]:
            print_finding("⚠", factor["description"], Colors.RED)
        elif severity == "medium":
            print_finding("⚠", factor["description"], Colors.YELLOW)
        else:
            print_finding("ℹ", factor["description"], Colors.WHITE)

    if not metadata_result.get("risk_factors"):
        print_finding("✓", "No metadata anomalies detected", Colors.GREEN)

    version = metadata.get("latest_version")

    # ── STEP 2: Typosquatting ──
    print_section("TYPOSQUATTING DETECTION")
    print(f"  {Colors.CYAN}Checking name similarity...{Colors.RESET}")

    typosquat_detector = TyposquatDetector()
    typosquat_result = typosquat_detector.check(package_name, ecosystem)

    if typosquat_result.get("is_typosquat_suspect"):
        print_finding(
            "⚠ ALERT",
            f"Package name is similar to "
            f"'{typosquat_result['closest_legitimate']}'!",
            Colors.RED
        )
        for technique in typosquat_result.get("techniques_triggered", []):
            print_finding("  →", f"Detection technique: {technique}",
                          Colors.YELLOW)
    else:
        print_finding("✓", "No typosquatting detected", Colors.GREEN)

    # ── STEP 3: Vulnerabilities ──
    print_section("VULNERABILITY INTELLIGENCE")
    print(f"  {Colors.CYAN}Querying vulnerability databases...{Colors.RESET}")

    vuln_engine = VulnerabilityEngine()
    vuln_result = vuln_engine.check(package_name, version, ecosystem)

    sources = vuln_result.get("sources_checked", [])
    print(f"  {Colors.WHITE}Sources checked: {', '.join(sources)}"
          f"{Colors.RESET}")

    total_vulns = vuln_result.get("total_count", 0)
    if total_vulns > 0:
        print_finding("⚠", f"Found {total_vulns} vulnerability(ies):",
                       Colors.RED)
        if vuln_result.get("critical_count"):
            print_finding(
                "  🔴",
                f"Critical: {vuln_result['critical_count']}",
                Colors.RED
            )
        if vuln_result.get("high_count"):
            print_finding(
                "  🟠",
                f"High: {vuln_result['high_count']}",
                Colors.RED
            )
        if vuln_result.get("medium_count"):
            print_finding(
                "  🟡",
                f"Medium: {vuln_result['medium_count']}",
                Colors.YELLOW
            )
        if vuln_result.get("low_count"):
            print_finding(
                "  🟢",
                f"Low: {vuln_result['low_count']}",
                Colors.WHITE
            )

        if verbose:
            for vuln in vuln_result.get("vulnerabilities", [])[:5]:
                print(f"    {Colors.WHITE}• {vuln['id']}: "
                      f"{vuln['summary'][:80]}...{Colors.RESET}")
    else:
        print_finding("✓", "No known vulnerabilities found", Colors.GREEN)

    for err in vuln_result.get("errors", []):
        print_finding("ℹ", f"Warning: {err['source']} - {err['error']}",
                       Colors.YELLOW)

    # ── STEP 4: Static Analysis ──
    print_section("STATIC CODE ANALYSIS")

    code_result = {"risk_score": 0, "issues": [], "summary": {}}
    scripts = metadata.get("scripts", {})

    if scripts:
        print(f"  {Colors.CYAN}Analyzing install scripts...{Colors.RESET}")
        combined_code = "\n".join(
            str(v) for v in scripts.values() if isinstance(v, str)
        )
        if combined_code.strip():
            static_analyzer = StaticCodeAnalyzer()
            language = "javascript" if ecosystem == "npm" else "python"
            code_result = static_analyzer.scan(
                combined_code,
                f"{package_name}/scripts",
                language
            )

            for issue in code_result.get("issues", []):
                severity = issue.get("severity", "medium")
                if severity in ["critical", "high"]:
                    print_finding("⚠", issue["description"], Colors.RED)
                else:
                    print_finding("⚠", issue["description"], Colors.YELLOW)

            if not code_result.get("issues"):
                print_finding("✓", "No suspicious code patterns",
                               Colors.GREEN)
        else:
            print_finding("ℹ", "No analyzable script content", Colors.WHITE)
    else:
        print_finding("ℹ", "No install scripts to analyze", Colors.WHITE)

    # ── STEP 5: Behavioral Profiling ──
    print_section("BEHAVIORAL ANALYSIS")

    behavioral_result = {"risk_score": 0, "behavior_summary": []}
    if scripts:
        combined_code = "\n".join(
            str(v) for v in scripts.values() if isinstance(v, str)
        )
        if combined_code.strip():
            profiler = BehavioralProfiler()
            language = "python" if ecosystem == "pypi" else "javascript"
            behavioral_result = profiler.profile(combined_code, language)

            for behavior in behavioral_result.get("behavior_summary", []):
                print_finding(
                    "→",
                    f"{behavior['description']}: "
                    f"{behavior['count']} detection(s) "
                    f"(score: {behavior['weighted_score']})",
                    Colors.YELLOW if behavior["weighted_score"] > 5
                    else Colors.WHITE
                )

            if not behavioral_result.get("behavior_summary"):
                print_finding("✓", "No concerning behaviors detected",
                               Colors.GREEN)
    else:
        print_finding("ℹ", "No code available for behavioral analysis",
                       Colors.WHITE)

    # ── STEP 6: Dependency Graph ──
    graph_result = {"risk_score": 0, "total_dependencies": 0}
    if scan_deps:
        print_section("DEPENDENCY GRAPH ANALYSIS")
        print(f"  {Colors.CYAN}Building dependency tree "
              f"(depth: {max_depth})...{Colors.RESET}")

        try:
            graph_analyzer = DependencyGraphAnalyzer()
            graph_result = graph_analyzer.analyze(
                package_name, ecosystem, max_depth
            )

            print(f"  {Colors.WHITE}Total dependencies: "
                  f"{graph_result.get('total_dependencies', 0)}{Colors.RESET}")

            critical_nodes = graph_result.get("critical_nodes", [])
            if critical_nodes:
                print_finding(
                    "⚠",
                    f"{len(critical_nodes)} critical node(s) "
                    f"in dependency tree",
                    Colors.YELLOW
                )

            for factor in graph_result.get("risk_factors", []):
                print_finding("⚠", factor, Colors.YELLOW)

            if not graph_result.get("risk_factors"):
                print_finding("✓", "Dependency graph looks healthy",
                               Colors.GREEN)

        except Exception as e:
            print_finding("ℹ", f"Graph analysis error: {e}", Colors.YELLOW)

    # ── STEP 7: Risk Scoring ──
    print_section("FINAL RISK ASSESSMENT")

    risk_scorer = RiskScorer()
    risk_result = risk_scorer.calculate(
        metadata_result=metadata_result,
        vuln_result=vuln_result,
        code_result=code_result,
        behavioral_result=behavioral_result,
        typosquat_result=typosquat_result,
        graph_result=graph_result
    )

    print_risk_level(risk_result["risk_level"], risk_result["final_score"])
    print(f"\n  {Colors.WHITE}Action: "
          f"{risk_result['recommended_action']}{Colors.RESET}")

    # Category breakdown
    print(f"\n  {Colors.BOLD}Category Breakdown:{Colors.RESET}")
    for category, scores in risk_result["category_breakdown"].items():
        bar_length = int(scores["normalized"] / 5)
        bar = "█" * bar_length + "░" * (20 - bar_length)
        print(f"    {category:<20} [{bar}] "
              f"{scores['normalized']:.0f}/100 "
              f"(weighted: {scores['weighted_score']:.1f})")

    # ── STEP 8: Generate Report ──
    print_section("REPORT GENERATION")

    report_generator = ReportGenerator()
    report = report_generator.generate(
        package_name=package_name,
        ecosystem=ecosystem,
        metadata_result=metadata_result,
        typosquat_result=typosquat_result,
        vuln_result=vuln_result,
        code_result=code_result,
        behavioral_result=behavioral_result,
        graph_result=graph_result,
        risk_result=risk_result
    )

    report_path = report_generator.save_report(report)
    print(f"  {Colors.GREEN}✓ Report saved: {report_path}{Colors.RESET}")

    # SBOM
    sbom_gen = SBOMGenerator(package_name, version or "unknown")
    sbom_gen.add_component(
        name=package_name,
        version=version or "unknown",
        ecosystem=ecosystem,
        risk_score=risk_result["final_score"],
        risk_level=risk_result["risk_level"],
        vulnerabilities=vuln_result.get("vulnerabilities", [])
    )
    sbom_path = sbom_gen.export_json()
    print(f"  {Colors.GREEN}✓ SBOM saved: {sbom_path}{Colors.RESET}")

    # Recommendations
    print_section("RECOMMENDATIONS")
    for rec in report.get("recommendations", []):
        color = Colors.RED if rec["priority"] in ["CRITICAL", "HIGH"] \
            else Colors.YELLOW if rec["priority"] == "MEDIUM" \
            else Colors.GREEN
        print_finding(f"[{rec['priority']}]", rec["action"], color)

    print(f"\n{Colors.CYAN}{'═' * 50}{Colors.RESET}\n")

    return risk_result


def main():
    parser = argparse.ArgumentParser(
        description="SupplyChainGuard - Real-Time Supply Chain Scanner"
    )
    parser.add_argument(
        "package",
        help="Package name to scan"
    )
    parser.add_argument(
        "-e", "--ecosystem",
        choices=["npm", "pypi"],
        default="npm",
        help="Package ecosystem (default: npm)"
    )
    parser.add_argument(
        "--no-deps",
        action="store_true",
        help="Skip dependency graph analysis"
    )
    parser.add_argument(
        "-d", "--depth",
        type=int,
        default=2,
        help="Maximum dependency scanning depth (default: 2)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    args = parser.parse_args()

    if args.json:
        # JSON mode - minimal output
        metadata_analyzer = MetadataAnalyzer()
        typosquat_detector = TyposquatDetector()
        vuln_engine = VulnerabilityEngine()
        risk_scorer = RiskScorer()

        metadata_result = metadata_analyzer.analyze(
            args.package, args.ecosystem
        )

        if "error" in metadata_result:
            print(json.dumps({"error": metadata_result["error"]}))
            sys.exit(1)

        version = metadata_result.get("metadata", {}).get("latest_version")
        typosquat_result = typosquat_detector.check(
            args.package, args.ecosystem
        )
        vuln_result = vuln_engine.check(
            args.package, version, args.ecosystem
        )

        risk_result = risk_scorer.calculate(
            metadata_result=metadata_result,
            vuln_result=vuln_result,
            typosquat_result=typosquat_result
        )

        output = {
            "package": args.package,
            "ecosystem": args.ecosystem,
            "version": version,
            "risk_score": risk_result["final_score"],
            "risk_level": risk_result["risk_level"],
            "vulnerabilities": vuln_result.get("total_count", 0),
            "typosquat_suspect": typosquat_result.get(
                "is_typosquat_suspect", False
            ),
            "metadata_issues": len(
                metadata_result.get("risk_factors", [])
            )
        }

        print(json.dumps(output, indent=2))
    else:
        # Interactive mode
        run_scan(
            package_name=args.package,
            ecosystem=args.ecosystem,
            scan_deps=not args.no_deps,
            max_depth=args.depth,
            verbose=args.verbose
        )


if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        # Interactive mode
        print_banner()
        package = input(f"  {Colors.WHITE}Enter package name: {Colors.RESET}")
        ecosystem = input(
            f"  {Colors.WHITE}Ecosystem (npm/pypi) [npm]: {Colors.RESET}"
        ).strip() or "npm"

        run_scan(package, ecosystem)