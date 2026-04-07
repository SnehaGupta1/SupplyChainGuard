"""
SupplyChainGuard - Secure Package Installer
Scans packages BEFORE installation and warns the user.

Usage:
    python cli/installer.py install express
    python cli/installer.py install requests -e pypi
    python cli/installer.py scan lodash
    python cli/installer.py scan -r requirements.txt
"""

import subprocess
import sys
import os
import json
import time
import argparse

# Add project root to path so we can import core modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.metadata_analyzer import MetadataAnalyzer
from core.typosquat_detector import TyposquatDetector
from core.vuln_engine import VulnerabilityEngine
from core.static_analyzer import StaticCodeAnalyzer
from core.behavioral_profiler import BehavioralProfiler
from core.risk_scorer import RiskScorer


# ──────────────────────────────────────────────
# TERMINAL COLORS (works on Mac/Linux/Windows 10+)
# ──────────────────────────────────────────────

class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# Enable colors on Windows
if os.name == 'nt':
    try:
        os.system('color')
    except Exception:
        # If colors don't work, disable them
        C.RED = C.GREEN = C.YELLOW = C.BLUE = ""
        C.CYAN = C.WHITE = C.BOLD = C.DIM = C.RESET = ""


# ──────────────────────────────────────────────
# BANNER
# ──────────────────────────────────────────────

def print_banner():
    print(f"""{C.CYAN}{C.BOLD}
  ┌─────────────────────────────────────────┐
  │  🛡️  SupplyChainGuard Installer         │
  │  Pre-Installation Security Scanner      │
  └─────────────────────────────────────────┘{C.RESET}
""")


# ──────────────────────────────────────────────
# THE SCANNING FUNCTION
# This is the heart of the tool.
# It runs all checks and returns results.
# ──────────────────────────────────────────────

def scan_package(package_name, ecosystem="npm"):
    """
    Scan a package through all detection modules.
    Returns: (score, level, findings_list)
    """
    findings = []

    # Create scanner instances
    metadata_analyzer = MetadataAnalyzer()
    typosquat_detector = TyposquatDetector()
    vuln_engine = VulnerabilityEngine()
    risk_scorer = RiskScorer()

    # ── CHECK 1: Metadata ──
    print(f"  {C.DIM}[1/4] Fetching metadata...{C.RESET}", end="", flush=True)
    start = time.time()

    metadata_result = metadata_analyzer.analyze(package_name, ecosystem)
    elapsed = time.time() - start

    # If package doesn't exist, stop here
    if "error" in metadata_result:
        print(f"\r  {C.RED}✗ {metadata_result['error']}{C.RESET}")
        return None, None, [{"source": "error", "severity": "critical",
                             "message": metadata_result["error"]}]

    metadata = metadata_result.get("metadata", {})
    version = metadata.get("latest_version", "unknown")
    print(f"\r  {C.GREEN}✓ Metadata fetched ({elapsed:.1f}s) "
          f"— v{version}{C.RESET}")

    # Collect any metadata issues
    for factor in metadata_result.get("risk_factors", []):
        findings.append({
            "source": "metadata",
            "severity": factor.get("severity", "medium"),
            "message": factor.get("description", "")
        })

    # ── CHECK 2: Typosquatting ──
    print(f"  {C.DIM}[2/4] Checking for typosquatting...{C.RESET}",
          end="", flush=True)

    typosquat_result = typosquat_detector.check(package_name, ecosystem)

    if typosquat_result.get("is_typosquat_suspect"):
        closest = typosquat_result.get("closest_legitimate", "?")
        print(f"\r  {C.RED}{C.BOLD}⚠ TYPOSQUATTING ALERT! "
              f"Similar to \"{closest}\"{C.RESET}")
        findings.append({
            "source": "typosquatting",
            "severity": "critical",
            "message": f"Name is suspiciously similar to '{closest}'"
        })
    else:
        print(f"\r  {C.GREEN}✓ Name check passed{C.RESET}")

    # ── CHECK 3: Known Vulnerabilities ──
    print(f"  {C.DIM}[3/4] Checking vulnerability databases...{C.RESET}",
          end="", flush=True)
    start = time.time()

    vuln_result = vuln_engine.check(package_name, version, ecosystem)
    elapsed = time.time() - start
    total_vulns = vuln_result.get("total_count", 0)

    if total_vulns > 0:
        crit = vuln_result.get("critical_count", 0)
        high = vuln_result.get("high_count", 0)
        med = vuln_result.get("medium_count", 0)
        print(f"\r  {C.RED}⚠ {total_vulns} vulnerability(ies) found "
              f"({elapsed:.1f}s){C.RESET}")
        if crit > 0:
            print(f"    {C.RED}🔴 Critical: {crit}{C.RESET}")
        if high > 0:
            print(f"    {C.RED}🟠 High: {high}{C.RESET}")
        if med > 0:
            print(f"    {C.YELLOW}🟡 Medium: {med}{C.RESET}")

        findings.append({
            "source": "vulnerability",
            "severity": "critical" if crit > 0 else "high",
            "message": f"{total_vulns} known CVE(s) — "
                       f"Critical:{crit} High:{high} Medium:{med}"
        })
    else:
        print(f"\r  {C.GREEN}✓ No known vulnerabilities ({elapsed:.1f}s)"
              f"{C.RESET}")

    # ── CHECK 4: Code Analysis ──
    print(f"  {C.DIM}[4/4] Analyzing code patterns...{C.RESET}",
          end="", flush=True)

    code_result = {"risk_score": 0, "issues": []}
    behavioral_result = {"risk_score": 0}

    # Analyze install scripts if they exist
    scripts = metadata.get("scripts", {})
    if scripts:
        combined_code = "\n".join(
            str(v) for v in scripts.values() if isinstance(v, str)
        )
        if combined_code.strip():
            static_analyzer = StaticCodeAnalyzer()
            lang = "javascript" if ecosystem == "npm" else "python"
            code_result = static_analyzer.scan(combined_code, "scripts", lang)

            profiler = BehavioralProfiler()
            behavioral_result = profiler.profile(combined_code, lang)

    code_issues = len(code_result.get("issues", []))

    if code_issues > 0:
        print(f"\r  {C.YELLOW}⚠ {code_issues} suspicious pattern(s) "
              f"found{C.RESET}")
        # Add top 3 findings
        for issue in code_result.get("issues", [])[:3]:
            findings.append({
                "source": "code_analysis",
                "severity": issue.get("severity", "medium"),
                "message": issue.get("description", "")
            })
    else:
        print(f"\r  {C.GREEN}✓ No suspicious code patterns{C.RESET}")

    # ── CALCULATE FINAL RISK SCORE ──
    risk_result = risk_scorer.calculate(
        metadata_result=metadata_result,
        vuln_result=vuln_result,
        code_result=code_result,
        behavioral_result=behavioral_result,
        typosquat_result=typosquat_result
    )

    return risk_result["final_score"], risk_result["risk_level"], findings


# ──────────────────────────────────────────────
# DISPLAY RESULTS IN TERMINAL
# ──────────────────────────────────────────────

def show_results(package_name, ecosystem, score, level, findings):
    """Show scan results with a nice visual display"""

    # Pick color based on risk level
    color = {
        "CRITICAL": C.RED,
        "HIGH": C.RED,
        "MEDIUM": C.YELLOW,
        "LOW": C.GREEN
    }.get(level, C.WHITE)

    # Build risk bar  [████████░░░░░░░░░░░░]
    filled = int(score / 5)
    empty = 20 - filled
    bar = "█" * filled + "░" * empty

    print(f"\n  {C.BOLD}{'─' * 45}{C.RESET}")
    print(f"  {C.BOLD}📦 {package_name} ({ecosystem}){C.RESET}")
    print(f"  {C.BOLD}{'─' * 45}{C.RESET}")
    print(f"  Risk Score: {color}{C.BOLD}{score:.0f}/100{C.RESET}")
    print(f"  Risk Level: {color}{C.BOLD}{level}{C.RESET}")
    print(f"  [{color}{bar}{C.RESET}]")

    # Show findings
    if findings:
        print(f"\n  {C.BOLD}Findings:{C.RESET}")
        for f in findings:
            sev = f.get("severity", "medium")
            icon = "🔴" if sev in ["critical", "high"] else \
                   "🟡" if sev == "medium" else "🟢"
            print(f"    {icon} [{f['source']}] {f['message']}")

    print(f"  {C.BOLD}{'─' * 45}{C.RESET}")


# ──────────────────────────────────────────────
# ASK USER: INSTALL OR NOT?
# ──────────────────────────────────────────────

def ask_user(package_name, level, score):
    """
    Ask the user whether to proceed with installation.
    Different prompts based on risk level.
    """

    if level == "CRITICAL":
        print(f"\n  {C.RED}{C.BOLD}🚫 CRITICAL RISK DETECTED!{C.RESET}")
        print(f"  {C.RED}This package shows strong indicators of "
              f"malicious activity.{C.RESET}")
        print(f"  {C.RED}Installation is NOT recommended.{C.RESET}")
        print()
        response = input(f"  {C.RED}Type 'INSTALL ANYWAY' to force, "
                         f"or press Enter to cancel: {C.RESET}")
        return response.strip() == "INSTALL ANYWAY"

    elif level == "HIGH":
        print(f"\n  {C.RED}⚠️  HIGH RISK — Multiple concerns found{C.RESET}")
        response = input(f"  Install {package_name} anyway? "
                         f"(y/N): ").strip().lower()
        return response == "y"

    elif level == "MEDIUM":
        print(f"\n  {C.YELLOW}⚡ MEDIUM RISK — Some concerns found{C.RESET}")
        response = input(f"  Install {package_name}? "
                         f"(Y/n): ").strip().lower()
        return response != "n"

    else:  # LOW
        print(f"\n  {C.GREEN}✅ LOW RISK — Package appears safe{C.RESET}")
        response = input(f"  Install {package_name}? "
                         f"(Y/n): ").strip().lower()
        return response != "n"


# ──────────────────────────────────────────────
# ACTUALLY INSTALL THE PACKAGE
# ──────────────────────────────────────────────

def run_install(package_name, ecosystem):
    """Run the real pip install or npm install command"""

    if ecosystem == "npm":
        cmd = ["npm", "install", package_name]
    elif ecosystem == "pypi":
        cmd = [sys.executable, "-m", "pip", "install", package_name]
    else:
        print(f"  {C.RED}Unknown ecosystem: {ecosystem}{C.RESET}")
        return False

    print(f"\n  {C.CYAN}Running: {' '.join(cmd)}{C.RESET}\n")

    try:
        result = subprocess.run(cmd)
        return result.returncode == 0
    except FileNotFoundError:
        tool = "npm" if ecosystem == "npm" else "pip"
        print(f"  {C.RED}'{tool}' not found. Is it installed?{C.RESET}")
        return False


# ──────────────────────────────────────────────
# SCAN A REQUIREMENTS FILE
# ──────────────────────────────────────────────

def scan_file(filepath, ecosystem=None):
    """Scan all packages in a requirements.txt or package.json"""

    if not os.path.exists(filepath):
        print(f"  {C.RED}File not found: {filepath}{C.RESET}")
        return

    filename = os.path.basename(filepath)

    # Auto-detect ecosystem from filename
    if ecosystem is None:
        if "package" in filename:
            ecosystem = "npm"
        else:
            ecosystem = "pypi"

    # Parse the file to get package names
    packages = []

    if filename == "package.json":
        with open(filepath, "r") as f:
            try:
                data = json.load(f)
                deps = data.get("dependencies", {})
                dev_deps = data.get("devDependencies", {})
                packages = list(deps.keys()) + list(dev_deps.keys())
            except json.JSONDecodeError:
                print(f"  {C.RED}Invalid JSON in {filepath}{C.RESET}")
                return
    else:
        # requirements.txt format
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Extract package name (remove version specifiers)
                name = line.split("==")[0].split(">=")[0].split("<=")[0]
                name = name.split("!=")[0].split("~=")[0].split(">")[0]
                name = name.split("<")[0].split("[")[0].strip()
                if name:
                    packages.append(name)

    if not packages:
        print(f"  {C.YELLOW}No packages found in {filepath}{C.RESET}")
        return

    print(f"  {C.CYAN}Scanning {len(packages)} package(s) "
          f"from {filename}...{C.RESET}\n")

    # Scan each package (quick version - metadata + typosquat + vulns)
    results = []
    dangerous = []

    metadata_analyzer = MetadataAnalyzer()
    typosquat_detector = TyposquatDetector()
    vuln_engine = VulnerabilityEngine()
    risk_scorer = RiskScorer()

    for i, pkg in enumerate(packages):
        print(f"  {C.DIM}[{i+1}/{len(packages)}] {pkg}...{C.RESET}",
              end="", flush=True)

        try:
            meta = metadata_analyzer.analyze(pkg, ecosystem)
            if "error" in meta:
                print(f"\r  {C.YELLOW}⚠ {pkg:25s} — {meta['error']}{C.RESET}")
                continue

            version = meta.get("metadata", {}).get("latest_version")
            typo = typosquat_detector.check(pkg, ecosystem)
            vulns = vuln_engine.check(pkg, version, ecosystem)

            risk = risk_scorer.calculate(
                metadata_result=meta,
                vuln_result=vulns,
                typosquat_result=typo
            )

            score = risk["final_score"]
            level = risk["risk_level"]

            # Color based on risk
            color = C.RED if level in ["CRITICAL", "HIGH"] else \
                    C.YELLOW if level == "MEDIUM" else C.GREEN
            icon = "🔴" if level in ["CRITICAL", "HIGH"] else \
                   "🟡" if level == "MEDIUM" else "🟢"

            print(f"\r  {icon} {pkg:25s} {color}{level:10s} "
                  f"(score: {score:.0f}){C.RESET}")

            results.append({"package": pkg, "score": score, "level": level})

            if level in ["CRITICAL", "HIGH"]:
                dangerous.append(pkg)

        except Exception as e:
            print(f"\r  {C.RED}✗ {pkg:25s} — Error: {str(e)[:40]}{C.RESET}")

    # Print summary
    print(f"\n  {C.BOLD}{'─' * 50}{C.RESET}")
    print(f"  {C.BOLD}SCAN SUMMARY{C.RESET}")
    print(f"  {C.BOLD}{'─' * 50}{C.RESET}")
    print(f"  Total scanned: {len(results)}")

    low = sum(1 for r in results if r['level'] == 'LOW')
    med = sum(1 for r in results if r['level'] == 'MEDIUM')
    high = sum(1 for r in results if r['level'] == 'HIGH')
    crit = sum(1 for r in results if r['level'] == 'CRITICAL')

    print(f"  {C.GREEN}🟢 LOW:      {low}{C.RESET}")
    print(f"  {C.YELLOW}🟡 MEDIUM:   {med}{C.RESET}")
    print(f"  {C.RED}🟠 HIGH:     {high}{C.RESET}")
    print(f"  {C.RED}🔴 CRITICAL: {crit}{C.RESET}")

    if dangerous:
        print(f"\n  {C.RED}{C.BOLD}⚠ Dangerous packages:{C.RESET}")
        for pkg in dangerous:
            print(f"    {C.RED}• {pkg}{C.RESET}")
        print(f"\n  {C.RED}Review these before installing!{C.RESET}")
    else:
        print(f"\n  {C.GREEN}✅ All packages appear safe!{C.RESET}")

    print(f"  {C.BOLD}{'─' * 50}{C.RESET}\n")


# ──────────────────────────────────────────────
# MAIN — HANDLES ALL COMMANDS
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="scg",
        description="SupplyChainGuard — Secure Package Installer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  scg install express                    Scan & install npm package
  scg install requests -e pypi           Scan & install pip package
  scg install express --force            Skip scan, install directly
  scg scan express                       Scan only (no install)
  scg scan requests -e pypi              Scan PyPI package
  scg scan -r requirements.txt           Scan entire requirements file
  scg scan -r package.json               Scan all npm dependencies
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Command")

    # ── "install" command ──
    install_p = subparsers.add_parser("install", help="Scan and install")
    install_p.add_argument("package", help="Package name")
    install_p.add_argument(
        "-e", "--ecosystem",
        choices=["npm", "pypi"],
        default="npm",
        help="Ecosystem (default: npm)"
    )
    install_p.add_argument(
        "--force",
        action="store_true",
        help="Skip scan, install directly"
    )

    # ── "scan" command ──
    scan_p = subparsers.add_parser("scan", help="Scan only (no install)")
    scan_p.add_argument("package", nargs="?", help="Package name")
    scan_p.add_argument(
        "-e", "--ecosystem",
        choices=["npm", "pypi"],
        default="npm",
        help="Ecosystem (default: npm)"
    )
    scan_p.add_argument(
        "-r", "--requirements",
        help="Path to requirements.txt or package.json"
    )

    args = parser.parse_args()

    # No command given — show help
    if not args.command:
        parser.print_help()
        return

    print_banner()

    # ══════════════════════════════════════════
    # INSTALL COMMAND
    # ══════════════════════════════════════════
    if args.command == "install":

        # Force mode — skip scan
        if args.force:
            print(f"  {C.YELLOW}⚡ Force mode — skipping scan{C.RESET}\n")
            success = run_install(args.package, args.ecosystem)
            sys.exit(0 if success else 1)

        # Normal mode — scan first
        print(f"  {C.CYAN}Scanning {args.package} before "
              f"installation...{C.RESET}\n")

        score, level, findings = scan_package(
            args.package, args.ecosystem
        )

        # Package not found
        if score is None:
            print(f"\n  {C.RED}Cannot install — package not found{C.RESET}\n")
            sys.exit(1)

        # Show results
        show_results(
            args.package, args.ecosystem, score, level, findings
        )

        # Ask user
        if ask_user(args.package, level, score):
            # User said yes — install
            print(f"\n  {C.GREEN}Proceeding with installation...{C.RESET}")
            success = run_install(args.package, args.ecosystem)

            if success:
                print(f"\n  {C.GREEN}✅ {args.package} installed "
                      f"successfully!{C.RESET}\n")
            else:
                print(f"\n  {C.RED}✗ Installation failed{C.RESET}\n")
                sys.exit(1)
        else:
            # User said no
            print(f"\n  {C.GREEN}Installation cancelled. "
                  f"You're safe! 🛡️{C.RESET}\n")
            sys.exit(0)

    # ══════════════════════════════════════════
    # SCAN COMMAND
    # ══════════════════════════════════════════
    elif args.command == "scan":

        # Scan a requirements file
        if args.requirements:
            scan_file(args.requirements, args.ecosystem)

        # Scan a single package
        elif args.package:
            print(f"  {C.CYAN}Scanning {args.package}...{C.RESET}\n")

            score, level, findings = scan_package(
                args.package, args.ecosystem
            )

            if score is not None:
                show_results(
                    args.package, args.ecosystem, score, level, findings
                )
        else:
            print(f"  {C.RED}Provide a package name or "
                  f"use -r for a file{C.RESET}")
            print(f"  Example: scg scan express")
            print(f"  Example: scg scan -r requirements.txt")


# ──────────────────────────────────────────────
# INTERACTIVE MODE (no arguments)
# ──────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        # Interactive mode — ask the user
        print_banner()

        print(f"  {C.BOLD}What do you want to do?{C.RESET}")
        print(f"  1. Scan & Install a package")
        print(f"  2. Scan a package (no install)")
        print(f"  3. Scan a requirements file")
        print()

        choice = input(f"  Choose (1/2/3): ").strip()

        if choice == "1":
            pkg = input(f"  Package name: ").strip()
            eco = input(f"  Ecosystem (npm/pypi) [npm]: ").strip() or "npm"

            print(f"\n  {C.CYAN}Scanning {pkg}...{C.RESET}\n")
            score, level, findings = scan_package(pkg, eco)

            if score is not None:
                show_results(pkg, eco, score, level, findings)

                if ask_user(pkg, level, score):
                    run_install(pkg, eco)
                else:
                    print(f"\n  {C.GREEN}Cancelled.{C.RESET}\n")

        elif choice == "2":
            pkg = input(f"  Package name: ").strip()
            eco = input(f"  Ecosystem (npm/pypi) [npm]: ").strip() or "npm"

            print(f"\n  {C.CYAN}Scanning {pkg}...{C.RESET}\n")
            score, level, findings = scan_package(pkg, eco)

            if score is not None:
                show_results(pkg, eco, score, level, findings)

        elif choice == "3":
            filepath = input(f"  File path: ").strip()
            scan_file(filepath)

        else:
            print(f"  {C.RED}Invalid choice{C.RESET}")