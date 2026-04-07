"""
GitHub Webhook Handler
Automatically scans dependencies when PRs or pushes change dependency files.
"""

import hmac
import hashlib
import json
from flask import Blueprint, request, jsonify

from core.metadata_analyzer import MetadataAnalyzer
from core.typosquat_detector import TyposquatDetector
from core.vuln_engine import VulnerabilityEngine
from core.risk_scorer import RiskScorer

webhook_bp = Blueprint('webhook', __name__)

WEBHOOK_SECRET = "your-webhook-secret-key"

DEPENDENCY_FILES = {
    "python": [
        "requirements.txt", "setup.py", "pyproject.toml",
        "Pipfile", "Pipfile.lock", "setup.cfg"
    ],
    "javascript": [
        "package.json", "package-lock.json",
        "yarn.lock", "pnpm-lock.yaml"
    ]
}


def verify_github_signature(payload_body, signature_header):
    """Verify that the webhook came from GitHub"""
    if not signature_header:
        return False
    
    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        payload_body,
        hashlib.sha256
    ).hexdigest()
    
    expected = f"sha256={expected_signature}"
    return hmac.compare_digest(expected, signature_header)


def parse_requirements_txt(content):
    """Parse requirements.txt content into package list"""
    packages = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle formats: package==1.0, package>=1.0, package
        name = line.split("==")[0].split(">=")[0].split("<=")[0].split(
            "!=")[0].split("~=")[0].split(">")[0].split("<")[0].strip()
        if name:
            packages.append({"name": name, "ecosystem": "pypi"})
    return packages


def parse_package_json(content):
    """Parse package.json content into package list"""
    packages = []
    try:
        data = json.loads(content)
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        
        for name in deps:
            packages.append({"name": name, "ecosystem": "npm"})
        for name in dev_deps:
            packages.append({"name": name, "ecosystem": "npm"})
    except json.JSONDecodeError:
        pass
    return packages


@webhook_bp.route("/api/webhook/github", methods=["POST"])
def github_webhook():
    """
    Handle GitHub webhook events.
    Triggers scanning when dependency files change.
    """
    # Verify signature
    signature = request.headers.get("X-Hub-Signature-256", "")
    if WEBHOOK_SECRET != "your-webhook-secret-key":  # Only verify if configured
        if not verify_github_signature(request.data, signature):
            return jsonify({"error": "Invalid signature"}), 403

    event_type = request.headers.get("X-GitHub-Event", "")
    payload = request.get_json()

    if not payload:
        return jsonify({"error": "Empty payload"}), 400

    if event_type == "push":
        return handle_push_event(payload)
    elif event_type == "pull_request":
        return handle_pr_event(payload)
    elif event_type == "ping":
        return jsonify({"message": "Webhook connected successfully!"})
    else:
        return jsonify({"message": f"Event type '{event_type}' not handled"})


def handle_push_event(payload):
    """Handle push events — scan if dependency files changed"""
    changed_dep_files = []
    
    commits = payload.get("commits", [])
    repo_name = payload.get("repository", {}).get("full_name", "unknown")
    branch = payload.get("ref", "").split("/")[-1]

    for commit in commits:
        all_files = (
            commit.get("added", []) +
            commit.get("modified", [])
        )
        
        for filepath in all_files:
            filename = filepath.split("/")[-1]
            for ecosystem, dep_files in DEPENDENCY_FILES.items():
                if filename in dep_files:
                    changed_dep_files.append({
                        "file": filepath,
                        "ecosystem": ecosystem,
                        "commit": commit.get("id", "")[:8],
                        "author": commit.get("author", {}).get("name", "unknown")
                    })

    if not changed_dep_files:
        return jsonify({
            "status": "no_dependency_changes",
            "message": "No dependency files were modified",
            "repository": repo_name,
            "branch": branch
        })

    # Scan changed dependency files
    scan_results = scan_dependency_changes(changed_dep_files)

    # Determine if we should block
    critical_found = any(
        r.get("risk_level") in ["CRITICAL", "HIGH"]
        for r in scan_results.get("package_results", [])
    )

    return jsonify({
        "status": "scanned",
        "repository": repo_name,
        "branch": branch,
        "dependency_files_changed": len(changed_dep_files),
        "packages_scanned": scan_results.get("total_scanned", 0),
        "critical_issues": scan_results.get("critical_count", 0),
        "high_issues": scan_results.get("high_count", 0),
        "should_block": critical_found,
        "results": scan_results
    })


def handle_pr_event(payload):
    """Handle pull request events"""
    action = payload.get("action", "")
    pr_number = payload.get("number", 0)
    repo_name = payload.get("repository", {}).get("full_name", "unknown")

    if action not in ["opened", "synchronize", "reopened"]:
        return jsonify({
            "status": "ignored",
            "message": f"PR action '{action}' not scanned"
        })

    return jsonify({
        "status": "pr_detected",
        "message": f"PR #{pr_number} detected in {repo_name}. "
                   f"Full PR diff scanning not yet implemented. "
                   f"Use push event scanning instead.",
        "pr_number": pr_number,
        "repository": repo_name
    })


def scan_dependency_changes(changed_files):
    """Scan packages from changed dependency files"""
    metadata_analyzer = MetadataAnalyzer()
    typosquat_detector = TyposquatDetector()
    vuln_engine = VulnerabilityEngine()
    risk_scorer = RiskScorer()

    all_results = []
    critical_count = 0
    high_count = 0

    # For webhook scanning, we scan package names
    # In production, you'd fetch the actual file content from GitHub API
    # For demo, we'll just acknowledge the files changed

    for dep_file in changed_files:
        all_results.append({
            "file": dep_file["file"],
            "ecosystem": dep_file["ecosystem"],
            "commit": dep_file["commit"],
            "author": dep_file["author"],
            "status": "dependency_file_change_detected",
            "note": "Full file content scanning requires GitHub API token"
        })

    return {
        "total_scanned": len(all_results),
        "critical_count": critical_count,
        "high_count": high_count,
        "package_results": all_results
    }


@webhook_bp.route("/api/webhook/scan-requirements", methods=["POST"])
def scan_requirements():
    """
    Direct endpoint to scan a requirements.txt or package.json content.
    
    Request body:
    {
        "content": "flask==3.0.0\nrequests==2.31.0\n...",
        "file_type": "requirements.txt"
    }
    """
    data = request.get_json()
    content = data.get("content", "")
    file_type = data.get("file_type", "requirements.txt")

    if not content:
        return jsonify({"error": "Missing content"}), 400

    # Parse packages
    if file_type in ["requirements.txt", "setup.py", "Pipfile"]:
        packages = parse_requirements_txt(content)
    elif file_type in ["package.json"]:
        packages = parse_package_json(content)
    else:
        return jsonify({"error": f"Unsupported file type: {file_type}"}), 400

    if not packages:
        return jsonify({
            "status": "no_packages",
            "message": "No packages found in the provided content"
        })

    # Scan each package
    metadata_analyzer = MetadataAnalyzer()
    typosquat_detector = TyposquatDetector()
    vuln_engine = VulnerabilityEngine()
    risk_scorer = RiskScorer()

    results = []
    for pkg in packages[:30]:  # Limit to 30 packages
        try:
            ecosystem = pkg["ecosystem"]
            name = pkg["name"]

            meta = metadata_analyzer.analyze(name, ecosystem)
            if "error" in meta:
                results.append({
                    "package": name,
                    "error": meta["error"]
                })
                continue

            version = meta.get("metadata", {}).get("latest_version")
            typo = typosquat_detector.check(name, ecosystem)
            vulns = vuln_engine.check(name, version, ecosystem)
            risk = risk_scorer.calculate(
                metadata_result=meta,
                vuln_result=vulns,
                typosquat_result=typo
            )

            results.append({
                "package": name,
                "version": version,
                "risk_score": risk["final_score"],
                "risk_level": risk["risk_level"],
                "vulnerabilities": vulns.get("total_count", 0),
                "typosquat_suspect": typo.get("is_typosquat_suspect", False)
            })
        except Exception as e:
            results.append({
                "package": pkg["name"],
                "error": str(e)
            })

    # Summary
    scanned = [r for r in results if "error" not in r]
    return jsonify({
        "status": "scanned",
        "file_type": file_type,
        "total_packages": len(packages),
        "total_scanned": len(scanned),
        "critical": sum(1 for r in scanned if r["risk_level"] == "CRITICAL"),
        "high": sum(1 for r in scanned if r["risk_level"] == "HIGH"),
        "medium": sum(1 for r in scanned if r["risk_level"] == "MEDIUM"),
        "low": sum(1 for r in scanned if r["risk_level"] == "LOW"),
        "results": results
    })