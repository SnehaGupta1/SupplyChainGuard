"""
Flask API Routes
Serves the React dashboard and provides REST API endpoints.
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
import traceback

from core.metadata_analyzer import MetadataAnalyzer
from core.typosquat_detector import TyposquatDetector
from core.vuln_engine import VulnerabilityEngine
from core.static_analyzer import StaticCodeAnalyzer
from core.behavioral_profiler import BehavioralProfiler
from core.dependency_graph import DependencyGraphAnalyzer
from core.risk_scorer import RiskScorer
from core.sbom_generator import SBOMGenerator
from core.report_generator import ReportGenerator


def create_app():
    app = Flask(__name__,
                static_folder="../dashboard/build",
                static_url_path="/")
    CORS(app)

    from api.webhook_handler import webhook_bp
    app.register_blueprint(webhook_bp)

    # ──────────────────────────────────────────────
    # SERVE REACT APP
    # ──────────────────────────────────────────────

    @app.route("/")
    def serve_react():
        if os.path.exists(app.static_folder + "/index.html"):
            return send_from_directory(app.static_folder, "index.html")
        return jsonify({
            "message": "SupplyChainGuard API is running",
            "endpoints": {
                "full_scan": "POST /api/scan",
                "metadata": "POST /api/scan/metadata",
                "typosquat": "POST /api/scan/typosquat",
                "vulnerabilities": "POST /api/scan/vulnerabilities",
                "dependency_graph": "POST /api/scan/dependencies",
                "health": "GET /api/health"
            }
        })

    @app.route("/<path:path>")
    def serve_static(path):
        if os.path.exists(os.path.join(app.static_folder, path)):
            return send_from_directory(app.static_folder, path)
        return send_from_directory(app.static_folder, "index.html")

    # ──────────────────────────────────────────────
    # API: HEALTH CHECK
    # ──────────────────────────────────────────────

    @app.route("/api/health", methods=["GET"])
    def health_check():
        return jsonify({
            "status": "healthy",
            "service": "SupplyChainGuard",
            "version": "1.0.0",
            "modules": {
                "metadata_analyzer": True,
                "typosquat_detector": True,
                "vulnerability_engine": True,
                "static_analyzer": True,
                "behavioral_profiler": True,
                "dependency_graph": True,
                "risk_scorer": True,
                "sbom_generator": True,
                "report_generator": True
            }
        })

    # ──────────────────────────────────────────────
    # API: FULL SCAN
    # ──────────────────────────────────────────────

    @app.route("/api/scan", methods=["POST"])
    def full_scan():
        """
        Run complete scan pipeline on a package.
        
        Request body:
        {
            "package_name": "express",
            "ecosystem": "npm",
            "scan_dependencies": true,
            "max_dependency_depth": 2
        }
        """
        try:
            data = request.get_json()

            if not data or "package_name" not in data:
                return jsonify({
                    "error": "Missing required field: package_name"
                }), 400

            package_name = data["package_name"].strip()
            ecosystem = data.get("ecosystem", "npm").strip().lower()
            scan_deps = data.get("scan_dependencies", True)
            max_depth = data.get("max_dependency_depth", 2)

            if ecosystem not in ["npm", "pypi"]:
                return jsonify({
                    "error": f"Unsupported ecosystem: {ecosystem}. "
                             f"Use 'npm' or 'pypi'."
                }), 400

            # Initialize all modules
            metadata_analyzer = MetadataAnalyzer()
            typosquat_detector = TyposquatDetector()
            vuln_engine = VulnerabilityEngine()
            static_analyzer = StaticCodeAnalyzer()
            behavioral_profiler = BehavioralProfiler()
            graph_analyzer = DependencyGraphAnalyzer()
            risk_scorer = RiskScorer()
            report_generator = ReportGenerator()

            # ── STEP 1: Metadata Analysis ──
            metadata_result = metadata_analyzer.analyze(
                package_name, ecosystem
            )

            if "error" in metadata_result:
                return jsonify({
                    "error": metadata_result["error"]
                }), 404

            # Extract version for vuln check
            version = None
            if metadata_result.get("metadata"):
                version = metadata_result["metadata"].get("latest_version")

            # ── STEP 2: Typosquatting Check ──
            typosquat_result = typosquat_detector.check(
                package_name, ecosystem
            )

            # ── STEP 3: Vulnerability Check ──
            vuln_result = vuln_engine.check(
                package_name, version, ecosystem
            )

            # ── STEP 4: Static Code Analysis ──
            # Analyze install scripts if available
            code_result = {"risk_score": 0, "issues": [], "summary": {}}
            scripts = metadata_result.get("metadata", {}).get("scripts", {})
            if scripts:
                combined_code = "\n".join(
                    str(v) for v in scripts.values() if isinstance(v, str)
                )
                if combined_code.strip():
                    language = "javascript" if ecosystem == "npm" else "python"
                    code_result = static_analyzer.scan(
                        combined_code,
                        filename=f"{package_name}/scripts",
                        language=language
                    )

            # ── STEP 5: Behavioral Profiling ──
            behavioral_result = {"risk_score": 0, "behavior_summary": []}
            if scripts:
                combined_code = "\n".join(
                    str(v) for v in scripts.values() if isinstance(v, str)
                )
                if combined_code.strip():
                    language = "python" if ecosystem == "pypi" else "javascript"
                    behavioral_result = behavioral_profiler.profile(
                        combined_code, language
                    )

            # ── STEP 6: Dependency Graph Analysis ──
            graph_result = {"risk_score": 0, "total_dependencies": 0}
            if scan_deps:
                try:
                    graph_result = graph_analyzer.analyze(
                        package_name, ecosystem, max_depth=max_depth
                    )
                except Exception as e:
                    graph_result = {
                        "risk_score": 0,
                        "total_dependencies": 0,
                        "error": str(e)
                    }

            # ── STEP 7: Risk Scoring ──
            risk_result = risk_scorer.calculate(
                metadata_result=metadata_result,
                vuln_result=vuln_result,
                code_result=code_result,
                behavioral_result=behavioral_result,
                typosquat_result=typosquat_result,
                graph_result=graph_result
            )

            # ── STEP 8: Generate Report ──
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

            # ── STEP 9: Generate SBOM ──
            sbom_gen = SBOMGenerator(package_name, version or "unknown")
            sbom_gen.add_component(
                name=package_name,
                version=version or "unknown",
                ecosystem=ecosystem,
                risk_score=risk_result["final_score"],
                risk_level=risk_result["risk_level"],
                vulnerabilities=vuln_result.get("vulnerabilities", [])
            )

            # Add dependencies to SBOM
            deps = metadata_result.get("metadata", {}).get(
                "dependencies", {}
            )
            if deps:
                for dep_name in list(deps.keys())[:20]:
                    sbom_gen.add_component(
                        name=dep_name,
                        version="latest",
                        ecosystem=ecosystem
                    )
                    sbom_gen.add_dependency_relationship(
                        package_name, dep_name
                    )

            # ── BUILD RESPONSE ──
            response = {
                "success": True,
                "package_name": package_name,
                "ecosystem": ecosystem,
                "version": version,

                # Core risk result
                "risk_score": risk_result["final_score"],
                "risk_level": risk_result["risk_level"],
                "risk_color": risk_result["risk_color"],
                "recommended_action": risk_result["recommended_action"],

                # Category breakdown for dashboard charts
                "category_breakdown": risk_result["category_breakdown"],

                # Module results
                "metadata": {
                    "risk_score": metadata_result.get("risk_score", 0),
                    "factors": metadata_result.get("risk_factors", []),
                    "checks": metadata_result.get("checks", []),
                    "package_info": {
                        "name": metadata_result.get("metadata", {}).get("name"),
                        "version": version,
                        "author": metadata_result.get("metadata", {}).get("author"),
                        "license": metadata_result.get("metadata", {}).get("license"),
                        "maintainers": metadata_result.get("metadata", {}).get("maintainers", []),
                        "version_count": metadata_result.get("metadata", {}).get("version_count", 0),
                        "dependency_count": len(deps) if deps else 0,
                        "has_repository": bool(metadata_result.get("metadata", {}).get("repository")),
                        "publish_time": metadata_result.get("metadata", {}).get("publish_time"),
                    }
                },

                "typosquatting": {
                    "is_suspect": typosquat_result.get("is_typosquat_suspect", False),
                    "closest_match": typosquat_result.get("closest_legitimate"),
                    "risk_score": typosquat_result.get("risk_score", 0),
                    "techniques": typosquat_result.get("techniques_triggered", []),
                    "matches": typosquat_result.get("matches", [])
                },

                "vulnerabilities": {
                    "total": vuln_result.get("total_count", 0),
                    "critical": vuln_result.get("critical_count", 0),
                    "high": vuln_result.get("high_count", 0),
                    "medium": vuln_result.get("medium_count", 0),
                    "low": vuln_result.get("low_count", 0),
                    "risk_score": vuln_result.get("risk_score", 0),
                    "details": vuln_result.get("vulnerabilities", [])[:10],
                    "sources_checked": vuln_result.get("sources_checked", [])
                },

                "code_analysis": {
                    "risk_score": code_result.get("risk_score", 0),
                    "total_issues": code_result.get("summary", {}).get("total_issues", 0),
                    "obfuscation_detected": code_result.get("obfuscation_detected", False),
                    "entropy_score": code_result.get("entropy_score", 0),
                    "issues": code_result.get("issues", [])[:20],
                    "encoded_payloads": code_result.get("encoded_payloads", []),
                    "suspicious_urls": code_result.get("suspicious_urls", [])
                },

                "behavioral": {
                    "risk_score": behavioral_result.get("risk_score", 0),
                    "dominant_behavior": behavioral_result.get("dominant_behavior"),
                    "assessment": behavioral_result.get("risk_assessment", ""),
                    "fingerprint": behavioral_result.get("fingerprint_vector", {}),
                    "summary": behavioral_result.get("behavior_summary", [])
                },

                "dependency_graph": {
                    "total_dependencies": graph_result.get("total_dependencies", 0),
                    "critical_nodes": graph_result.get("critical_nodes", []),
                    "blast_radius": graph_result.get("blast_radius", {}),
                    "risk_score": graph_result.get("risk_score", 0),
                    "risk_factors": graph_result.get("risk_factors", []),
                    "graph_data": graph_analyzer.get_graph_data() if scan_deps else {"nodes": [], "edges": []}
                },

                # Evidence trail
                "evidence": risk_result.get("evidence", []),

                # Report & SBOM
                "report": report,
                "sbom_summary": sbom_gen.get_summary(),

                # Recommendations
                "recommendations": report.get("recommendations", [])
            }

            # Save report and SBOM
            try:
                report_generator.save_report(report)
                sbom_gen.export_json()
            except Exception:
                pass  # Non-critical if save fails

            return jsonify(response)

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                "error": f"Scan failed: {str(e)}",
                "success": False
            }), 500

    # ──────────────────────────────────────────────
    # API: INDIVIDUAL MODULE ENDPOINTS
    # ──────────────────────────────────────────────

    @app.route("/api/scan/metadata", methods=["POST"])
    def scan_metadata():
        """Run metadata analysis only"""
        try:
            data = request.get_json()
            package_name = data.get("package_name", "").strip()
            ecosystem = data.get("ecosystem", "npm").strip().lower()

            if not package_name:
                return jsonify({"error": "Missing package_name"}), 400

            analyzer = MetadataAnalyzer()
            result = analyzer.analyze(package_name, ecosystem)

            if "error" in result:
                return jsonify(result), 404

            return jsonify({"success": True, "result": result})

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/scan/typosquat", methods=["POST"])
    def scan_typosquat():
        """Run typosquatting detection only"""
        try:
            data = request.get_json()
            package_name = data.get("package_name", "").strip()
            ecosystem = data.get("ecosystem", "npm").strip().lower()

            if not package_name:
                return jsonify({"error": "Missing package_name"}), 400

            detector = TyposquatDetector()
            result = detector.check(package_name, ecosystem)

            return jsonify({"success": True, "result": result})

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/scan/vulnerabilities", methods=["POST"])
    def scan_vulnerabilities():
        """Run vulnerability check only"""
        try:
            data = request.get_json()
            package_name = data.get("package_name", "").strip()
            version = data.get("version")
            ecosystem = data.get("ecosystem", "npm").strip().lower()

            if not package_name:
                return jsonify({"error": "Missing package_name"}), 400

            engine = VulnerabilityEngine()
            result = engine.check(package_name, version, ecosystem)

            return jsonify({"success": True, "result": result})

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/scan/dependencies", methods=["POST"])
    def scan_dependencies():
        """Run dependency graph analysis only"""
        try:
            data = request.get_json()
            package_name = data.get("package_name", "").strip()
            ecosystem = data.get("ecosystem", "npm").strip().lower()
            max_depth = data.get("max_depth", 2)

            if not package_name:
                return jsonify({"error": "Missing package_name"}), 400

            analyzer = DependencyGraphAnalyzer()
            result = analyzer.analyze(package_name, ecosystem, max_depth)
            result["graph_data"] = analyzer.get_graph_data()

            return jsonify({"success": True, "result": result})

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/scan/code", methods=["POST"])
    def scan_code():
        """Run static code analysis on submitted code"""
        try:
            data = request.get_json()
            code_content = data.get("code", "")
            language = data.get("language", "python")
            filename = data.get("filename", "submitted_code")

            if not code_content:
                return jsonify({"error": "Missing code content"}), 400

            analyzer = StaticCodeAnalyzer()
            result = analyzer.scan(code_content, filename, language)

            profiler = BehavioralProfiler()
            behavioral = profiler.profile(code_content, language)

            return jsonify({
                "success": True,
                "static_analysis": result,
                "behavioral_profile": behavioral
            })

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ──────────────────────────────────────────────
    # API: BATCH SCAN
    # ──────────────────────────────────────────────

    @app.route("/api/scan/batch", methods=["POST"])
    def batch_scan():
        """
        Scan multiple packages at once.
        
        Request body:
        {
            "packages": ["express", "lodash", "axios"],
            "ecosystem": "npm"
        }
        """
        try:
            data = request.get_json()
            packages = data.get("packages", [])
            ecosystem = data.get("ecosystem", "npm")

            if not packages:
                return jsonify({"error": "Missing packages list"}), 400

            if len(packages) > 20:
                return jsonify({
                    "error": "Maximum 20 packages per batch scan"
                }), 400

            results = []
            metadata_analyzer = MetadataAnalyzer()
            typosquat_detector = TyposquatDetector()
            vuln_engine = VulnerabilityEngine()
            risk_scorer = RiskScorer()

            for pkg_name in packages:
                try:
                    metadata_result = metadata_analyzer.analyze(
                        pkg_name, ecosystem
                    )

                    if "error" in metadata_result:
                        results.append({
                            "package_name": pkg_name,
                            "error": metadata_result["error"]
                        })
                        continue

                    version = metadata_result.get("metadata", {}).get(
                        "latest_version"
                    )

                    typosquat_result = typosquat_detector.check(
                        pkg_name, ecosystem
                    )
                    vuln_result = vuln_engine.check(
                        pkg_name, version, ecosystem
                    )

                    risk_result = risk_scorer.calculate(
                        metadata_result=metadata_result,
                        vuln_result=vuln_result,
                        typosquat_result=typosquat_result
                    )

                    results.append({
                        "package_name": pkg_name,
                        "version": version,
                        "risk_score": risk_result["final_score"],
                        "risk_level": risk_result["risk_level"],
                        "risk_color": risk_result["risk_color"],
                        "vulnerabilities": vuln_result.get("total_count", 0),
                        "typosquat_suspect": typosquat_result.get(
                            "is_typosquat_suspect", False
                        ),
                        "metadata_issues": len(
                            metadata_result.get("risk_factors", [])
                        )
                    })

                except Exception as e:
                    results.append({
                        "package_name": pkg_name,
                        "error": str(e)
                    })

            # Summary
            scanned = [r for r in results if "error" not in r]
            critical_count = sum(
                1 for r in scanned if r["risk_level"] == "CRITICAL"
            )
            high_count = sum(
                1 for r in scanned if r["risk_level"] == "HIGH"
            )

            return jsonify({
                "success": True,
                "total_scanned": len(scanned),
                "total_errors": len(results) - len(scanned),
                "critical_packages": critical_count,
                "high_risk_packages": high_count,
                "results": results
            })

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ──────────────────────────────────────────────
    # API: COMPARE VERSIONS
    # ──────────────────────────────────────────────

    @app.route("/api/scan/compare", methods=["POST"])
    def compare_versions():
        """
        Compare two versions of a package.
        Useful for detecting malicious updates.
        """
        try:
            data = request.get_json()
            package_name = data.get("package_name", "").strip()
            ecosystem = data.get("ecosystem", "npm")

            if not package_name:
                return jsonify({"error": "Missing package_name"}), 400

            analyzer = MetadataAnalyzer()
            result = analyzer.analyze(package_name, ecosystem)

            if "error" in result:
                return jsonify(result), 404

            metadata = result.get("metadata", {})
            version_history = metadata.get("version_history", {})

            return jsonify({
                "success": True,
                "package_name": package_name,
                "latest_version": metadata.get("latest_version"),
                "total_versions": len(version_history),
                "version_timeline": version_history,
                "metadata_analysis": result
            })

        except Exception as e:
            return jsonify({"error": str(e)}), 500
        
    if __name__ == "__main__":
        app.run()
    return app