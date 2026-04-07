"""
Metadata Analyzer Module
Fetches and analyzes package metadata from npm and PyPI registries.
Detects anomalies in publish history, maintainer info, scripts, and more.
"""

import requests
from datetime import datetime, timezone
from config.settings import (
    NPM_REGISTRY_URL,
    PYPI_REGISTRY_URL,
    SUSPICIOUS_INSTALL_SCRIPTS,
    SUSPICIOUS_KEYWORDS,
    PACKAGE_AGE_THRESHOLD_DAYS,
    HIGH_DEPENDENCY_THRESHOLD,
    SCAN_TIMEOUT_SECONDS
)


class MetadataAnalyzer:
    """
    Analyzes package metadata from npm and PyPI registries.
    Extracts metadata fields and detects anomalies.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "SupplyChainGuard/1.0"
        })

    # ──────────────────────────────────────────────
    # PUBLIC API
    # ──────────────────────────────────────────────

    def analyze(self, package_name, ecosystem="npm"):
        """
        Main entry point. Fetches metadata and runs all checks.
        Returns structured analysis result.
        """
        if ecosystem == "npm":
            raw_metadata = self._fetch_npm_metadata(package_name)
        elif ecosystem == "pypi":
            raw_metadata = self._fetch_pypi_metadata(package_name)
        else:
            return {"error": f"Unsupported ecosystem: {ecosystem}"}

        if "error" in raw_metadata:
            return raw_metadata

        # Run all metadata checks
        analysis = {
            "package_name": package_name,
            "ecosystem": ecosystem,
            "metadata": raw_metadata,
            "checks": self._run_all_checks(raw_metadata, ecosystem),
            "risk_score": 0,
            "risk_factors": []
        }

        # Calculate metadata risk score
        total_score = 0
        for check in analysis["checks"]:
            if check["flagged"]:
                total_score += check["score"]
                analysis["risk_factors"].append({
                    "check": check["name"],
                    "description": check["description"],
                    "score": check["score"],
                    "severity": check["severity"]
                })

        analysis["risk_score"] = min(total_score, 100)
        return analysis

    # ──────────────────────────────────────────────
    # REGISTRY FETCHERS
    # ──────────────────────────────────────────────

    def _fetch_npm_metadata(self, package_name):
        """Fetch metadata from npm registry"""
        try:
            url = f"{NPM_REGISTRY_URL}/{package_name}"
            response = self.session.get(url, timeout=SCAN_TIMEOUT_SECONDS)

            if response.status_code == 404:
                return {"error": f"Package '{package_name}' not found on npm"}
            if response.status_code != 200:
                return {"error": f"npm registry returned status {response.status_code}"}

            data = response.json()
            latest_version = data.get("dist-tags", {}).get("latest", "")
            version_data = data.get("versions", {}).get(latest_version, {})
            time_data = data.get("time", {})

            # Extract maintainers
            maintainers = data.get("maintainers", [])
            maintainer_names = [m.get("name", "unknown") for m in maintainers]

            # Extract all version publish times
            version_history = {}
            for ver, timestamp in time_data.items():
                if ver not in ["created", "modified"]:
                    version_history[ver] = timestamp

            metadata = {
                "name": data.get("name"),
                "latest_version": latest_version,
                "description": data.get("description", ""),
                "author": version_data.get("author"),
                "maintainers": maintainer_names,
                "maintainer_count": len(maintainers),
                "license": version_data.get("license"),
                "homepage": data.get("homepage"),
                "repository": data.get("repository"),
                "readme": data.get("readme", ""),
                "publish_time": time_data.get(latest_version),
                "created_time": time_data.get("created"),
                "modified_time": time_data.get("modified"),
                "version_count": len(data.get("versions", {})),
                "version_history": version_history,
                "dependencies": version_data.get("dependencies", {}),
                "dev_dependencies": version_data.get("devDependencies", {}),
                "scripts": version_data.get("scripts", {}),
                "keywords": data.get("keywords", []),
                "has_types": "types" in version_data or "typings" in version_data,
                "dist": version_data.get("dist", {}),
                "engines": version_data.get("engines", {})
            }

            return metadata

        except requests.exceptions.Timeout:
            return {"error": f"Timeout fetching metadata for '{package_name}'"}
        except requests.exceptions.RequestException as e:
            return {"error": f"Network error: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    def _fetch_pypi_metadata(self, package_name):
        """Fetch metadata from PyPI registry"""
        try:
            url = f"{PYPI_REGISTRY_URL}/{package_name}/json"
            response = self.session.get(url, timeout=SCAN_TIMEOUT_SECONDS)

            if response.status_code == 404:
                return {"error": f"Package '{package_name}' not found on PyPI"}
            if response.status_code != 200:
                return {"error": f"PyPI registry returned status {response.status_code}"}

            data = response.json()
            info = data.get("info", {})
            releases = data.get("releases", {})

            # Find latest release time
            latest_version = info.get("version", "")
            latest_release_files = releases.get(latest_version, [])
            publish_time = None
            if latest_release_files:
                publish_time = latest_release_files[0].get("upload_time_iso_8601")

            # Determine created time (first release)
            created_time = None
            if releases:
                first_version = list(releases.keys())[0]
                first_files = releases.get(first_version, [])
                if first_files:
                    created_time = first_files[0].get("upload_time_iso_8601")

            metadata = {
                "name": info.get("name"),
                "latest_version": latest_version,
                "description": info.get("summary", ""),
                "author": info.get("author"),
                "author_email": info.get("author_email"),
                "maintainers": [info.get("author", "unknown")],
                "maintainer_count": 1 if info.get("author") else 0,
                "license": info.get("license"),
                "homepage": info.get("home_page"),
                "repository": info.get("project_urls", {}).get("Source")
                              or info.get("project_urls", {}).get("Repository"),
                "readme": info.get("description", ""),
                "publish_time": publish_time,
                "created_time": created_time,
                "modified_time": publish_time,
                "version_count": len(releases),
                "version_history": {
                    ver: files[0].get("upload_time_iso_8601") if files else None
                    for ver, files in releases.items()
                },
                "dependencies": self._parse_pypi_dependencies(
                    info.get("requires_dist", [])
                ),
                "dev_dependencies": {},
                "scripts": {},
                "keywords": info.get("keywords", "").split(",") if info.get("keywords") else [],
                "has_types": False,
                "classifiers": info.get("classifiers", []),
                "requires_python": info.get("requires_python"),
                "project_urls": info.get("project_urls", {})
            }

            return metadata

        except requests.exceptions.Timeout:
            return {"error": f"Timeout fetching metadata for '{package_name}'"}
        except requests.exceptions.RequestException as e:
            return {"error": f"Network error: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    def _parse_pypi_dependencies(self, requires_dist):
        """Parse PyPI requires_dist into a dependency dict"""
        deps = {}
        if not requires_dist:
            return deps
        for req in requires_dist:
            # Format: "package_name (>=1.0)" or "package_name; extra == 'dev'"
            parts = req.split(";")
            pkg_spec = parts[0].strip()
            pkg_name = pkg_spec.split("(")[0].split(">")[0].split("<")[0].split("=")[0].split("!")[0].strip()
            if pkg_name:
                deps[pkg_name] = pkg_spec
        return deps

    # ──────────────────────────────────────────────
    # ANALYSIS CHECKS
    # ──────────────────────────────────────────────

    def _run_all_checks(self, metadata, ecosystem):
        """Run all metadata analysis checks"""
        checks = []

        checks.append(self._check_author(metadata))
        checks.append(self._check_package_age(metadata))
        checks.append(self._check_install_scripts(metadata))
        checks.append(self._check_script_contents(metadata))
        checks.append(self._check_dependency_count(metadata))
        checks.append(self._check_repository(metadata))
        checks.append(self._check_readme(metadata))
        checks.append(self._check_version_history(metadata))
        checks.append(self._check_maintainer_count(metadata))
        checks.append(self._check_license(metadata))
        checks.append(self._check_version_anomaly(metadata))

        return checks

    def _check_author(self, metadata):
        """Check if package has author information"""
        has_author = bool(metadata.get("author"))
        return {
            "name": "author_check",
            "description": "No author information provided" if not has_author
                           else "Author information present",
            "flagged": not has_author,
            "score": 15,
            "severity": "medium",
            "details": {"author": metadata.get("author")}
        }

    def _check_package_age(self, metadata):
        """Check if package was recently published"""
        publish_time = metadata.get("publish_time")
        if not publish_time:
            return {
                "name": "package_age_check",
                "description": "Unable to determine package age",
                "flagged": True,
                "score": 10,
                "severity": "low",
                "details": {"publish_time": None}
            }

        try:
            if publish_time.endswith("Z"):
                publish_date = datetime.fromisoformat(
                    publish_time.replace("Z", "+00:00")
                )
            else:
                publish_date = datetime.fromisoformat(publish_time)

            if publish_date.tzinfo is None:
                publish_date = publish_date.replace(tzinfo=timezone.utc)

            current_date = datetime.now(timezone.utc)
            days_old = (current_date - publish_date).days

            is_new = days_old < PACKAGE_AGE_THRESHOLD_DAYS

            return {
                "name": "package_age_check",
                "description": f"Package is only {days_old} days old"
                               if is_new
                               else f"Package is {days_old} days old",
                "flagged": is_new,
                "score": 20 if is_new else 0,
                "severity": "high" if is_new else "info",
                "details": {
                    "publish_time": publish_time,
                    "days_old": days_old
                }
            }
        except Exception:
            return {
                "name": "package_age_check",
                "description": "Error parsing publish date",
                "flagged": True,
                "score": 10,
                "severity": "low",
                "details": {"publish_time": publish_time}
            }

    def _check_install_scripts(self, metadata):
        """Check for suspicious lifecycle install scripts"""
        scripts = metadata.get("scripts", {})
        if not scripts:
            return {
                "name": "install_scripts_check",
                "description": "No install scripts detected",
                "flagged": False,
                "score": 0,
                "severity": "info",
                "details": {"scripts": {}}
            }

        suspicious_found = []
        for script_name in scripts:
            if script_name in SUSPICIOUS_INSTALL_SCRIPTS:
                suspicious_found.append(script_name)

        flagged = len(suspicious_found) > 0
        return {
            "name": "install_scripts_check",
            "description": f"Suspicious install scripts found: {', '.join(suspicious_found)}"
                           if flagged
                           else "No suspicious install scripts",
            "flagged": flagged,
            "score": 30 if flagged else 0,
            "severity": "high" if flagged else "info",
            "details": {
                "all_scripts": list(scripts.keys()),
                "suspicious_scripts": suspicious_found
            }
        }

    def _check_script_contents(self, metadata):
        """Check for suspicious keywords inside script contents"""
        scripts = metadata.get("scripts", {})
        if not scripts:
            return {
                "name": "script_contents_check",
                "description": "No scripts to analyze",
                "flagged": False,
                "score": 0,
                "severity": "info",
                "details": {}
            }

        found_keywords = []
        for script_name, script_content in scripts.items():
            if not isinstance(script_content, str):
                continue
            content_lower = script_content.lower()
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword.lower() in content_lower:
                    found_keywords.append({
                        "script": script_name,
                        "keyword": keyword,
                        "content_preview": script_content[:200]
                    })

        flagged = len(found_keywords) > 0
        score = min(len(found_keywords) * 15, 40)

        return {
            "name": "script_contents_check",
            "description": f"Found {len(found_keywords)} suspicious keywords in scripts"
                           if flagged
                           else "No suspicious keywords in scripts",
            "flagged": flagged,
            "score": score,
            "severity": "critical" if score >= 30 else "high" if flagged else "info",
            "details": {"findings": found_keywords}
        }

    def _check_dependency_count(self, metadata):
        """Check if package has unusually high dependency count"""
        deps = metadata.get("dependencies", {})
        dep_count = len(deps) if deps else 0
        flagged = dep_count > HIGH_DEPENDENCY_THRESHOLD

        return {
            "name": "dependency_count_check",
            "description": f"High dependency count: {dep_count}"
                           if flagged
                           else f"Dependency count: {dep_count}",
            "flagged": flagged,
            "score": 10 if flagged else 0,
            "severity": "medium" if flagged else "info",
            "details": {
                "dependency_count": dep_count,
                "threshold": HIGH_DEPENDENCY_THRESHOLD,
                "dependencies": list(deps.keys()) if deps else []
            }
        }

    def _check_repository(self, metadata):
        """Check if package has a linked source repository"""
        repo = metadata.get("repository")
        has_repo = bool(repo)

        return {
            "name": "repository_check",
            "description": "No source repository linked"
                           if not has_repo
                           else "Source repository present",
            "flagged": not has_repo,
            "score": 15 if not has_repo else 0,
            "severity": "medium" if not has_repo else "info",
            "details": {"repository": repo}
        }

    def _check_readme(self, metadata):
        """Check if package has a README"""
        readme = metadata.get("readme", "")
        has_readme = bool(readme) and len(readme) > 50

        return {
            "name": "readme_check",
            "description": "No README or very short README"
                           if not has_readme
                           else "README present",
            "flagged": not has_readme,
            "score": 10 if not has_readme else 0,
            "severity": "low" if not has_readme else "info",
            "details": {"readme_length": len(readme) if readme else 0}
        }

    def _check_version_history(self, metadata):
        """Check version history for anomalies"""
        version_count = metadata.get("version_count", 0)
        flagged = version_count <= 1

        return {
            "name": "version_history_check",
            "description": f"Only {version_count} version(s) published"
                           if flagged
                           else f"{version_count} versions published",
            "flagged": flagged,
            "score": 10 if flagged else 0,
            "severity": "medium" if flagged else "info",
            "details": {"version_count": version_count}
        }

    def _check_maintainer_count(self, metadata):
        """Check number of maintainers"""
        count = metadata.get("maintainer_count", 0)
        flagged = count <= 1

        return {
            "name": "maintainer_count_check",
            "description": f"Only {count} maintainer(s)"
                           if flagged
                           else f"{count} maintainers",
            "flagged": flagged,
            "score": 10 if flagged else 0,
            "severity": "low" if flagged else "info",
            "details": {
                "maintainer_count": count,
                "maintainers": metadata.get("maintainers", [])
            }
        }

    def _check_license(self, metadata):
        """Check if package has a license"""
        license_info = metadata.get("license")
        has_license = bool(license_info)

        return {
            "name": "license_check",
            "description": "No license specified"
                           if not has_license
                           else f"License: {license_info}",
            "flagged": not has_license,
            "score": 5 if not has_license else 0,
            "severity": "low" if not has_license else "info",
            "details": {"license": license_info}
        }

    def _check_version_anomaly(self, metadata):
        """
        Check for version anomalies like jumping from 0.0.1 to 99.0.0
        """
        version_history = metadata.get("version_history", {})
        if len(version_history) < 2:
            return {
                "name": "version_anomaly_check",
                "description": "Not enough versions to analyze",
                "flagged": False,
                "score": 0,
                "severity": "info",
                "details": {}
            }

        versions = list(version_history.keys())
        anomalies = []

        for i in range(1, len(versions)):
            prev = versions[i - 1]
            curr = versions[i]
            try:
                prev_parts = [int(x) for x in prev.split(".")[:3]]
                curr_parts = [int(x) for x in curr.split(".")[:3]]

                # Check for major version jump
                if len(prev_parts) >= 1 and len(curr_parts) >= 1:
                    if curr_parts[0] - prev_parts[0] > 10:
                        anomalies.append({
                            "from": prev,
                            "to": curr,
                            "type": "major_version_jump"
                        })
            except (ValueError, IndexError):
                continue

        flagged = len(anomalies) > 0
        return {
            "name": "version_anomaly_check",
            "description": f"Version anomalies detected: {len(anomalies)}"
                           if flagged
                           else "No version anomalies",
            "flagged": flagged,
            "score": 15 if flagged else 0,
            "severity": "high" if flagged else "info",
            "details": {"anomalies": anomalies}
        }