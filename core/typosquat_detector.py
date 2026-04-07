"""
Typosquatting Detection Module
Detects if a package name is suspiciously similar to a known popular package.
Uses multiple detection techniques: Levenshtein distance, homoglyph detection,
separator swapping, repeated character detection.
"""

import json
import os
from Levenshtein import distance as levenshtein_distance
from config.settings import DATA_DIR


class TyposquatDetector:
    """
    Multi-technique typosquatting detection engine.
    """

    # Homoglyph character mappings
    HOMOGLYPHS = {
        "o": "0", "0": "o",
        "l": "1", "1": "l",
        "i": "1",
        "rn": "m",
        "vv": "w",
        "cl": "d",
        "nn": "m"
    }

    def __init__(self):
        self.popular_packages = self._load_popular_packages()

    def _load_popular_packages(self):
        """Load known popular package names from data file or defaults"""
        filepath = os.path.join(DATA_DIR, "popular_packages.json")

        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                return json.load(f)

        # Default popular packages if file doesn't exist
        defaults = {
            "npm": [
                "lodash", "express", "react", "axios", "moment",
                "commander", "chalk", "debug", "webpack", "babel-core",
                "typescript", "next", "vue", "angular", "jquery",
                "underscore", "request", "bluebird", "async", "minimist",
                "yargs", "glob", "rimraf", "mkdirp", "semver",
                "uuid", "colors", "inquirer", "ora", "dotenv",
                "cors", "body-parser", "mongoose", "sequelize", "passport",
                "socket.io", "redis", "pg", "mysql", "nodemon",
                "eslint", "prettier", "jest", "mocha", "chai"
            ],
            "pypi": [
                "requests", "numpy", "pandas", "flask", "django",
                "scipy", "tensorflow", "boto3", "pillow", "cryptography",
                "matplotlib", "scikit-learn", "pytest", "setuptools", "pip",
                "urllib3", "certifi", "idna", "chardet", "six",
                "python-dateutil", "pyyaml", "pytz", "jinja2", "markupsafe",
                "werkzeug", "click", "itsdangerous", "packaging", "pyparsing",
                "colorama", "tqdm", "virtualenv", "wheel", "twine",
                "black", "flake8", "mypy", "sqlalchemy", "celery",
                "redis", "psycopg2", "gunicorn", "uvicorn", "fastapi"
            ]
        }

        # Save defaults for future use
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(defaults, f, indent=2)

        return defaults

    # ──────────────────────────────────────────────
    # PUBLIC API
    # ──────────────────────────────────────────────

    def check(self, package_name, ecosystem="npm"):
        """
        Run all typosquatting detection techniques.
        Returns structured result.
        """
        results = {
            "package_name": package_name,
            "ecosystem": ecosystem,
            "is_typosquat_suspect": False,
            "matches": [],
            "techniques_triggered": [],
            "closest_legitimate": None,
            "min_distance": None,
            "risk_score": 0,
            "details": {}
        }

        popular = self.popular_packages.get(ecosystem, [])

        # If the package IS a known popular package, skip
        if package_name.lower() in [p.lower() for p in popular]:
            results["details"]["note"] = "Package is a known popular package"
            return results

        all_matches = []

        for legit_pkg in popular:
            match_result = self._compare_package(package_name, legit_pkg)
            if match_result["is_similar"]:
                all_matches.append(match_result)

        if all_matches:
            results["is_typosquat_suspect"] = True
            results["matches"] = all_matches

            # Find closest match
            best = min(all_matches, key=lambda x: x["distance"])
            results["closest_legitimate"] = best["legitimate_package"]
            results["min_distance"] = best["distance"]

            # Collect triggered techniques
            techniques = set()
            for m in all_matches:
                techniques.update(m["techniques"])
            results["techniques_triggered"] = list(techniques)

            # Calculate risk score based on similarity
            if best["distance"] == 1:
                results["risk_score"] = 40
            elif best["distance"] == 2:
                results["risk_score"] = 25
            else:
                results["risk_score"] = 15

            # Boost score if multiple techniques triggered
            if len(results["techniques_triggered"]) > 1:
                results["risk_score"] += 10

        return results

    # ──────────────────────────────────────────────
    # COMPARISON ENGINE
    # ──────────────────────────────────────────────

    def _compare_package(self, suspect, legitimate):
        """
        Compare a suspect package name against a legitimate one
        using multiple techniques.
        """
        result = {
            "suspect_package": suspect,
            "legitimate_package": legitimate,
            "is_similar": False,
            "distance": 999,
            "techniques": []
        }

        # 1. Levenshtein Distance
        dist = levenshtein_distance(suspect.lower(), legitimate.lower())
        result["distance"] = dist

        if 0 < dist <= 2:
            result["is_similar"] = True
            result["techniques"].append("levenshtein")

        # 2. Separator Swapping
        if self._separator_swap_check(suspect, legitimate):
            result["is_similar"] = True
            result["techniques"].append("separator_swap")
            result["distance"] = min(result["distance"], 1)

        # 3. Repeated/Missing Character
        if self._repeated_char_check(suspect, legitimate):
            result["is_similar"] = True
            result["techniques"].append("repeated_char")
            result["distance"] = min(result["distance"], 1)

        # 4. Homoglyph Detection
        if self._homoglyph_check(suspect, legitimate):
            result["is_similar"] = True
            result["techniques"].append("homoglyph")
            result["distance"] = min(result["distance"], 1)

        # 5. Prefix/Suffix Addition
        if self._prefix_suffix_check(suspect, legitimate):
            result["is_similar"] = True
            result["techniques"].append("prefix_suffix")
            result["distance"] = min(result["distance"], 2)

        return result

    def _separator_swap_check(self, suspect, legitimate):
        """Detect separator swapping: python-utils vs python_utils vs pythonutils"""
        clean_suspect = suspect.replace("-", "").replace("_", "").replace(".", "").lower()
        clean_legit = legitimate.replace("-", "").replace("_", "").replace(".", "").lower()
        return clean_suspect == clean_legit and suspect.lower() != legitimate.lower()

    def _repeated_char_check(self, suspect, legitimate):
        """Detect added/removed characters: requsets vs requests"""
        if abs(len(suspect) - len(legitimate)) != 1:
            return False

        longer = suspect if len(suspect) > len(legitimate) else legitimate
        shorter = suspect if len(suspect) < len(legitimate) else legitimate

        diffs = 0
        j = 0
        for i in range(len(longer)):
            if j < len(shorter) and longer[i].lower() == shorter[j].lower():
                j += 1
            else:
                diffs += 1

        return diffs <= 1 and suspect.lower() != legitimate.lower()

    def _homoglyph_check(self, suspect, legitimate):
        """Detect character substitution using visually similar characters"""
        normalized = suspect.lower()
        for fake, real in self.HOMOGLYPHS.items():
            normalized = normalized.replace(fake, real)

        return normalized == legitimate.lower() and suspect.lower() != legitimate.lower()

    def _prefix_suffix_check(self, suspect, legitimate):
        """Detect common prefix/suffix attacks: react-native vs react-nativee"""
        suspect_lower = suspect.lower()
        legit_lower = legitimate.lower()

        # Check if suspect is legit + common suffix/prefix
        common_additions = [
            "-js", "-node", "-cli", "-api", "-lib", "-utils",
            "-core", "-dev", "-pro", "js-", "node-", "py-"
        ]

        for addition in common_additions:
            if suspect_lower == legit_lower + addition:
                return True
            if suspect_lower == addition.lstrip("-") + "-" + legit_lower:
                return True

        return False