"""
Behavioral Profiler Module
Creates behavioral fingerprints for packages by analyzing
what operations the code performs: network, filesystem,
process spawning, encoding, environment access, etc.
"""

import ast
import re
from collections import defaultdict


class BehavioralProfiler:
    """
    Generates behavioral fingerprints for packages.
    Categorizes code behavior into risk categories.
    """

    # Behavior categories
    BEHAVIOR_CATEGORIES = {
        "network": {
            "description": "Network communication",
            "keywords_py": [
                "socket", "requests.get", "requests.post",
                "urllib", "http.client", "urlopen",
                "httplib", "ftplib", "smtplib"
            ],
            "keywords_js": [
                "http.request", "https.request", "fetch(",
                "XMLHttpRequest", "axios", "net.connect",
                "dgram", "WebSocket", "socket.io"
            ],
            "weight": 3.0
        },
        "filesystem": {
            "description": "File system operations",
            "keywords_py": [
                "open(", "os.remove", "os.unlink", "shutil",
                "pathlib", "os.makedirs", "os.listdir",
                "glob.glob", "os.walk"
            ],
            "keywords_js": [
                "fs.readFile", "fs.writeFile", "fs.unlink",
                "fs.mkdir", "fs.readdir", "fs.stat",
                "fs.createWriteStream", "fs.createReadStream"
            ],
            "weight": 2.5
        },
        "process_execution": {
            "description": "Process spawning and command execution",
            "keywords_py": [
                "subprocess", "os.system", "os.popen",
                "os.exec", "os.fork", "os.spawn",
                "commands.getoutput"
            ],
            "keywords_js": [
                "child_process", "exec(", "execSync",
                "spawn(", "spawnSync", "fork(",
                "execFile"
            ],
            "weight": 4.0
        },
        "code_execution": {
            "description": "Dynamic code execution",
            "keywords_py": [
                "eval(", "exec(", "compile(", "__import__(",
                "importlib", "execfile"
            ],
            "keywords_js": [
                "eval(", "Function(", "setTimeout(.*,",
                "setInterval(.*,", "vm.runInNewContext",
                "vm.createContext"
            ],
            "weight": 5.0
        },
        "data_encoding": {
            "description": "Data encoding/decoding operations",
            "keywords_py": [
                "base64", "codecs", "binascii",
                "marshal.loads", "pickle.loads",
                "zlib.decompress"
            ],
            "keywords_js": [
                "Buffer.from", "atob(", "btoa(",
                "toString('base64')", "toString('hex')"
            ],
            "weight": 3.0
        },
        "environment_access": {
            "description": "Environment variable and system info access",
            "keywords_py": [
                "os.environ", "os.getenv", "platform.",
                "sys.platform", "getpass", "os.getlogin"
            ],
            "keywords_js": [
                "process.env", "os.hostname", "os.platform",
                "os.userInfo", "os.homedir", "os.tmpdir"
            ],
            "weight": 2.0
        },
        "crypto_operations": {
            "description": "Cryptographic operations",
            "keywords_py": [
                "hashlib", "hmac", "cryptography",
                "Crypto.", "pycryptodome", "rsa"
            ],
            "keywords_js": [
                "crypto.createHash", "crypto.createCipher",
                "crypto.createHmac", "crypto.randomBytes"
            ],
            "weight": 1.5
        },
        "data_exfiltration": {
            "description": "Potential data exfiltration patterns",
            "keywords_py": [
                "requests.post", "urllib.request.urlopen",
                "smtp", "ftplib.FTP",
                "paramiko"
            ],
            "keywords_js": [
                "http.request.*POST", "fetch.*POST",
                "axios.post", "dns.resolve",
                "dgram.createSocket"
            ],
            "weight": 5.0
        }
    }

    def __init__(self):
        pass

    # ──────────────────────────────────────────────
    # PUBLIC API
    # ──────────────────────────────────────────────

    def profile(self, code_content, language="python"):
        """
        Generate a behavioral profile for the given code.
        Returns a fingerprint with behavior counts and risk assessment.
        """
        profile_result = {
            "behaviors": {},
            "fingerprint_vector": {},
            "total_behaviors_detected": 0,
            "dominant_behavior": None,
            "risk_score": 0,
            "risk_assessment": "",
            "behavior_summary": []
        }

        keyword_set = "keywords_py" if language == "python" else "keywords_js"
        code_lower = code_content.lower()

        behavior_scores = {}
        total_detections = 0

        for category, config in self.BEHAVIOR_CATEGORIES.items():
            keywords = config.get(keyword_set, [])
            detections = []

            for keyword in keywords:
                # Handle regex patterns
                try:
                    matches = re.findall(
                        re.escape(keyword).replace(r'\(', r'\('),
                        code_lower
                    )
                    if matches:
                        detections.append({
                            "keyword": keyword,
                            "count": len(matches)
                        })
                except re.error:
                    if keyword.lower() in code_lower:
                        count = code_lower.count(keyword.lower())
                        detections.append({
                            "keyword": keyword,
                            "count": count
                        })

            detection_count = sum(d["count"] for d in detections)
            weighted_score = detection_count * config["weight"]

            profile_result["behaviors"][category] = {
                "description": config["description"],
                "detections": detections,
                "detection_count": detection_count,
                "weighted_score": round(weighted_score, 2)
            }

            profile_result["fingerprint_vector"][category] = detection_count
            behavior_scores[category] = weighted_score
            total_detections += detection_count

            if detection_count > 0:
                profile_result["behavior_summary"].append({
                    "category": category,
                    "description": config["description"],
                    "count": detection_count,
                    "weighted_score": round(weighted_score, 2)
                })

        profile_result["total_behaviors_detected"] = total_detections

        # Find dominant behavior
        if behavior_scores:
            dominant = max(behavior_scores, key=behavior_scores.get)
            if behavior_scores[dominant] > 0:
                profile_result["dominant_behavior"] = dominant

        # Calculate risk score
        total_weighted = sum(behavior_scores.values())
        profile_result["risk_score"] = min(round(total_weighted * 2), 100)

        # Risk assessment
        risk_score = profile_result["risk_score"]
        if risk_score >= 70:
            profile_result["risk_assessment"] = (
                "HIGH - Multiple dangerous behaviors detected. "
                "Package exhibits patterns consistent with malicious activity."
            )
        elif risk_score >= 40:
            profile_result["risk_assessment"] = (
                "MEDIUM - Some concerning behaviors detected. "
                "Manual review recommended."
            )
        elif risk_score >= 15:
            profile_result["risk_assessment"] = (
                "LOW - Minor behavioral indicators found. "
                "Likely benign but worth noting."
            )
        else:
            profile_result["risk_assessment"] = (
                "MINIMAL - No significant behavioral concerns detected."
            )

        # Sort summary by weighted score descending
        profile_result["behavior_summary"].sort(
            key=lambda x: x["weighted_score"],
            reverse=True
        )

        return profile_result

    def compare_profiles(self, profile_a, profile_b):
        """
        Compare two behavioral profiles.
        Useful for detecting if a package changed behavior between versions.
        """
        vector_a = profile_a.get("fingerprint_vector", {})
        vector_b = profile_b.get("fingerprint_vector", {})

        changes = {}
        all_categories = set(list(vector_a.keys()) + list(vector_b.keys()))

        for category in all_categories:
            count_a = vector_a.get(category, 0)
            count_b = vector_b.get(category, 0)

            if count_a != count_b:
                changes[category] = {
                    "before": count_a,
                    "after": count_b,
                    "change": count_b - count_a,
                    "new_behavior": count_a == 0 and count_b > 0,
                    "removed_behavior": count_a > 0 and count_b == 0
                }

        new_behaviors = [
            cat for cat, change in changes.items()
            if change["new_behavior"]
        ]

        risk_increased = (
            profile_b.get("risk_score", 0) > profile_a.get("risk_score", 0)
        )

        return {
            "changes": changes,
            "total_changes": len(changes),
            "new_behaviors": new_behaviors,
            "risk_increased": risk_increased,
            "risk_delta": (
                profile_b.get("risk_score", 0) -
                profile_a.get("risk_score", 0)
            ),
            "suspicious": len(new_behaviors) > 0 and risk_increased
        }