"""
Static Code Analyzer Module
Analyzes package source code without execution.
Uses AST parsing, regex pattern matching, entropy analysis,
and keyword detection to identify malicious patterns.
"""

import ast
import re
import math
import os
from collections import Counter
from config.settings import (
    SUSPICIOUS_KEYWORDS,
    DANGEROUS_PYTHON_MODULES,
    DANGEROUS_NODE_MODULES
)


class StaticCodeAnalyzer:
    """
    Performs static analysis on package source code.
    Supports Python and JavaScript analysis.
    """

    # ──────────────────────────────────────────────
    # PATTERNS FOR DETECTION
    # ──────────────────────────────────────────────

    BASE64_PATTERN = re.compile(
        r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']'
    )

    HEX_PATTERN = re.compile(
        r'["\']((?:\\x[0-9a-fA-F]{2}){10,})["\']'
    )

    URL_PATTERN = re.compile(
        r'https?://[^\s\'"<>]+',
        re.IGNORECASE
    )

    IP_PATTERN = re.compile(
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    )

    SUSPICIOUS_DOMAINS = [
        "pastebin.com", "hastebin.com", "ghostbin.co",
        "ngrok.io", "serveo.net", "localhost.run",
        "burpcollaborator.net",
        ".onion", ".tk", ".ml", ".ga", ".cf"
    ]

    JS_SUSPICIOUS_PATTERNS = [
        (r'\beval\s*\(', "eval() execution"),
        (r'\bFunction\s*\(', "Function() constructor"),
        (r'\bchild_process\b', "child_process module usage"),
        (r'\brequire\s*\(\s*[\'"]child_process[\'"]\s*\)', "child_process require"),
        (r'\brequire\s*\(\s*[\'"]net[\'"]\s*\)', "net module require"),
        (r'\brequire\s*\(\s*[\'"]dgram[\'"]\s*\)', "dgram module require"),
        (r'\brequire\s*\(\s*[\'"]vm[\'"]\s*\)', "vm module require"),
        (r'process\.env', "environment variable access"),
        (r'Buffer\.from\s*\(.*,\s*[\'"]base64[\'"]\)', "base64 buffer decoding"),
        (r'\.exec\s*\(', "exec() call"),
        (r'\.spawn\s*\(', "spawn() call"),
        (r'new\s+WebSocket\s*\(', "WebSocket connection"),
        (r'XMLHttpRequest', "XMLHttpRequest usage"),
        (r'\.download\s*\(', "download function call"),
        (r'fs\.writeFileSync', "synchronous file write"),
        (r'fs\.readFileSync\s*\(.*(/etc/passwd|/etc/shadow)', "sensitive file read"),
    ]

    PY_SUSPICIOUS_PATTERNS = [
        (r'\beval\s*\(', "eval() execution"),
        (r'\bexec\s*\(', "exec() execution"),
        (r'\bcompile\s*\(', "compile() usage"),
        (r'\b__import__\s*\(', "dynamic import"),
        (r'\bsubprocess\b', "subprocess module usage"),
        (r'\bos\.system\s*\(', "os.system() call"),
        (r'\bos\.popen\s*\(', "os.popen() call"),
        (r'\bos\.exec', "os.exec call"),
        (r'\bos\.environ', "environment variable access"),
        (r'\bsocket\.socket\s*\(', "raw socket creation"),
        (r'\bctypes\b', "ctypes FFI usage"),
        (r'\bbase64\.b64decode\s*\(', "base64 decoding"),
        (r'\bcodecs\.decode\s*\(', "codecs decoding"),
        (r'\burllib\.request\.urlopen\s*\(', "URL opening"),
        (r'\brequests\.(get|post)\s*\(', "HTTP request"),
        (r'open\s*\(.*[\'"]w', "file write operation"),
        (r'/etc/passwd|/etc/shadow', "sensitive file reference"),
        (r'\bkeylogger\b|\bkeylog\b', "keylogger reference"),
        (r'\breverse.shell\b|\brev.shell\b', "reverse shell reference"),
    ]

    def __init__(self):
        self.findings = []

    # ──────────────────────────────────────────────
    # PUBLIC API
    # ──────────────────────────────────────────────

    def scan(self, code_content, filename="unknown", language="python"):
        """
        Scan source code content and return analysis results.
        """
        self.findings = []

        result = {
            "filename": filename,
            "language": language,
            "issues": [],
            "risk_score": 0,
            "entropy_score": 0.0,
            "obfuscation_detected": False,
            "encoded_payloads": [],
            "suspicious_urls": [],
            "suspicious_ips": [],
            "dangerous_imports": [],
            "suspicious_function_calls": [],
            "summary": {}
        }

        if not code_content or not code_content.strip():
            result["summary"] = {"total_issues": 0, "note": "Empty code content"}
            return result

        # 1. Entropy Analysis
        result["entropy_score"] = self._calculate_entropy(code_content)
        if result["entropy_score"] > 5.5:
            result["obfuscation_detected"] = True
            self._add_finding(
                "high_entropy",
                f"High code entropy detected: {result['entropy_score']:.2f}",
                "high",
                20
            )

        # 2. Base64 / Hex Encoded Payload Detection
        encoded = self._detect_encoded_payloads(code_content)
        result["encoded_payloads"] = encoded

        # 3. URL and IP Detection
        result["suspicious_urls"] = self._detect_suspicious_urls(code_content)
        result["suspicious_ips"] = self._detect_ips(code_content)

        # 4. Pattern-Based Detection
        if language == "python":
            self._scan_python_patterns(code_content)
        elif language in ["javascript", "js"]:
            self._scan_javascript_patterns(code_content)

        # 5. AST Analysis (Python only)
        if language == "python":
            ast_results = self._analyze_python_ast(code_content)
            result["dangerous_imports"] = ast_results.get("dangerous_imports", [])
            result["suspicious_function_calls"] = ast_results.get(
                "suspicious_calls", []
            )

        # 6. Keyword Analysis
        self._scan_suspicious_keywords(code_content)

        # Aggregate findings
        result["issues"] = self.findings
        result["risk_score"] = self._calculate_code_risk_score()
        result["summary"] = {
            "total_issues": len(self.findings),
            "critical_issues": sum(
                1 for f in self.findings if f["severity"] == "critical"
            ),
            "high_issues": sum(
                1 for f in self.findings if f["severity"] == "high"
            ),
            "medium_issues": sum(
                1 for f in self.findings if f["severity"] == "medium"
            ),
            "low_issues": sum(
                1 for f in self.findings if f["severity"] == "low"
            )
        }

        return result

    def scan_directory(self, directory_path):
        """Scan all relevant files in a directory."""
        results = []
        file_extensions = {
            ".py": "python",
            ".js": "javascript",
            ".mjs": "javascript",
            ".cjs": "javascript",
            ".ts": "javascript"
        }

        if not os.path.exists(directory_path):
            return {"error": f"Directory not found: {directory_path}"}

        for root, dirs, files in os.walk(directory_path):
            dirs[:] = [
                d for d in dirs
                if d not in ["node_modules", ".git", "__pycache__",
                             "venv", ".venv", "env"]
            ]

            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext in file_extensions:
                    filepath = os.path.join(root, filename)
                    try:
                        with open(filepath, "r", encoding="utf-8",
                                  errors="ignore") as f:
                            content = f.read()
                        language = file_extensions[ext]
                        result = self.scan(content, filepath, language)
                        if result["issues"]:
                            results.append(result)
                    except Exception as e:
                        results.append({
                            "filename": filepath,
                            "error": str(e),
                            "issues": []
                        })

        total_issues = sum(len(r.get("issues", [])) for r in results)
        max_risk = max(
            (r.get("risk_score", 0) for r in results),
            default=0
        )

        return {
            "files_scanned": len(results),
            "total_issues": total_issues,
            "max_risk_score": max_risk,
            "file_results": results
        }

    # ──────────────────────────────────────────────
    # ENTROPY ANALYSIS
    # ──────────────────────────────────────────────

    def _calculate_entropy(self, text):
        """
        Calculate Shannon entropy of text.
        Normal code: 4.0-5.0 | Obfuscated/encoded: >5.5
        """
        if not text:
            return 0.0

        freq = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in freq.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    # ──────────────────────────────────────────────
    # ENCODED PAYLOAD DETECTION
    # ──────────────────────────────────────────────

    def _detect_encoded_payloads(self, code):
        """Detect base64 and hex encoded strings in code"""
        payloads = []

        # Base64 detection
        for match in self.BASE64_PATTERN.finditer(code):
            encoded_str = match.group(1)
            if len(encoded_str) >= 40:
                payloads.append({
                    "type": "base64",
                    "value_preview": encoded_str[:50] + "...",
                    "length": len(encoded_str),
                    "position": match.start()
                })
                self._add_finding(
                    "encoded_payload",
                    f"Base64 encoded string detected (length: {len(encoded_str)})",
                    "high",
                    25
                )

        # Hex encoded detection
        for match in self.HEX_PATTERN.finditer(code):
            hex_str = match.group(1)
            payloads.append({
                "type": "hex",
                "value_preview": hex_str[:50] + "...",
                "length": len(hex_str),
                "position": match.start()
            })
            self._add_finding(
                "encoded_payload",
                f"Hex encoded string detected (length: {len(hex_str)})",
                "high",
                25
            )

        return payloads

    # ──────────────────────────────────────────────
    # URL AND IP DETECTION
    # ──────────────────────────────────────────────

    def _detect_suspicious_urls(self, code):
        """Detect URLs in code and flag suspicious domains"""
        urls = self.URL_PATTERN.findall(code)
        suspicious = []

        for url in urls:
            is_suspicious = False
            reason = ""

            for domain in self.SUSPICIOUS_DOMAINS:
                if domain in url.lower():
                    is_suspicious = True
                    reason = f"Suspicious domain: {domain}"
                    break

            if is_suspicious:
                suspicious.append({
                    "url": url[:200],
                    "reason": reason
                })
                self._add_finding(
                    "suspicious_url",
                    f"Suspicious URL found: {url[:100]}",
                    "critical",
                    30
                )

        return suspicious

    def _detect_ips(self, code):
        """Detect hardcoded IP addresses"""
        ips = self.IP_PATTERN.findall(code)
        suspicious_ips = []

        # Filter out common non-suspicious IPs
        safe_ips = ["127.0.0.1", "0.0.0.0", "255.255.255.255",
                     "192.168.", "10.0.", "172.16."]

        for ip in ips:
            is_safe = any(ip.startswith(safe) for safe in safe_ips)
            if not is_safe:
                suspicious_ips.append(ip)
                self._add_finding(
                    "hardcoded_ip",
                    f"Hardcoded external IP address: {ip}",
                    "medium",
                    15
                )

        return suspicious_ips

    # ──────────────────────────────────────────────
    # PATTERN SCANNING
    # ──────────────────────────────────────────────

    def _scan_python_patterns(self, code):
        """Scan for suspicious Python code patterns"""
        for pattern, description in self.PY_SUSPICIOUS_PATTERNS:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                severity = "critical" if any(
                    keyword in description.lower()
                    for keyword in ["eval", "exec", "reverse shell",
                                    "keylogger", "subprocess"]
                ) else "high"

                score = 30 if severity == "critical" else 20

                self._add_finding(
                    "suspicious_pattern",
                    f"{description} (found {len(matches)} occurrence(s))",
                    severity,
                    score
                )

    def _scan_javascript_patterns(self, code):
        """Scan for suspicious JavaScript code patterns"""
        for pattern, description in self.JS_SUSPICIOUS_PATTERNS:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                severity = "critical" if any(
                    keyword in description.lower()
                    for keyword in ["eval", "child_process", "exec",
                                    "spawn", "sensitive file"]
                ) else "high"

                score = 30 if severity == "critical" else 20

                self._add_finding(
                    "suspicious_pattern",
                    f"{description} (found {len(matches)} occurrence(s))",
                    severity,
                    score
                )

    def _scan_suspicious_keywords(self, code):
        """Scan for general suspicious keywords"""
        code_lower = code.lower()
        found = []

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword.lower() in code_lower:
                count = code_lower.count(keyword.lower())
                found.append({"keyword": keyword, "count": count})

        if len(found) > 5:
            self._add_finding(
                "keyword_concentration",
                f"High concentration of suspicious keywords: "
                f"{len(found)} different types found",
                "high",
                20
            )

    # ──────────────────────────────────────────────
    # PYTHON AST ANALYSIS
    # ──────────────────────────────────────────────

    def _analyze_python_ast(self, code):
        """
        Parse Python AST and extract dangerous patterns.
        More reliable than regex for Python code.
        """
        result = {
            "dangerous_imports": [],
            "suspicious_calls": [],
            "parse_error": None
        }

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            result["parse_error"] = str(e)
            return result

        for node in ast.walk(tree):
            # Check imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in DANGEROUS_PYTHON_MODULES:
                        result["dangerous_imports"].append({
                            "module": alias.name,
                            "line": node.lineno,
                            "type": "import"
                        })
                        self._add_finding(
                            "dangerous_import",
                            f"Dangerous module imported: {alias.name} "
                            f"(line {node.lineno})",
                            "high",
                            20
                        )

            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in DANGEROUS_PYTHON_MODULES:
                    result["dangerous_imports"].append({
                        "module": node.module,
                        "line": node.lineno,
                        "type": "from_import"
                    })
                    self._add_finding(
                        "dangerous_import",
                        f"Dangerous module imported: {node.module} "
                        f"(line {node.lineno})",
                        "high",
                        20
                    )

            # Check function calls
            elif isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name:
                    dangerous_calls = [
                        "eval", "exec", "compile", "__import__",
                        "os.system", "os.popen", "os.execvp",
                        "subprocess.call", "subprocess.Popen",
                        "subprocess.run", "subprocess.check_output"
                    ]

                    if func_name in dangerous_calls:
                        result["suspicious_calls"].append({
                            "function": func_name,
                            "line": node.lineno,
                        })
                        self._add_finding(
                            "dangerous_call",
                            f"Dangerous function call: {func_name}() "
                            f"(line {node.lineno})",
                            "critical",
                            35
                        )

        return result

    def _get_call_name(self, node):
        """Extract function name from an ast.Call node"""
        try:
            if isinstance(node.func, ast.Name):
                return node.func.id
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    return f"{node.func.value.id}.{node.func.attr}"
                elif isinstance(node.func.value, ast.Attribute):
                    if isinstance(node.func.value.value, ast.Name):
                        return (f"{node.func.value.value.id}."
                                f"{node.func.value.attr}."
                                f"{node.func.attr}")
        except AttributeError:
            pass
        return None

    # ──────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────

    def _add_finding(self, finding_type, description, severity, score):
        """Add a finding to the results"""
        self.findings.append({
            "type": finding_type,
            "description": description,
            "severity": severity,
            "score": score
        })

    def _calculate_code_risk_score(self):
        """Calculate aggregate risk score from all findings"""
        if not self.findings:
            return 0

        total = sum(f["score"] for f in self.findings)
        return min(total, 100)