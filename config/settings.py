"""
Global configuration for Supply Chain Guard
"""

import os
import yaml

# ──────────────────────────────────────────────
# BASE DIRECTORIES
# ──────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
ML_MODELS_DIR = os.path.join(BASE_DIR, "ml", "models")

# Create directories if they don't exist
for directory in [DATA_DIR, REPORTS_DIR, ML_MODELS_DIR]:
    os.makedirs(directory, exist_ok=True)

# ──────────────────────────────────────────────
# REGISTRY URLS
# ──────────────────────────────────────────────
NPM_REGISTRY_URL = "https://registry.npmjs.org"
PYPI_REGISTRY_URL = "https://pypi.org/pypi"

# ──────────────────────────────────────────────
# VULNERABILITY DATABASE URLS
# ──────────────────────────────────────────────
OSV_API_URL = "https://api.osv.dev/v1"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"

# ──────────────────────────────────────────────
# SCANNING CONFIGURATION
# ──────────────────────────────────────────────
MAX_DEPENDENCY_DEPTH = 5           # How deep to scan transitive deps
MAX_DEPENDENCIES_TO_SCAN = 20      # Max deps to scan per package
SCAN_TIMEOUT_SECONDS = 30          # Timeout per package scan
PACKAGE_AGE_THRESHOLD_DAYS = 30    # Flag packages newer than this
HIGH_DEPENDENCY_THRESHOLD = 20     # Flag if more deps than this

# ──────────────────────────────────────────────
# RISK SCORE THRESHOLDS
# ──────────────────────────────────────────────
RISK_THRESHOLDS = {
    "MEDIUM": 25,     # MEDIUM starts at 25
    "HIGH": 50,       # HIGH starts at 50
    "CRITICAL": 75    # CRITICAL starts at 75
}

# ──────────────────────────────────────────────
# SUSPICIOUS PATTERNS
# ──────────────────────────────────────────────
SUSPICIOUS_INSTALL_SCRIPTS = [
    "preinstall",
    "postinstall",
    "install",
    "preuninstall",
    "postuninstall"
]

SUSPICIOUS_KEYWORDS = [
    "eval", "exec", "child_process", "spawn",
    "curl", "wget", "bash", "powershell",
    "base64", "atob", "btoa",
    "process.env", "os.environ",
    "socket", "net.connect",
    "crypto", "cipher",
    "fs.writeFile", "fs.readFile",
    "XMLHttpRequest", "fetch(",
    "require('http')", "require('https')",
    "require('net')", "require('dgram')",
    "subprocess", "os.system", "os.popen",
    "__import__", "importlib"
]

DANGEROUS_NODE_MODULES = [
    "child_process", "net", "dgram", "cluster",
    "http", "https", "tls", "vm", "worker_threads"
]

DANGEROUS_PYTHON_MODULES = [
    "subprocess", "os", "sys", "socket",
    "ctypes", "importlib", "code", "codeop",
    "compileall", "eval", "exec"
]

# ──────────────────────────────────────────────
# RISK SCORING WEIGHTS
# ──────────────────────────────────────────────
def load_weights():
    """Load risk scoring weights from YAML config"""
    weights_path = os.path.join(CONFIG_DIR, "weights.yaml")
    if os.path.exists(weights_path):
        with open(weights_path, "r") as f:
            return yaml.safe_load(f)
    else:
        # Default weights
        return {
            "metadata": 0.20,
            "vulnerability": 0.35,
            "code_analysis": 0.30,
            "dependency_graph": 0.15
        }

RISK_WEIGHTS = load_weights()