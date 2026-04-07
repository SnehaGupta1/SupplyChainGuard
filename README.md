# 🛡️ SupplyChainGuard

**A Multi-Layered Security Analysis Framework for Software Supply Chain Threat Detection in npm and PyPI Ecosystems**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![React 18](https://img.shields.io/badge/react-18-61dafb.svg)](https://reactjs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

SupplyChainGuard scans software packages **before installation** to detect malicious code, typosquatting attacks, known vulnerabilities, and suspicious behaviors. It protects developers from supply chain attacks by intercepting `pip install` and `npm install` commands.

![Dashboard Screenshot](docs/screenshots/dashboard-overview.png)

## 🎯 Problem

- Anyone can publish packages to npm/PyPI with **zero security review**
- Malicious packages steal credentials, install backdoors, mine crypto
- **245,000+** malicious packages detected in 2023 (Sonatype)
- Traditional tools (`npm audit`, `pip-audit`) scan **after** installation — too late

## ✨ Features

### 6 Detection Modules
| Module | What It Checks |
|--------|---------------|
| **Metadata Analyzer** | 11 trust indicators (author, age, scripts, repo, README, versions, maintainers, license) |
| **Typosquat Detector** | 5 methods — Levenshtein distance, homoglyphs, separator swaps, repeated chars, prefix/suffix |
| **Vulnerability Engine** | Queries OSV (Google) + NVD (NIST) for known CVEs with CVSS severity |
| **Static Code Analyzer** | AST parsing, Shannon entropy, regex patterns, base64/hex payloads, suspicious URLs |
| **Behavioral Profiler** | 8-category fingerprint — network, filesystem, process exec, code exec, encoding, env access, crypto,exfiltration |
| **Dependency Graph** | Transitive dependency tree, betweenness centrality, blast radius |

### 3 Interfaces
- **🌐 Web Dashboard** — React app with interactive charts (8 tabs)
- **💻 CLI Interceptor** — `scg install <pkg>` scans before installing
- **🔗 CI/CD Webhook** — GitHub webhook for automated pipeline scanning

### Risk Scoring
Weighted formula grounded in academic research:
Final = Metadata×0.20 + Vulnerability×0.35 + Code×0.30 + Dependencies×0.15 + Bonuses

Classifies packages: **LOW** (0-24) | **MEDIUM** (25-49) | **HIGH** (50-74) | **CRITICAL** (75-100)

### Additional
- 📋 **SBOM Generation** — CycloneDX 1.5 format
- 🤖 **ML Module** — Isolation Forest + Random Forest anomaly detection
- 📊 **Shell Hooks** — Intercept normal `pip install` / `npm install` transparently

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Node.js 18+ (for dashboard)
- npm or pip

### Installation

```bash
# Clone
git clone https://github.com/yourusername/supply-chain-guard.git
cd supply-chain-guard

# Backend setup
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Frontend setup
cd dashboard
npm install
cd ..

Usage
1. CLI Scanner (Recommended)
bash
# Install as global command
pip install -e .

# Scan and install
scg install express -e npm
scg install requests -e pypi

# Scan only (no install)
scg scan lodash -e npm

# Scan requirements file
scg scan -r requirements.txt -e pypi
scg scan -r package.json -e npm

# Audit current project
scg audit

2. Web Dashboard
bash
# Terminal 1: Start backend
python app.py

# Terminal 2: Start frontend
cd dashboard
npm start

# Open http://localhost:3000
3. Shell Hooks (Intercept pip/npm)
bash
# Install hooks
python cli/setup_hooks.py --install

# Now normal commands are intercepted:
pip install numpy     # → Scanned automatically!
npm install express   # → Scanned automatically!

# Remove hooks
python cli/setup_hooks.py --uninstall

4. API Only
bash
python app.py

# POST http://localhost:5000/api/scan
# Body: {"package_name": "express", "ecosystem": "npm"}
📁 Project Structure
text
supply-chain-guard/
├── config/
│   ├── settings.py          # Global configuration
│   └── weights.yaml         # Risk scoring weights (editable)
├── core/
│   ├── metadata_analyzer.py # Registry metadata analysis
│   ├── typosquat_detector.py# Typosquatting detection
│   ├── vuln_engine.py       # OSV + NVD vulnerability checking
│   ├── static_analyzer.py   # Code analysis (AST + entropy)
│   ├── behavioral_profiler.py# 8-category behavioral fingerprint
│   ├── dependency_graph.py  # Dependency tree analysis
│   ├── risk_scorer.py       # Weighted risk aggregation
│   ├── sbom_generator.py    # CycloneDX 1.5 SBOM
│   └── report_generator.py  # Comprehensive reports
├── api/
│   ├── routes.py            # Flask REST API
│   └── webhook_handler.py   # GitHub webhook
├── cli/
│   ├── installer.py         # scg install/scan/audit
│   └── setup_hooks.py       # Shell hook installer
├── ml/
│   ├── feature_extractor.py # 26-feature vector extraction
│   ├── train_model.py       # Model training
│   └── predict.py           # Prediction
├── dashboard/src/           # React frontend
├── tests/                   # pytest test suite
├── evaluation/              # Benchmark scripts
└── data/                    # Popular packages list

🧪 Testing
bash
# Run all tests
python -m pytest tests/ -v

# Run specific module tests
python -m pytest tests/test_typosquat.py -v
python -m pytest tests/test_metadata.py -v
python -m pytest tests/test_static_analysis.py -v
python -m pytest tests/test_risk_scoring.py -v

# Run benchmark
python evaluation/benchmark.py

# Test malicious sample detection
python -c "
from core.static_analyzer import StaticCodeAnalyzer
analyzer = StaticCodeAnalyzer()
with open('tests/test_scenarios/malicious_sample/malicious.py') as f:
    result = analyzer.scan(f.read(), 'malicious.py', 'python')
print(f'Score: {result[\"risk_score\"]}, Issues: {len(result.get(\"issues\", []))}')"
📊 Benchmark Results
Metric	Result
Packages tested	20 (10 npm + 10 PyPI)
All safe packages classified correctly	✅ 100%
Typosquatting detection accuracy	✅ 100% (10/10)
Average scan time	0.93 seconds
False positive rate	0%
🔬 Academic Foundation
Every scoring weight and threshold is traceable to published research:

Weight	Source
Vulnerability: 0.35	FIRST CVSS v3.1; NIST SP 800-161
Code Analysis: 0.30	Ohm et al. 2020 (DIMVA); Sejfia & Schäfer 2022 (ICSE)
Metadata: 0.20	Duan et al. 2021 (NDSS); OpenSSF Scorecard
Dependencies: 0.15	Zimmermann et al. 2019 (USENIX Security)
See full reference list for all 30 citations.

🛠️ Tech Stack
Backend: Python 3.9+, Flask, NetworkX, scikit-learn
Frontend: React 18, Recharts, Custom SVG
APIs: npm Registry, PyPI, OSV (Google), NVD (NIST)
Standards: CycloneDX 1.5, CVSS v3.1, MITRE CWE