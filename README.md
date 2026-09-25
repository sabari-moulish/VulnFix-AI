# AI-Powered Vulnerability Validation and Proof-of-Fix Platform

**Track:** Offensive Security & Red Teaming  
**Environment:** Exclusively for authorized, local, intentionally vulnerable test applications.

---

## 🛡️ Executive Summary & Purpose

In modern AppSec and Red Teaming workflows, security teams are overwhelmed by thousands of unvalidated scanner findings, high false-positive rates, and unclear remediation guidance. 

The **AI-Powered Vulnerability Validation and Proof-of-Fix Platform** bridges this gap by:
1. **Safely Validating Findings**: Deterministically verifying vulnerability hypotheses against local test environments without destructive actions.
2. **Filtering Noise**: Distinguishing genuine exploitable flaws from benign anomalies and false positives.
3. **AI-Powered Root-Cause & Patch Generation**: Suggesting contextual, secure code diffs and defensive remediations.
4. **Automated Proof-of-Fix Retesting**: Executing post-patch verification probes to certify that the vulnerability was successfully neutralized without regressions.

---

## ⚠️ Strict Scope & Safety Boundaries

> **MANDATORY POLICY NOTICE:**  
> This platform is engineered strictly for **explicitly authorized, local testbeds** (`localhost`, `127.0.0.1`, `::1`).  
> **Internet-wide scanning, remote network targeting, credential theft, persistence, malware installation, data exfiltration, or uncontrolled exploitation are strictly prohibited and locked out by the architecture.**

### Scope Enforcement & Target Management Mechanism
Every operation in the pipeline passes through `modules/scope_controller.py`. The controller strictly enforces:
- **Default Targets**: Allows only local loopback targets (`http://127.0.0.1`, `http://localhost`, and standard development ports).
- **Target Authorization & Selection**: Interactive UI to select the active local target and dynamically authorize new local testbeds with safety validation.
- **Strict Boundary Guard**: Blocks remote hostnames, public IP addresses, non-loopback LAN addresses, and cloud metadata (`169.254.169.254`).
- **Cryptographic & Persistent Audit Log**: Every scope check, target selection, and operation is permanently recorded in SQLite (`scope_audit_logs`) and JSON (`data/scope_audit_log.json`) with timestamps, target URLs, operation types, allowed/rejected decisions, and rationale.
- **Operation Enforcement**: All security stages (discovery, detection, validation, retest) must call `authorize_operation` before network communication.

---

## 🧩 Architecture & Directory Structure

```text
├── app.py                     # Streamlit web dashboard & interactive landing page
├── config.py                  # Global settings, allowed ports/hosts, and SQLite setup
├── requirements.txt           # Python dependencies
├── README.md                  # Documentation and execution instructions
│
├── modules/                   # Decoupled core pipeline components
│   ├── __init__.py
│   ├── scope_controller.py    # Strict boundary guard (localhost/127.0.0.1 validation)
│   ├── discovery.py           # Safe local endpoint & route identification
│   ├── vulnerability_detector.py # Pattern & signature detection for local testbeds
│   ├── validator.py           # Deterministic proof-of-concept verification
│   ├── evidence.py            # Evidence logging & SQLite persistence
│   ├── risk_engine.py         # Severity weighting and contextual scoring
│   ├── remediation.py         # Defensive fix recommendations and code patches
│   ├── retest.py              # Proof-of-fix verification engine
│   └── ai_analyzer.py         # AI-assisted root-cause diagnosis
│
├── data/                      # Persistent storage and logs
│   ├── findings/              # Raw findings and candidate JSON files
│   ├── evidence/              # Request/response dumps and proof artifacts
│   ├── reports/               # Generated validation and audit reports
│   └── platform.db            # SQLite database for structured tracking
│
└── tests/                     # Unit and integration test suite
    ├── __init__.py
    └── test_scope_controller.py # Comprehensive tests for scope boundaries
```

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.10+ installed
- Virtual environment (recommended)

### 2. Setup Virtual Environment
```bash
python -m venv venv

# On Windows:
.\venv\Scripts\activate

# On Linux/macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Test Suite
Execute the automated test suite to ensure strict scope boundaries and module integrity:
```bash
pytest -v
```

### 5. Launch the Streamlit Platform Dashboard
```bash
streamlit run app.py
```
Once started, open your browser at `http://localhost:8501` to view:
- Platform track classification and mission overview
- Mandatory authorization and safety warnings
- Live interactive **Target & Scope Controller**
- Modular architecture walkthrough and database connectivity status

---

## 🔄 Pipeline Workflow

```mermaid
flowchart LR
    A["Target Input"] --> B["modules/scope_controller.py<br/>(Gatekeeper)"]
    B -->|Passed (localhost)| C["modules/discovery.py<br/>(Endpoint Map)"]
    B -->|Failed| X["BLOCKED (Scope Violation)"]
    C --> D["modules/vulnerability_detector.py<br/>(Flaw Hypotheses)"]
    D --> E["modules/validator.py<br/>(Deterministic Safe Probing)"]
    E --> F["modules/evidence.py<br/>(SQLite / JSON Artifacts)"]
    F --> G["modules/risk_engine.py<br/>(Contextual Scoring)"]
    G --> H["modules/remediation.py<br/>& ai_analyzer.py"]
    H --> I["modules/retest.py<br/>(Proof-of-Fix Certification)"]
```

---

## 👥 Hackathon Track Alignment
- **Track**: Offensive Security & Red Teaming
- **Theme**: AI-driven adversarial validation paired with automated defensive remediation to close the feedback loop between discovery and patch verification.

