# 🛡️ VulnFix AI

## Vulnerability Validation & Proof-of-Fix Platform

**Track:** Offensive Security & Red Teaming

**Security Model:** Authorized, local, intentionally vulnerable environments only

VulnFix AI is an intelligent security validation platform designed to bridge the gap between **vulnerability discovery and verified remediation**.

Instead of stopping at a potential vulnerability, the platform follows the complete security lifecycle:

> **Authorized Target → Discovery → Detection → Validation → Evidence → Risk Assessment → Remediation → Proof-of-Fix**

The platform safely validates vulnerabilities in authorized local test environments, generates reproducible evidence, assesses contextual risk, provides remediation guidance, and retests the application to verify whether the vulnerability has actually been fixed.

---

# 📊 Key Results

| Verified Metric | Result |
| --------------- | -----: |
| Automated tests | **99/99 passed** |
| Endpoints discovered | **16** |
| Controllable inputs | **9** |
| Vulnerabilities validated | **6/6** |
| Vulnerability classes | **3** — SQLi, Reflected XSS, IDOR |
| Evaluation cases | **5/5 passed** |
| Proof-of-fix | **6/6 FIXED_VERIFIED** |
| Confirmed vulnerabilities after secure-state retest | **0** |

These results are from the included local laboratory and automated evaluation suite.

---

## 🎯 Problem Statement

Traditional vulnerability scanners can produce large numbers of findings that still require manual investigation.

Security teams need to answer several questions:

* Is the detected issue actually exploitable?
* Can the vulnerability be reproduced?
* What evidence proves the issue?
* How severe is the vulnerability in its current context?
* What should developers change?
* Did the remediation actually fix the problem?

VulnFix AI addresses this gap by connecting **detection, validation, evidence, risk assessment, remediation, and verification** into one controlled workflow.

---

## 💡 Our Solution

VulnFix AI provides an end-to-end vulnerability validation workflow.

### Core Capabilities

1. **Authorized Target Validation**

   * Accepts only explicitly authorized local targets.
   * Enforces strict scope boundaries before network communication.

2. **Safe Discovery**

   * Maps available endpoints, routes, forms, links, APIs, and controllable inputs.
   * Uses bounded requests and same-origin restrictions.

3. **Vulnerability Detection**

   * Identifies potential SQL Injection, Reflected XSS, and IDOR findings.
   * Creates structured vulnerability candidates.

4. **Controlled Validation**

   * Performs deterministic and bounded validation probes.
   * Distinguishes potential findings from confirmed vulnerabilities.

5. **Evidence Collection**

   * Records reproducible request/response evidence.
   * Stores structured evidence in SQLite and JSON artifacts.

6. **Contextual Risk Assessment**

   * Evaluates exploitability, impact, confidence, and validation status.
   * Produces a contextual risk score and severity/priority.

7. **Contextual Remediation**

   * Generates root-cause information, remediation guidance, CWE mapping, code-level fixes, and verification steps.

8. **Proof-of-Fix Retesting**

   * Retests findings after remediation.
   * Reports whether the vulnerability remains reproducible or has been successfully fixed.

---

# 🔒 Strict Scope & Safety

VulnFix AI is designed exclusively for **authorized security testing**.

The included demonstration environment is a deliberately vulnerable Flask application running locally at:

```text
http://127.0.0.1:5000
```

### Allowed Targets

The scope controller permits local loopback targets such as:

```text
localhost
127.0.0.1
::1
```

### Blocked Targets

The platform is designed to reject:

* Public internet targets
* Remote organizations and websites
* Public IP addresses
* Non-loopback LAN targets
* Cloud metadata endpoints
* Unauthorized targets
* Out-of-scope operations

The architecture also prevents uncontrolled security testing and does not provide functionality for:

* Credential theft
* Persistence
* Malware installation
* Data exfiltration
* Uncontrolled exploitation
* Internet-wide scanning

Every security operation must pass through the scope authorization layer before network communication.

---

# 🏗️ Architecture

```text
                         ┌─────────────────────┐
                         │   Authorized Target │
                         │   Local Test App    │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │  Scope Controller   │
                         │     Gatekeeper      │
                         └──────────┬──────────┘
                                    │
                             Scope Approved
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │     Discovery       │
                         │ Endpoint & Input Map│
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Vulnerability       │
                         │ Detection           │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │     Validation      │
                         │  Controlled Probes  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │      Evidence       │
                         │    SQLite + JSON    │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Risk Assessment   │
                         │ Exploitability      │
                         │ Impact + Confidence │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │     Remediation     │
                         │ Guidance + Patches  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │       Retest        │
                         │    Proof-of-Fix     │
                         └─────────────────────┘
```

---

![VulnFix AI Architecture](Architecture%20%26%20Workflow%20Diagram.png)

The diagram shows the controlled end-to-end security validation pipeline:

**Authorized Target → Scope Controller → Discovery → Detection → Validation → Evidence → Risk Assessment → Remediation → Retest / Proof-of-Fix → Security Outcome**

The Scope Controller acts as the safety gate, enforcing authorized local targets, approved ports, bounded requests, and controlled execution before validation begins.

---


# 🖼️ Screenshots & Visual Walkthrough

### Architecture & Workflow

![VulnFix AI Architecture](Architecture%20%26%20Workflow%20Diagram.png)

The architecture view shows the controlled pipeline from **Authorized Target → Scope Controller → Discovery → Detection → Validation → Evidence → Risk Assessment → Remediation → Retest / Proof-of-Fix → Security Outcome**.

> **Dashboard screenshots:** The repository currently contains the architecture visual. Additional dashboard screenshots can be added here once captured from the running Streamlit UI (pipeline, findings/evidence, risk/remediation, and proof-of-fix).

# 🎬 Quick Demo

1. Start the local intentionally vulnerable Flask lab.
2. Start the Streamlit dashboard.
3. Select the authorized `127.0.0.1:5000` target.
4. Run the end-to-end validation pipeline.
5. Review SQL Injection, Reflected XSS, and IDOR evidence.
6. Review contextual risk scores and remediation guidance.
7. Apply the secure configuration/remediation and run the retest.
8. Confirm the findings transition to `FIXED_VERIFIED`.

Dashboard:

```text
http://localhost:8502
```

The demo is designed to show the full loop from **discovery → validation → evidence → remediation → proof-of-fix**, rather than detection alone.

---

# 🤖 AI-Assisted Approach

VulnFix AI uses an **AI-assisted security validation approach** combined with deterministic security controls.

The platform applies contextual analysis to findings, evidence collection, risk assessment, remediation guidance, and proof-of-fix verification. Safety-critical behavior remains bounded by deterministic controls such as:

* Authorized-target validation
* Local-only scope enforcement
* Approved-port checks
* Request limits
* Audit logging
* Non-destructive execution

This keeps the AI-assisted workflow useful while maintaining predictable security boundaries.

---

# 🔄 Security Validation Workflow

VulnFix AI follows an eight-stage workflow:

### 1. Authorized Target

The target must first pass the scope controller.

```text
Target → Scope Evaluation → ALLOWED / BLOCKED
```

### 2. Discovery

The discovery engine maps:

* Endpoints
* Routes
* Forms
* API routes
* Links
* Query parameters
* Path parameters
* Controllable inputs

### 3. Detection

The vulnerability detector analyzes discovered inputs and creates structured finding candidates.

The demonstration environment includes:

* SQL Injection
* Reflected XSS
* IDOR / Broken Access Control

### 4. Validation

Potential findings are subjected to controlled validation.

A finding becomes useful to the security workflow when reproducible evidence supports the vulnerability hypothesis.

### 5. Evidence

The platform stores security evidence including:

* Target information
* Endpoint
* Parameter
* Validation result
* Request/response information
* Timestamp
* Finding information

Evidence is persisted through SQLite and JSON artifacts.

### 6. Risk Assessment

The risk engine considers:

```text
Exploitability
      +
Impact
      +
Confidence
      +
Validation Status
      ↓
Contextual Risk Score
      ↓
Severity + Priority
```

The system supports:

| Risk Score | Severity   | Priority |
| ---------: | ---------- | -------- |
| 9.0 – 10.0 | Critical   | P1       |
|  7.0 – 8.9 | High       | P2       |
|  4.0 – 6.9 | Medium     | P3       |
|      < 4.0 | Low / Info | P4       |

### 7. Remediation

For each validated finding, the platform generates contextual remediation information including:

* Root cause
* CWE classification
* Security guidance
* Code-level remediation
* Verification steps
* Remediation priority

### 8. Proof-of-Fix

After remediation, the same finding can be retested.

The platform reports:

```text
FIXED_VERIFIED
STILL_VULNERABLE
INCONCLUSIVE
BLOCKED_OUT_OF_SCOPE
```

This creates a measurable security feedback loop:

```text
Vulnerability
     ↓
Evidence
     ↓
Remediation
     ↓
Retest
     ↓
Proof-of-Fix
```

---

# 🧪 Demonstration Environment

The project includes an intentionally vulnerable Flask laboratory application.

### Vulnerabilities Demonstrated

| Vulnerability | Example Endpoint   |
| ------------- | ------------------ |
| SQL Injection | `/sqli?query=`     |
| SQL Injection | `/api/search?q=`   |
| Reflected XSS | `/xss?name=`       |
| Reflected XSS | `/api/greet?name=` |
| IDOR          | `/record/<id>`     |
| IDOR          | `/api/record/<id>` |

The laboratory application supports two modes:

```text
VULNERABLE
     ↓
Security Validation
     ↓
STILL_VULNERABLE
```

After applying the secure configuration:

```text
SECURE
     ↓
Security Retest
     ↓
FIXED_VERIFIED
```

---

# 📊 Demonstrated Results

The complete end-to-end demonstration successfully produced:

| Stage                              |                   Result |
| ---------------------------------- | -----------------------: |
| Endpoints discovered               |                       16 |
| Controllable inputs                |                        9 |
| Vulnerability candidates confirmed |                        6 |
| Vulnerability types                | SQL Injection, XSS, IDOR |
| Peak contextual risk               |              10.0 / 10.0 |
| Remediation plans generated        |                        6 |
| Vulnerable-state retests           |                        6 |
| Secure-state retests               |                        6 |
| Final proof-of-fix results         |       6 `FIXED_VERIFIED` |

The demonstrated findings covered both web and API endpoints.

---

# 🧩 Project Structure

```text
VulnFix-AI/
│
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── modules/
│   ├── __init__.py
│   ├── scope_controller.py
│   ├── discovery.py
│   ├── vulnerability_detector.py
│   ├── validator.py
│   ├── evidence.py
│   ├── risk_engine.py
│   ├── remediation.py
│   └── retest.py
│
├── lab_app/
│   ├── app.py
│   ├── database.py
│   ├── schema.sql
│   ├── templates/
│   └── static/
│
├── data/
│   ├── findings/
│   ├── evidence/
│   └── reports/
│
└── tests/
    ├── test_scope_controller.py
    ├── test_lab_app.py
    ├── test_discovery.py
    ├── test_vulnerability_detector.py
    ├── test_validator.py
    ├── test_risk_engine.py
    ├── test_remediation.py
    └── test_retest.py
```

---

# 🛡️ Scope Controller

`modules/scope_controller.py` acts as the security gatekeeper.

Before a security operation is performed, the controller evaluates:

* Host
* Port
* Protocol
* Target authorization
* Operation type
* Scope restrictions

Every decision is recorded in the audit system.

The platform maintains scope information through:

```text
SQLite
+
JSON audit log
```

This provides an auditable record of allowed and rejected operations.

---

# 🧠 Risk Assessment Engine

The risk engine combines multiple factors instead of relying only on vulnerability type.

### Exploitability

Factors include:

* Vulnerability type
* API endpoint presence
* Query/path parameters
* Validation evidence

### Impact

Factors include:

* Vulnerability type
* Cross-tenant exposure
* Structured data leakage

### Confidence

Confidence is influenced by:

* Validation results
* Response differentials
* Multiple probe traces
* Actionable evidence

The final score combines:

```text
Exploitability
      +
Impact
      +
Confidence
      +
Validation Multiplier
      ↓
Contextual Risk Score
```

This allows the same vulnerability category to receive different contextual assessments depending on the evidence and application behavior.

---

# 🔧 Remediation Engine

The remediation engine provides vulnerability-specific defensive guidance.

### SQL Injection

**CWE-89**

Recommended approach:

```text
Unsafe Dynamic SQL
        ↓
Parameterized Query
```

### Reflected XSS

**CWE-79**

Recommended approach:

```text
Untrusted Input
        ↓
Context-Aware Output Encoding
        ↓
Safe Rendering
```

### IDOR / Broken Access Control

**CWE-639**

Recommended approach:

```text
User Request
     ↓
Authorization Check
     ↓
Tenant / Ownership Verification
     ↓
Authorized Resource
```

Each remediation plan also includes verification steps for retesting.

---

# 🧪 Automated Testing

The project includes unit and integration tests covering the major security components.

Run:

```cmd
.\venv\Scripts\python.exe -m pytest -q
```

Current validation status:

```text
99 / 99 tests passed
```

The tests cover:

* Scope enforcement
* Laboratory application
* Discovery
* Vulnerability detection
* Validation
* Risk assessment
* Remediation
* Retesting
* AI Defense Lab 5-case evaluation suite

---

# 📊 Evaluation Results

VulnFix AI includes a standardized evaluation suite covering the 5 core evaluation cases from the AI Defense Lab framework. All 5 cases are dynamically evaluated from actual security-control execution, including scope enforcement, deterministic validation, and rate limiting:

* **Normal: PASS** — Legitimate requests to authorized local endpoints operate successfully with HTTP 200 and expected data.
* **Attack/Positive: PASS** — Controlled vulnerabilities across all 3 classes are detected and validated with reproducible evidence.
* **Negative: PASS** — Benign inputs produce zero false positives; remediated secure mode safely neutralizes attack probes.
* **Failure: PASS** — Out-of-scope, malformed, and unreachable targets are safely handled with zero unauthorized network traffic.
* **Adversarial: PASS** — Malformed and evasive inputs (SSRF to cloud metadata `169.254.169.254`, public IP `8.8.8.8`, arbitrary scheme `file://`, unauthorized port `22`, and scan flooding) cannot bypass scope controls or rate limits.

### 📈 Verified Platform Telemetry

* **99/99 tests passed** across all security engines and evaluation modules
* **16 endpoints discovered** across application routes, APIs, and forms
* **9 controllable inputs** mapped for targeted evaluation
* **6/6 vulnerabilities validated** with deterministic differential evidence
* **3 vulnerability classes** evaluated (SQLi CWE-89, Reflected XSS CWE-79, IDOR CWE-639)
* **6/6 FIXED_VERIFIED after remediation** confirmed through proof-of-fix retesting

---

# 🚀 Getting Started

## 1. Prerequisites

Install:

* Python 3.10+
* Git
* A modern web browser

A Python virtual environment is recommended.

---

## 2. Clone the Repository

### SSH

```cmd
git clone git@github.com:sabari-moulish/VulnFix-AI.git
cd VulnFix-AI
```

### HTTPS

```cmd
git clone https://github.com/sabari-moulish/VulnFix-AI.git
cd VulnFix-AI
```

---

## 3. Create a Virtual Environment

### Windows

```cmd
python -m venv venv
```

> **Windows PowerShell note:** Some systems may block `Activate.ps1` because of execution-policy restrictions. Activation is not required for this project. The commands below directly use the Python executable inside the virtual environment.

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 4. Install Dependencies

### Windows

```cmd
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Linux / macOS

```bash
pip install -r requirements.txt
```

---

## 5. Run Tests

### Windows

```cmd
.\venv\Scripts\python.exe -m pytest -q
```

### Linux / macOS

```bash
pytest -q
```

Expected result:

```text
99 passed
```

---

# ▶️ Running the Platform

## Step 1 — Start the Laboratory Application

Open a terminal in the project directory:

```cmd
cd /d D:\VulnFix-AI
```

Start the intentionally vulnerable Flask laboratory:

```cmd
.\venv\Scripts\python.exe -m lab_app.app
```

The laboratory will be available at:

```text
http://127.0.0.1:5000
```

Keep this terminal running.

---

## Step 2 — Start the VulnFix AI Dashboard

Open a **second terminal**:

```cmd
cd /d D:\VulnFix-AI
```

Start Streamlit on port **8502**:

```cmd
.\venv\Scripts\python.exe -m streamlit run app.py --server.port 8502
```

The dashboard will be available at:

```text
http://localhost:8502
```

---

# 🖥️ Dashboard

The Streamlit dashboard provides three primary areas:

### 🚀 End-to-End Pipeline

Runs and visualizes the complete security workflow:

```text
Scope
  ↓
Discovery
  ↓
Detection
  ↓
Validation
  ↓
Risk
  ↓
Remediation
  ↓
Retest
```

### 🔍 Finding Lifecycle Center

Allows investigation of an individual finding across:

```text
Detection
    →
Validation
    →
Risk
    →
Remediation
    →
Proof-of-Fix
```

### 🔒 Scope Governance & Audit

Provides visibility into:

* Authorized targets
* Scope decisions
* Scope audit logs
* Safety boundaries
* Architecture

---

# 🔐 Security Design Principles

VulnFix AI follows these principles:

* **Authorization before action**
* **Local-only demonstration**
* **Bounded requests**
* **Controlled validation**
* **Evidence-backed decisions**
* **Human-visible security outcomes**
* **Auditable scope decisions**
* **No uncontrolled exploitation**
* **Proof-of-fix instead of detection-only reporting**

The goal is not exploitation for its own sake.

The goal is:

> **Find → Prove → Prioritize → Fix → Verify**

---

# 🏆 Hackathon Track Alignment

**Track:** Offensive Security & Red Teaming

VulnFix AI addresses the required security validation workflow:

| Track Requirement | VulnFix AI                                      |
| ----------------- | ----------------------------------------------- |
| Authorized target | Local intentionally vulnerable Flask lab        |
| Discovery         | Endpoint and input discovery                    |
| Validation        | Controlled deterministic validation             |
| Evidence          | SQLite + JSON evidence                          |
| Risk assessment   | Contextual exploitability / impact / confidence |
| Remediation       | Vulnerability-specific defensive guidance       |
| Verification      | Automated proof-of-fix retesting                |
| Safety            | Strict scope controller and audit logging       |

---

# ⚠️ Limitations

* Designed for authorized local security validation and intentionally vulnerable lab environments.
* The current demonstration focuses on SQL Injection, Reflected XSS, and IDOR / Broken Access Control.
* Validation is demonstrated against the included vulnerable Flask laboratory application.
* The platform is not intended to replace a full production penetration test, enterprise DAST/SAST platform, or comprehensive security assessment.
* Results depend on the configured laboratory, validation rules, and available evidence.

---

# ⚠️ Responsible Use

This project is intended for:

* Security education
* Authorized penetration testing
* Local application security testing
* Controlled vulnerability research
* Defensive security validation

Only test applications and systems for which you have explicit authorization.

Do not use this project to scan or attack third-party systems, public infrastructure, accounts, or organizations without authorization.

---

# 📌 Project Summary

**VulnFix AI** is an authorized security validation platform that goes beyond vulnerability detection.

It connects:

```text
Discovery
    ↓
Validation
    ↓
Evidence
    ↓
Risk
    ↓
Remediation
    ↓
Proof-of-Fix
```

The result is a closed-loop security workflow that helps demonstrate not only:

> **"A vulnerability exists."**

but also:

> **"Here is the evidence, here is the risk, here is how to fix it, and here is proof that the fix worked."**

---

## 📜 License

This project was developed as a hackathon security research and demonstration project.

Use only in authorized environments.
