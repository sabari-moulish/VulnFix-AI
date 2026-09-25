# 🛡️ VulnFix AI

## AI-Powered Vulnerability Validation & Proof-of-Fix Platform

**Track:** Offensive Security & Red Teaming
**Security Model:** Authorized, local, intentionally vulnerable environments only

VulnFix AI is a security validation platform designed to bridge the gap between **vulnerability discovery and verified remediation**.

Instead of stopping at a potential vulnerability, the platform follows the complete security lifecycle:

> **Authorized Target → Discovery → Detection → Validation → Evidence → Risk Assessment → Remediation → Proof-of-Fix**

The platform safely validates vulnerabilities in authorized local test environments, generates reproducible evidence, assesses contextual risk, provides remediation guidance, and retests the application to verify whether the vulnerability has actually been fixed.

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

### Core capabilities

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

   * Retests confirmed findings after remediation.
   * Reports whether the vulnerability remains exploitable or has been successfully fixed.

---

# 🔒 Strict Scope & Safety

VulnFix AI is designed exclusively for **authorized security testing**.

The included demonstration environment is a deliberately vulnerable Flask application running locally at:

```text
http://127.0.0.1:5000
```

### Allowed targets

The scope controller permits local loopback targets such as:

```text
localhost
127.0.0.1
::1
```

### Blocked targets

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
                         │  Local Test App     │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │  Scope Controller   │
                         │    Gatekeeper       │
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
                         │ Detection            │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │     Validation      │
                         │ Controlled Probes   │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │      Evidence       │
                         │ SQLite + JSON       │
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

A finding becomes useful to the security workflow only when there is reproducible evidence supporting the vulnerability hypothesis.

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

The system supports severity levels:

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

### Vulnerabilities demonstrated

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
Unsafe dynamic SQL
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

```bash
pytest -v
```

Current validation status:

```text
92 / 92 tests passed
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

```bash
git clone git@github.com:sabari-moulish/VulnFix-AI.git
cd VulnFix-AI
```

For HTTPS users:

```bash
git clone https://github.com/sabari-moulish/VulnFix-AI.git
cd VulnFix-AI
```

---

## 3. Create a Virtual Environment

### Windows

```bash
python -m venv venv
.\venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 4. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 5. Run Tests

```bash
pytest -v
```

Expected result:

```text
92 passed
```

---

# ▶️ Running the Platform

Start the intentionally vulnerable laboratory application:

```bash
python lab_app/app.py
```

The laboratory will be available at:

```text
http://127.0.0.1:5000
```

In another terminal, start the VulnFix AI dashboard:

```bash
streamlit run app.py
```

The dashboard will normally be available at:

```text
http://localhost:8501
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
 → Validation
 → Risk
 → Remediation
 → Proof-of-Fix
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

VulnFix AI directly addresses the track's security validation workflow:

| Track Requirement | VulnFix AI                                  |
| ----------------- | ------------------------------------------- |
| Authorized target | Local intentionally vulnerable Flask lab    |
| Discovery         | Endpoint and input discovery                |
| Validation        | Controlled deterministic validation         |
| Evidence          | SQLite + JSON evidence                      |
| Risk assessment   | Contextual exploitability/impact/confidence |
| Remediation       | Vulnerability-specific defensive guidance   |
| Verification      | Automated proof-of-fix retesting            |
| Safety            | Strict scope controller and audit logging   |

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

The result is a closed-loop security workflow that helps demonstrate not only **"a vulnerability exists"**, but also:

> **"Here is the evidence, here is the risk, here is how to fix it, and here is proof that the fix worked."**

---

## 📜 License

This project was developed as a hackathon security research and demonstration project.

Use only in authorized environments.
