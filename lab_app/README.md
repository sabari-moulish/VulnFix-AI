# VulnLab: Authorized Local Security Testing Laboratory

**Platform:** AI-Powered Vulnerability Validation and Proof-of-Fix Platform  
**Track:** Offensive Security & Red Teaming  
**Environment:** Strictly Localhost (`127.0.0.1:5000`)

---

## ⚠️ Mandatory Scope & Authorization Notice

> **IMPORTANT:**  
> This application is an **intentionally vulnerable demonstration laboratory** built strictly for local authorized testing on `127.0.0.1` / `localhost`.
> - All organizations, users, telemetry records, and products are **100% synthetic and fake**.
> - It does **NOT** connect to external networks or external databases.
> - Destructive exploitation, malware, persistence, or data exfiltration are **strictly prohibited**.

---

## 🎯 Demonstration Scenarios

The lab contains three controlled vulnerability scenarios with built-in remediation toggles to demonstrate the complete lifecycle:  
`VULNERABLE (Demonstrate) ➔ DETECT & VALIDATE ➔ APPLY FIX ➔ RETEST (Proof-of-Fix) ➔ SECURE`

### 1. SQL Injection (CWE-89)
- **Endpoint**: `GET /sqli?query=<term>` and `GET /api/search?q=<term>`
- **Vulnerable Behavior**: The product search interpolates user input directly into dynamic SQL queries without parameterized binding, permitting SQL syntax manipulation (e.g. `' OR '1'='1`).
- **Remediated Behavior**: Executes parameterized queries (`SELECT ... WHERE name LIKE ?`) with SQLite query binding, preventing any syntax injection.

### 2. Reflected Cross-Site Scripting (CWE-79)
- **Endpoint**: `GET /xss?name=<input>` and `GET /api/greet?name=<input>`
- **Vulnerable Behavior**: Input is reflected directly into HTML output and rendered with Jinja2 `| safe`, allowing script and HTML tag injection (e.g. `<b>Canary</b>` or harmless test payloads).
- **Remediated Behavior**: Enforces context-aware HTML entity encoding (`html.escape()`), neutralizing all HTML/script tags.

### 3. Broken Object-Level Authorization / IDOR (CWE-639)
- **Endpoint**: `GET /record/<id>` and `GET /api/record/<id>`
- **Synthetic Tenancy**:
  - `User A` belongs to `Organization A` (owns Record ID `1`: `REC-001`).
  - `User B` belongs to `Organization B` (owns Record ID `2`: `REC-002`).
- **Vulnerable Behavior**: The application retrieves records directly by primary key without verifying that the requesting user's organization owns the record. `User A` can view `Organization B`'s confidential telemetry (`/record/2`).
- **Remediated Behavior**: Enforces tenancy ownership assertions (`WHERE id = ? AND organization_id = ?`). Attempting cross-tenant access returns `HTTP 403 Forbidden`.

---

## 🔄 Remediation & Proof-of-Fix Mode Toggle

You can dynamically switch the entire lab between **Vulnerable** and **Secure** states:
- **Web UI**: Click the "Switch Mode" button in the top banner.
- **REST API**:
  - Check current mode: `GET /api/mode`
  - Set mode: `POST /api/mode` with JSON `{"mode": "secure"}` or `{"mode": "vulnerable"}`
  - Toggle: `POST /toggle_mode`

---

## 🚀 How to Run the Laboratory

### 1. Install Dependencies
```powershell
pip install -r ../requirements.txt
```

### 2. Initialize the SQLite Database
The SQLite database (`lab_data.db`) auto-initializes on startup with synthetic data. To manually reseed:
```powershell
python -c "from lab_app.database import init_db; init_db(reset=True)"
```

### 3. Start the Lab Application
```powershell
python -m lab_app.app
```
Or directly with Python:
```powershell
python lab_app/app.py
```
The lab will be available at:
```text
http://127.0.0.1:5000
```
