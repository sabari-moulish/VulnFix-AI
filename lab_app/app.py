"""
Intentionally Vulnerable Local Security Laboratory
AI-Powered Vulnerability Validation and Proof-of-Fix Platform
Track: Offensive Security & Red Teaming

STRICTLY FOR AUTHORIZED LOCAL TESTING ON LOCALHOST.
Contains 3 controlled scenarios:
1. SQL Injection (CWE-89)
2. Reflected XSS (CWE-79)
3. Broken Access Control / IDOR (CWE-639)

Includes a configurable remediation toggle (VULNERABLE <-> SECURE) to demonstrate:
VULNERABLE -> VALIDATE -> APPLY FIX -> RETEST -> FIXED
"""

import html
import sqlite3
from typing import Optional, Dict, Any
from flask import Flask, request, render_template, jsonify, redirect, url_for, session

from lab_app.database import get_db, init_db

app = Flask(__name__)
app.secret_key = "synthetic-lab-secret-key-for-local-testing-only"

# Global security configuration mode: "vulnerable" vs "secure"
# Demonstrates proof-of-fix transition
SECURITY_MODE = "vulnerable"


def get_current_user() -> Dict[str, Any]:
    """Simulates currently authenticated user session (synthetic User A)."""
    user_id = session.get("user_id", 1)
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if user:
            return dict(user)
    return {"id": 1, "username": "User A", "organization_id": 1, "role": "Lab Tester"}


def get_current_org(org_id: int) -> Dict[str, Any]:
    """Retrieves organization details for a synthetic user."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM organizations WHERE id = ?", (org_id,))
        org = cursor.fetchone()
        if org:
            return dict(org)
    return {"id": org_id, "name": f"Organization {org_id}"}


@app.context_processor
def inject_global_state():
    """Injects security mode and current user context into all rendered templates."""
    user = get_current_user()
    org = get_current_org(user["organization_id"])
    return {
        "is_vulnerable": (SECURITY_MODE == "vulnerable"),
        "security_mode": SECURITY_MODE,
        "current_user": user,
        "current_org": org,
    }


# --- Platform Diagnostics & Mode Toggle ---

@app.route("/")
def index():
    """Landing overview of the laboratory scenarios."""
    return render_template("index.html")


@app.route("/api/health")
def api_health():
    """Health check endpoint for automated discovery."""
    return jsonify({
        "status": "healthy",
        "app": "VulnLab Local Laboratory",
        "security_mode": SECURITY_MODE,
        "is_vulnerable": (SECURITY_MODE == "vulnerable"),
        "host": "localhost",
    })


@app.route("/api/mode", methods=["GET", "POST"])
def api_mode():
    """Inspect or change the security mode for Proof-of-Fix demonstration."""
    global SECURITY_MODE
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        new_mode = data.get("mode", "").lower()
        if new_mode in ("vulnerable", "secure"):
            SECURITY_MODE = new_mode
    return jsonify({
        "security_mode": SECURITY_MODE,
        "is_vulnerable": (SECURITY_MODE == "vulnerable"),
    })


@app.route("/toggle_mode", methods=["POST"])
def toggle_mode():
    """Toggle button handler to switch between vulnerable and secure remediated mode."""
    global SECURITY_MODE
    SECURITY_MODE = "secure" if SECURITY_MODE == "vulnerable" else "vulnerable"
    referrer = request.referrer or url_for("index")
    return redirect(referrer)


# --- Scenario 1: SQL Injection (CWE-89) ---

@app.route("/sqli")
def sqli_page():
    """
    Search catalog with an intentionally unsafe SQL query when in vulnerable mode.
    Demonstrates CWE-89 vs Parameterized Query Remediation.
    """
    query = request.args.get("query", "").strip()
    results = []
    error = None
    executed_query = ""

    if query:
        with get_db() as conn:
            cursor = conn.cursor()
            try:
                if SECURITY_MODE == "vulnerable":
                    # Intentionally vulnerable raw query string concatenation
                    executed_query = f"SELECT id, name, description, category FROM products WHERE name LIKE '%{query}%'"
                    cursor.execute(executed_query)
                    rows = cursor.fetchall()
                    results = [dict(r) for r in rows]
                else:
                    # Secure / Remediated parameterized query
                    executed_query = "SELECT id, name, description, category FROM products WHERE name LIKE ? (Parameterized)"
                    cursor.execute("SELECT id, name, description, category FROM products WHERE name LIKE ?", (f"%{query}%",))
                    rows = cursor.fetchall()
                    results = [dict(r) for r in rows]
            except sqlite3.OperationalError as e:
                error = str(e)

    return render_template("sqli.html", query=query, results=results, error=error, executed_query=executed_query)


@app.route("/api/search")
def api_search():
    """API endpoint for automated SQLi validation testing."""
    query = request.args.get("q", "").strip()
    results = []
    error = None
    executed_query = ""

    if query:
        with get_db() as conn:
            cursor = conn.cursor()
            try:
                if SECURITY_MODE == "vulnerable":
                    executed_query = f"SELECT id, name, description, category FROM products WHERE name LIKE '%{query}%'"
                    cursor.execute(executed_query)
                    results = [dict(r) for r in cursor.fetchall()]
                else:
                    executed_query = "SELECT id, name, description, category FROM products WHERE name LIKE ?"
                    cursor.execute(executed_query, (f"%{query}%",))
                    results = [dict(r) for r in cursor.fetchall()]
            except sqlite3.OperationalError as e:
                error = str(e)

    return jsonify({
        "query": query,
        "results": results,
        "count": len(results),
        "error": error,
        "executed_query": executed_query,
        "security_mode": SECURITY_MODE,
    })


# --- Scenario 2: Reflected XSS (CWE-79) ---

@app.route("/xss")
def xss_page():
    """
    Reflects user input into HTML response unsafely in vulnerable mode.
    Demonstrates CWE-79 vs Context-Aware HTML Entity Encoding.
    """
    raw_input = request.args.get("name", "").strip()
    greeting = ""

    if raw_input:
        if SECURITY_MODE == "vulnerable":
            # Vulnerable: Raw reflection without sanitization, rendered with | safe
            greeting = f"Hello, {raw_input}! Welcome to the testing laboratory."
        else:
            # Secure / Remediated: Explicitly escaped to neutralize any HTML tags
            greeting = f"Hello, {html.escape(raw_input)}! Welcome to the testing laboratory."

    return render_template("xss.html", raw_input=raw_input, greeting=greeting)


@app.route("/api/greet")
def api_greet():
    """API endpoint for automated XSS verification probing."""
    raw_input = request.args.get("name", "")
    if SECURITY_MODE == "vulnerable":
        reflected = raw_input
    else:
        reflected = html.escape(raw_input)

    return jsonify({
        "raw_input": raw_input,
        "reflected": reflected,
        "is_escaped": (SECURITY_MODE == "secure"),
        "security_mode": SECURITY_MODE,
    })


# --- Scenario 3: Broken Access Control / IDOR (CWE-639) ---

@app.route("/idor")
def idor_page():
    """IDOR overview and lookup page."""
    return render_template("idor.html", record=None)


@app.route("/record_lookup")
def record_lookup():
    """Helper route redirecting lookup form to direct record ID."""
    record_id = request.args.get("record_id", "1")
    return redirect(f"/record/{record_id}")


@app.route("/record/<int:record_id>")
def view_record(record_id: int):
    """
    Displays confidential record.
    In vulnerable mode: Fetches by ID only without verifying organization tenancy (IDOR).
    In secure mode: Enforces organization ownership checks and blocks foreign records with 403.
    """
    current_user = get_current_user()
    record = None
    record_org_name = ""
    error = None

    with get_db() as conn:
        cursor = conn.cursor()
        
        if SECURITY_MODE == "vulnerable":
            # Broken Access Control: Missing tenant isolation check!
            cursor.execute("SELECT * FROM records WHERE id = ?", (record_id,))
            row = cursor.fetchone()
            if row:
                record = dict(row)
                org = get_current_org(record["organization_id"])
                record_org_name = org["name"]
            else:
                error = f"Record ID {record_id} not found."
        else:
            # Secure: Strict ownership enforcement
            cursor.execute(
                "SELECT * FROM records WHERE id = ? AND organization_id = ?",
                (record_id, current_user["organization_id"]),
            )
            row = cursor.fetchone()
            if row:
                record = dict(row)
                org = get_current_org(record["organization_id"])
                record_org_name = org["name"]
            else:
                # Check if it exists in another organization to deliver accurate 403
                cursor.execute("SELECT organization_id FROM records WHERE id = ?", (record_id,))
                foreign_row = cursor.fetchone()
                if foreign_row:
                    error = (
                        f"HTTP 403 FORBIDDEN - Access Denied: Record {record_id} belongs to a different "
                        "organization. Cross-tenant access is prohibited."
                    )
                    return render_template("idor.html", requested_id=record_id, error=error), 403
                else:
                    error = f"Record ID {record_id} not found."

    return render_template(
        "idor.html",
        requested_id=record_id,
        record=record,
        record_org_name=record_org_name,
        error=error,
    )


@app.route("/api/record/<int:record_id>")
def api_record(record_id: int):
    """API endpoint for automated IDOR validation testing."""
    current_user = get_current_user()

    with get_db() as conn:
        cursor = conn.cursor()
        
        if SECURITY_MODE == "vulnerable":
            # Vulnerable: Direct access by record_id without ownership assertion
            cursor.execute("SELECT * FROM records WHERE id = ?", (record_id,))
            row = cursor.fetchone()
            if not row:
                return jsonify({"error": "Record not found"}), 404
            
            data = dict(row)
            return jsonify({
                "record": data,
                "current_user_org": current_user["organization_id"],
                "data_leaked_across_tenancy": (data["organization_id"] != current_user["organization_id"]),
                "security_mode": SECURITY_MODE,
            })
        else:
            # Secure: Requires matching organization_id
            cursor.execute(
                "SELECT * FROM records WHERE id = ? AND organization_id = ?",
                (record_id, current_user["organization_id"]),
            )
            row = cursor.fetchone()
            if not row:
                return jsonify({
                    "error": "Forbidden: Tenant isolation enforced",
                    "status": 403,
                    "security_mode": SECURITY_MODE,
                }), 403

            return jsonify({
                "record": dict(row),
                "current_user_org": current_user["organization_id"],
                "data_leaked_across_tenancy": False,
                "security_mode": SECURITY_MODE,
            })


if __name__ == "__main__":
    init_db()
    # Runs strictly locally on localhost port 5000
    app.run(host="127.0.0.1", port=5000, debug=False)
