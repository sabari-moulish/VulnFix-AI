"""
Remediation Engine Module
AI-Powered Vulnerability Validation and Proof-of-Fix Platform
Track: Offensive Security & Red Teaming

Generates concrete, contextual defensive remediation plans, architectural guidance,
and code patch diffs for validated findings.
Supports:
1. SQL Injection (CWE-89): Parameterized queries, prepared statements, ORM binds.
2. Reflected XSS (CWE-79): Context-aware output encoding, template auto-escaping.
3. Broken Access Control / IDOR (CWE-639): Tenant-scoped database queries, 403 Forbidden enforcement.

No external LLM or public APIs. Strictly local, deterministic guidance.
Persists remediation records to SQLite database and reports directory.
"""

from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass, asdict, field
from datetime import datetime
import json
import uuid
from pathlib import Path

from config import get_db_connection, REPORTS_DIR
from modules.vulnerability_detector import FindingCandidate
from modules.validator import ValidationOutcome
from modules.risk_engine import RiskAssessment


@dataclass
class RemediationPlan:
    """Comprehensive contextual remediation plan for a vulnerability finding."""
    remediation_id: str
    finding_id: str
    vuln_type: str
    cwe_id: str
    title: str
    root_cause: str
    guidance: str
    code_patch: str
    verification_steps: List[str]
    severity: str
    remediation_priority: str
    endpoint: str = ""
    affected_parameter: Optional[str] = None
    created_at: str = ""
    report_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the remediation plan to a dictionary."""
        return asdict(self)


class RemediationEngine:
    """
    Produces actionable, code-level remediation patterns, architectural guidance,
    and verification steps tailored to findings and risk assessments.
    """

    REMEDIATION_TEMPLATES = {
        "SQL_INJECTION": {
            "title": "Use Parameterized Queries and Prepared Statements",
            "cwe": "CWE-89",
            "root_cause": (
                "User-supplied input is directly concatenated or formatted into the dynamic SQL query "
                "string without parameter binding, allowing query logic alteration via boolean injection."
            ),
            "advice": (
                "1. Replace all dynamic SQL string concatenation (f'...' or % formatting) with parameterized queries.\n"
                "2. Pass user inputs as distinct parameters using placeholder markers (? in SQLite, %s in PostgreSQL/MySQL).\n"
                "3. Ensure the database driver handles escaping and type casting natively.\n"
                "4. Avoid building table or column names from untrusted input without strict whitelisting."
            ),
            "sample_fix": (
                "# --- Vulnerable Code ---\n"
                "# executed_query = f\"SELECT id, name, description, category FROM products WHERE name LIKE '%{query}%'\"\n"
                "# cursor.execute(executed_query)\n\n"
                "# +++ Remediated Code +++\n"
                "cursor.execute(\n"
                "    \"SELECT id, name, description, category FROM products WHERE name LIKE ?\",\n"
                "    (f\"%{query}%\",)\n"
                ")"
            ),
            "verification_steps": [
                "Submit benign search input (e.g., 'Sensor') and verify catalog items are returned normally.",
                "Submit boolean tautology probe (e.g., \"' OR '1'='1\") and verify it is treated as a literal search term without expanding results.",
                "Verify that single quotes and comments do not trigger unhandled database operational errors.",
            ],
        },
        "CWE-89": {
            "alias_of": "SQL_INJECTION",
        },
        "REFLECTED_XSS": {
            "title": "Context-Aware Output Encoding and HTML Entity Neutralization",
            "cwe": "CWE-79",
            "root_cause": (
                "User-controlled input is reflected verbatim into the HTML document or JSON response "
                "without contextual sanitization or entity encoding, allowing arbitrary markup injection."
            ),
            "advice": (
                "1. Apply context-aware HTML entity encoding using html.escape() before reflecting inputs into HTML contexts.\n"
                "2. In Jinja2 templates, remove the '| safe' filter on all user-controlled variables.\n"
                "3. Ensure API responses set Content-Type: application/json so browsers parse data strictly as data.\n"
                "4. Implement a robust Content Security Policy (CSP) header as a defense-in-depth barrier."
            ),
            "sample_fix": (
                "# --- Vulnerable Code ---\n"
                "# greeting = f\"Hello, {raw_input}! Welcome to the testing laboratory.\"\n"
                "# In template: {{ greeting | safe }}\n\n"
                "# +++ Remediated Code +++\n"
                "import html\n"
                "safe_input = html.escape(raw_input)\n"
                "greeting = f\"Hello, {safe_input}! Welcome to the testing laboratory.\"\n"
                "# In template: Render with default Jinja2 auto-escaping (remove | safe filter)"
            ),
            "verification_steps": [
                "Send standard alphanumeric input and verify expected greeting display.",
                "Send input with HTML markup tokens (e.g., '<poc_probe_nonexec>') and verify angle brackets are escaped to '&lt;' and '&gt;' in the response body.",
                "Verify Content-Type header is text/html; charset=utf-8 with X-Content-Type-Options: nosniff.",
            ],
        },
        "CROSS_SITE_SCRIPTING": {
            "alias_of": "REFLECTED_XSS",
        },
        "CWE-79": {
            "alias_of": "REFLECTED_XSS",
        },
        "BROKEN_ACCESS_CONTROL": {
            "title": "Enforce Multi-Tenant Data Isolation and Session-Bound Authorization",
            "cwe": "CWE-639",
            "root_cause": (
                "The endpoint retrieves and discloses records based solely on a client-supplied identifier "
                "without validating that the requesting user's session belongs to the organization that owns the record (IDOR)."
            ),
            "advice": (
                "1. Always include the authenticated user's organization_id / tenant identifier in the SQL WHERE clause.\n"
                "2. When a requested record ID belongs to another tenant, reject the request with HTTP 403 Forbidden.\n"
                "3. Do not rely solely on client-provided IDs; enforce authorization server-side in the business logic.\n"
                "4. Log unauthorized cross-tenant access attempts for security monitoring."
            ),
            "sample_fix": (
                "# --- Vulnerable Code ---\n"
                "# cursor.execute(\"SELECT * FROM records WHERE id = ?\", (record_id,))\n"
                "# row = cursor.fetchone()  # Discloses foreign tenant records!\n\n"
                "# +++ Remediated Code +++\n"
                "current_user = get_current_user()\n"
                "cursor.execute(\n"
                "    \"SELECT * FROM records WHERE id = ? AND organization_id = ?\",\n"
                "    (record_id, current_user[\"organization_id\"])\n"
                ")\n"
                "row = cursor.fetchone()\n"
                "if not row:\n"
                "    # Return HTTP 403 Forbidden on tenant ownership mismatch\n"
                "    return jsonify({\"error\": \"Forbidden: Tenant isolation enforced\", \"status\": 403}), 403"
            ),
            "verification_steps": [
                "Authenticate as User A (Org 1) and access Record 1; verify HTTP 200 OK and valid tenant data returned.",
                "Under the User A session, attempt to access Record 2 (owned by Org 2); verify access is blocked with HTTP 403 Forbidden.",
                "Verify no foreign organization telemetry or sensitive record fields are leaked in error responses.",
            ],
        },
        "IDOR": {
            "alias_of": "BROKEN_ACCESS_CONTROL",
        },
        "CWE-639": {
            "alias_of": "BROKEN_ACCESS_CONTROL",
        },
    }

    def __init__(self, reports_dir: Optional[Path] = None):
        self.reports_dir = reports_dir or REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_template(self, vuln_type: str, cwe_id: str = "") -> Dict[str, Any]:
        """Resolves template handling aliases and fallbacks."""
        norm_key = vuln_type.upper().replace(" ", "_") if vuln_type else ""
        norm_cwe = cwe_id.upper().strip() if cwe_id else ""

        # Try key lookup
        tmpl = self.REMEDIATION_TEMPLATES.get(norm_key) or self.REMEDIATION_TEMPLATES.get(norm_cwe)

        if tmpl and "alias_of" in tmpl:
            tmpl = self.REMEDIATION_TEMPLATES.get(tmpl["alias_of"])

        if tmpl:
            return tmpl

        # Generic fallback
        return {
            "title": f"Secure Remediation and Hardening for {vuln_type or cwe_id or 'Vulnerability'}",
            "cwe": cwe_id or "CWE-Unknown",
            "root_cause": (
                "Insufficient validation or missing authorization controls allow untrusted user input "
                "to compromise application integrity or boundary enforcement."
            ),
            "advice": (
                "1. Apply strict server-side input validation against an explicit allowlist.\n"
                "2. Enforce the principle of least privilege across database queries and API endpoints.\n"
                "3. Apply context-aware output encoding to all rendered user variables.\n"
                "4. Enforce session-authenticated authorization checks before performing sensitive operations."
            ),
            "sample_fix": (
                "# Generic Secure Remediation Pattern:\n"
                "# Validate input against strict allowlist\n"
                "# Enforce session-level authorization check\n"
                "# Use parameterized interfaces and safe escaping"
            ),
            "verification_steps": [
                "Verify normal operational requests succeed with valid inputs.",
                "Send boundary and malformed probes to verify robust rejection.",
                "Check application logs for clean error handling without stack trace leakage.",
            ],
        }

    def generate_fix(self, vuln_type: str, finding_details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Retrieves or generates tailored remediation guidance for a given vulnerability type.
        Preserves backward-compatibility with earlier scaffold tests while enriching output.
        """
        details = finding_details or {}
        cwe_id = details.get("cwe_id", "")
        template = self._resolve_template(vuln_type, cwe_id)

        return {
            "vuln_type": vuln_type,
            "remediation_title": template["title"],
            "cwe": template["cwe"],
            "guidance": template["advice"],
            "code_patch_example": template["sample_fix"],
            "root_cause": template.get("root_cause", ""),
            "verification_steps": template.get("verification_steps", []),
        }

    def _persist_remediation(self, plan: RemediationPlan, target_url: str = "") -> None:
        """
        Persists remediation plan to the SQLite remediations table and JSON report artifact.
        """
        # 1. Save JSON report artifact
        try:
            self.reports_dir.mkdir(parents=True, exist_ok=True)
            report_path = self.reports_dir / f"remediation_{plan.finding_id}_{plan.remediation_id}.json"
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(plan.to_dict(), f, indent=2)
            plan.report_file = str(report_path)
        except Exception:
            pass

        # 2. Persist in SQLite remediations table
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                # Ensure findings table has entry for this finding
                cursor.execute("SELECT id FROM findings WHERE id = ?", (plan.finding_id,))
                row = cursor.fetchone()
                if not row:
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO findings (id, target_url, title, vuln_type, cwe_id, severity, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            plan.finding_id,
                            target_url or "http://127.0.0.1:5000",
                            plan.title,
                            plan.vuln_type,
                            plan.cwe_id,
                            plan.severity,
                            "REMEDIATION_READY",
                        ),
                    )

                cursor.execute("DELETE FROM remediations WHERE finding_id = ?", (plan.finding_id,))
                cursor.execute(
                    """
                    INSERT INTO remediations (id, finding_id, fix_summary, code_patch, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        plan.remediation_id,
                        plan.finding_id,
                        f"{plan.title}: {plan.guidance}",
                        plan.code_patch,
                        plan.created_at,
                    ),
                )
                conn.commit()
        except Exception:
            pass

    def generate_remediation(
        self,
        finding: Union[FindingCandidate, Dict[str, Any]],
        risk_assessment: Optional[Union[RiskAssessment, Dict[str, Any]]] = None,
        validation: Optional[Union[ValidationOutcome, Dict[str, Any]]] = None,
        persist: bool = True,
    ) -> RemediationPlan:
        """
        Generates a comprehensive, contextual remediation plan consuming finding,
        risk assessment, and validation outcomes.
        """
        # Normalize finding inputs
        if isinstance(finding, FindingCandidate):
            finding_id = finding.id
            vuln_type = finding.vuln_type
            cwe_id = finding.cwe_id
            endpoint = finding.endpoint
            affected_param = finding.affected_parameter
            target_url = finding.target_url
            severity = finding.severity
        elif isinstance(finding, dict):
            finding_id = finding.get("id", f"FIND-{uuid.uuid4().hex[:6].upper()}")
            vuln_type = finding.get("vuln_type", "")
            cwe_id = finding.get("cwe_id", "")
            endpoint = finding.get("endpoint", "")
            affected_param = finding.get("affected_parameter") or finding.get("param")
            target_url = finding.get("target_url", "")
            severity = finding.get("severity", "MEDIUM")
        else:
            finding_id = "unknown"
            vuln_type = ""
            cwe_id = ""
            endpoint = ""
            affected_param = None
            target_url = ""
            severity = "MEDIUM"

        # Normalize risk assessment inputs
        remediation_priority = "P2"
        if isinstance(risk_assessment, RiskAssessment):
            severity = risk_assessment.severity
            remediation_priority = risk_assessment.remediation_priority
        elif isinstance(risk_assessment, dict):
            severity = risk_assessment.get("severity", severity)
            remediation_priority = risk_assessment.get("remediation_priority", "P2")

        # Resolve template
        template = self._resolve_template(vuln_type, cwe_id)
        remediation_id = f"rem-{uuid.uuid4().hex[:8]}"
        created_at = datetime.now().isoformat()

        # Build contextual code patch tailoring
        code_patch = template["sample_fix"]
        if affected_param and affected_param != "unknown":
            code_patch = code_patch.replace("{query}", f"{{{affected_param}}}")
            code_patch = code_patch.replace("query_param", affected_param)

        plan = RemediationPlan(
            remediation_id=remediation_id,
            finding_id=finding_id,
            vuln_type=vuln_type,
            cwe_id=template.get("cwe", cwe_id),
            title=template["title"],
            root_cause=template.get("root_cause", ""),
            guidance=template["advice"],
            code_patch=code_patch,
            verification_steps=list(template.get("verification_steps", [])),
            severity=severity,
            remediation_priority=remediation_priority,
            endpoint=endpoint,
            affected_parameter=affected_param,
            created_at=created_at,
        )

        if persist:
            self._persist_remediation(plan, target_url)

        return plan

    # Convenience alias
    remediate = generate_remediation

    def generate_remediations_all(
        self,
        findings: List[Union[FindingCandidate, Dict[str, Any]]],
        risk_assessments: Optional[List[Union[RiskAssessment, Dict[str, Any]]]] = None,
        validations: Optional[List[Union[ValidationOutcome, Dict[str, Any]]]] = None,
        persist: bool = True,
    ) -> List[RemediationPlan]:
        """
        Generates remediation plans for a batch of findings with correlated risk assessments.
        """
        risk_map: Dict[str, Any] = {}
        if risk_assessments:
            for r in risk_assessments:
                fid = r.finding_id if isinstance(r, RiskAssessment) else r.get("finding_id")
                if fid:
                    risk_map[fid] = r

        plans: List[RemediationPlan] = []
        for f in findings:
            fid = f.id if isinstance(f, FindingCandidate) else f.get("id")
            risk_match = risk_map.get(fid) if fid else None
            plan = self.generate_remediation(f, risk_assessment=risk_match, persist=persist)
            plans.append(plan)

        return plans
