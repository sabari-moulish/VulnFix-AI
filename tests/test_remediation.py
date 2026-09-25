"""
Unit and integration tests for Phase 7: Remediation Engine.
Tests contextual remediation plan generation for SQLi, XSS, and IDOR,
persistence to SQLite and JSON artifacts, contextual parameter mapping,
fallback guidance, and backward compatibility with generate_fix.
"""

import unittest
from pathlib import Path
import json
import tempfile
import shutil

from modules.remediation import RemediationEngine, RemediationPlan
from modules.vulnerability_detector import FindingCandidate
from modules.risk_engine import RiskAssessment, RiskFactors
from config import get_db_connection


class TestRemediationEngine(unittest.TestCase):

    def setUp(self):
        self.temp_reports_dir = Path(tempfile.mkdtemp())
        self.engine = RemediationEngine(reports_dir=self.temp_reports_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_reports_dir, ignore_errors=True)

    # --- 1. SQL Injection Remediation ---

    def test_sqli_remediation_generation(self):
        """Tests that SQL Injection remediation provides parameterized query guidance and patch."""
        finding = {
            "id": "FIND-SQLI-TEST",
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/api/search",
            "affected_parameter": "q",
            "severity": "HIGH",
        }
        risk = {
            "finding_id": "FIND-SQLI-TEST",
            "severity": "CRITICAL",
            "remediation_priority": "P1",
        }

        plan = self.engine.generate_remediation(finding, risk_assessment=risk)

        self.assertIsInstance(plan, RemediationPlan)
        self.assertEqual(plan.finding_id, "FIND-SQLI-TEST")
        self.assertEqual(plan.cwe_id, "CWE-89")
        self.assertIn("Parameterized Queries", plan.title)
        self.assertIn("parameter", plan.guidance.lower())
        self.assertIn("?", plan.code_patch)
        self.assertEqual(plan.severity, "CRITICAL")
        self.assertEqual(plan.remediation_priority, "P1")
        self.assertGreaterEqual(len(plan.verification_steps), 2)
        self.assertTrue(any("OR '1'='1" in step for step in plan.verification_steps))

    # --- 2. Reflected XSS Remediation ---

    def test_xss_remediation_generation(self):
        """Tests that Reflected XSS remediation provides context-aware encoding and safe template guidance."""
        finding = {
            "id": "FIND-XSS-TEST",
            "vuln_type": "REFLECTED_XSS",
            "cwe_id": "CWE-79",
            "endpoint": "/api/greet",
            "affected_parameter": "name",
            "severity": "MEDIUM",
        }
        risk = {
            "finding_id": "FIND-XSS-TEST",
            "severity": "HIGH",
            "remediation_priority": "P2",
        }

        plan = self.engine.generate_remediation(finding, risk_assessment=risk)

        self.assertEqual(plan.cwe_id, "CWE-79")
        self.assertIn("Output Encoding", plan.title)
        self.assertIn("html.escape", plan.guidance)
        self.assertIn("html.escape", plan.code_patch)
        self.assertIn("| safe", plan.code_patch)
        self.assertEqual(plan.remediation_priority, "P2")
        self.assertTrue(any("&lt;" in step for step in plan.verification_steps))

    # --- 3. Broken Access Control / IDOR Remediation ---

    def test_idor_remediation_generation(self):
        """Tests that IDOR remediation provides tenant-scoped database query and 403 Forbidden guidance."""
        finding = FindingCandidate(
            id="FIND-IDOR-TEST",
            vuln_type="BROKEN_ACCESS_CONTROL",
            cwe_id="CWE-639",
            title="IDOR on /api/record/<record_id>",
            endpoint="/api/record/2",
            http_method="GET",
            affected_parameter="record_id",
            input_location="path_param",
            detection_status="LIKELY_VULNERABLE",
            confidence=0.95,
            evidence={},
            observed_behavior="Cross-tenant leak",
            potential_impact="Data breach",
            remediation_reference="OWASP",
            timestamp="2026-09-25T10:00:00",
            target_url="http://127.0.0.1:5000/api/record/2",
            severity="CRITICAL",
            is_vulnerable=True,
        )

        plan = self.engine.generate_remediation(finding)

        self.assertEqual(plan.cwe_id, "CWE-639")
        self.assertIn("Multi-Tenant Data Isolation", plan.title)
        self.assertIn("organization_id", plan.guidance)
        self.assertIn("organization_id", plan.code_patch)
        self.assertIn("403", plan.code_patch)
        self.assertTrue(any("403 Forbidden" in step for step in plan.verification_steps))

    # --- 4. Persistence in SQLite Remediations Table ---

    def test_persistence_in_sqlite(self):
        """Tests that remediation records are saved to SQLite remediations table."""
        import uuid
        fid = f"FIND-PERSIST-REM-{uuid.uuid4().hex[:6]}"
        finding = {
            "id": fid,
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/api/search",
        }

        plan = self.engine.generate_remediation(finding, persist=True)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            rows = cursor.execute(
                "SELECT * FROM remediations WHERE finding_id = ?", (fid,)
            ).fetchall()
            self.assertGreaterEqual(len(rows), 1)
            row = dict(rows[0])
            self.assertEqual(row["finding_id"], fid)
            self.assertIn("Parameterized Queries", row["fix_summary"])
            self.assertIn("SELECT", row["code_patch"])

    # --- 5. JSON Artifact Persistence in Reports Directory ---

    def test_artifact_persistence_in_reports_dir(self):
        """Tests that remediation plans are saved as JSON artifacts in reports directory."""
        finding = {
            "id": "FIND-ARTIFACT-REM",
            "vuln_type": "REFLECTED_XSS",
            "cwe_id": "CWE-79",
            "endpoint": "/xss",
        }

        plan = self.engine.generate_remediation(finding, persist=True)

        self.assertIsNotNone(plan.report_file)
        self.assertTrue(Path(plan.report_file).exists())

        with open(plan.report_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["finding_id"], "FIND-ARTIFACT-REM")
        self.assertEqual(data["cwe_id"], "CWE-79")
        self.assertIn("Context-Aware Output Encoding", data["title"])
        self.assertIsInstance(data["verification_steps"], list)

    # --- 6. Contextual Data Propagation ---

    def test_contextual_data_propagation(self):
        """Tests that endpoint, parameter, severity, and priority from RiskAssessment propagate accurately."""
        finding = {
            "id": "FIND-CTX-01",
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/custom/api/catalog",
            "affected_parameter": "catalog_query",
        }

        # Mock RiskAssessment
        risk = RiskAssessment(
            assessment_id="risk-ctx-01",
            finding_id="FIND-CTX-01",
            risk_score=9.5,
            severity="CRITICAL",
            remediation_priority="P1",
            remediation_urgency="CRITICAL_IMMEDIATE",
            exploitability=9.5,
            impact=9.5,
            confidence=0.98,
            factors=RiskFactors(
                vuln_type="SQL_INJECTION",
                cwe_id="CWE-89",
                base_exploitability=8.5,
                exploitability_score=9.5,
                base_impact=9.0,
                impact_score=9.5,
                confidence_score=0.98,
                evidence_strength=0.9,
                validation_status="CONFIRMED",
                validation_multiplier=1.0,
                is_confirmed=True,
            ),
            summary="Confirmed critical SQLi",
            assessed_at="2026-09-25T10:00:00",
        )

        plan = self.engine.generate_remediation(finding, risk_assessment=risk)

        self.assertEqual(plan.endpoint, "/custom/api/catalog")
        self.assertEqual(plan.affected_parameter, "catalog_query")
        self.assertEqual(plan.severity, "CRITICAL")
        self.assertEqual(plan.remediation_priority, "P1")
        # Parameter should be reflected in patch
        self.assertIn("{catalog_query}", plan.code_patch)

    # --- 7. Fallback for Unknown Vulnerabilities ---

    def test_fallback_for_unknown_vulnerability(self):
        """Tests that an unsupported or custom vulnerability type receives defensive hardening guidance."""
        finding = {
            "id": "FIND-UNKNOWN-01",
            "vuln_type": "WEAK_CRYPTO_HASH",
            "cwe_id": "CWE-328",
            "endpoint": "/api/hash",
        }

        plan = self.engine.generate_remediation(finding, persist=False)

        self.assertEqual(plan.cwe_id, "CWE-328")
        self.assertIn("Secure Remediation and Hardening", plan.title)
        self.assertIn("least privilege", plan.guidance.lower())
        self.assertGreaterEqual(len(plan.verification_steps), 1)

    # --- 8. Backward Compatibility with generate_fix ---

    def test_generate_fix_backward_compatibility(self):
        """Tests that generate_fix maintains backward compatibility with legacy dictionary calls."""
        res_sqli = self.engine.generate_fix("SQL_INJECTION")
        self.assertEqual(res_sqli["vuln_type"], "SQL_INJECTION")
        self.assertEqual(res_sqli["cwe"], "CWE-89")
        self.assertIn("Parameterized Queries", res_sqli["remediation_title"])
        self.assertIn("code_patch_example", res_sqli)

        res_xss = self.engine.generate_fix("CROSS_SITE_SCRIPTING")
        self.assertEqual(res_xss["cwe"], "CWE-79")
        self.assertIn("Output Encoding", res_xss["remediation_title"])

        res_idor = self.engine.generate_fix("IDOR")
        self.assertEqual(res_idor["cwe"], "CWE-639")
        self.assertIn("Multi-Tenant Data Isolation", res_idor["remediation_title"])

    # --- 9. Batch Remediation Generation ---

    def test_generate_remediations_all(self):
        """Tests batch generation of remediation plans for multiple findings."""
        findings = [
            {"id": "F1", "vuln_type": "SQL_INJECTION", "cwe_id": "CWE-89"},
            {"id": "F2", "vuln_type": "REFLECTED_XSS", "cwe_id": "CWE-79"},
            {"id": "F3", "vuln_type": "BROKEN_ACCESS_CONTROL", "cwe_id": "CWE-639"},
        ]
        plans = self.engine.generate_remediations_all(findings, persist=False)

        self.assertEqual(len(plans), 3)
        self.assertEqual(plans[0].cwe_id, "CWE-89")
        self.assertEqual(plans[1].cwe_id, "CWE-79")
        self.assertEqual(plans[2].cwe_id, "CWE-639")


if __name__ == "__main__":
    unittest.main()
