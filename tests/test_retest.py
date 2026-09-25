"""
Unit and integration tests for Phase 8: Retest / Proof-of-Fix Engine.
Tests proof-of-fix verification across SQLi, Reflected XSS, and IDOR in both
Vulnerable (STILL_VULNERABLE) and Secure (FIXED_VERIFIED) modes on the local lab,
as well as out-of-scope blocking, persistence, and RemediationPlan integration.
"""

import unittest
from pathlib import Path
import json
import requests
import uuid
import tempfile
import shutil

from modules.retest import RetestEngine, RetestResult
from modules.remediation import RemediationPlan
from modules.vulnerability_detector import FindingCandidate
from modules.scope_controller import ScopeController
from config import get_db_connection


class TestRetestEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.target_url = "http://127.0.0.1:5000"
        # Verify local lab is reachable
        try:
            requests.get(f"{cls.target_url}/api/health", timeout=2.0)
        except Exception:
            pass

    def setUp(self):
        self.temp_reports_dir = Path(tempfile.mkdtemp())
        self.scope_controller = ScopeController()
        self.engine = RetestEngine(
            scope_controller=self.scope_controller,
            reports_dir=self.temp_reports_dir,
            max_requests=25,
            timeout=2.5,
        )
        # Default lab to vulnerable mode
        try:
            requests.post(f"{self.target_url}/api/mode", json={"mode": "vulnerable"}, timeout=2.0)
        except Exception:
            pass

    def tearDown(self):
        shutil.rmtree(self.temp_reports_dir, ignore_errors=True)
        # Reset lab to vulnerable mode
        try:
            requests.post(f"{self.target_url}/api/mode", json={"mode": "vulnerable"}, timeout=2.0)
        except Exception:
            pass

    # --- 1. SQL Injection: Still Vulnerable vs. Fixed Verified ---

    def test_sqli_retest_vulnerable_mode(self):
        """Tests that retesting SQLi in vulnerable mode confirms defect persists (STILL_VULNERABLE)."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "vulnerable"}, timeout=2.0)

        finding = {
            "id": "FIND-SQLI-RETEST",
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/api/search",
            "affected_parameter": "q",
        }
        res = self.engine.verify_fix(self.target_url, finding)

        self.assertIsInstance(res, RetestResult)
        self.assertEqual(res.status, "STILL_VULNERABLE")
        self.assertIn("STILL_VULNERABLE", res.proof_of_fix_details)
        self.assertIn("persists", res.proof_of_fix_details.lower())

    def test_sqli_retest_secure_mode(self):
        """Tests that retesting SQLi in secure mode confirms fix effectiveness (FIXED_VERIFIED)."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "secure"}, timeout=2.0)

        finding = {
            "id": "FIND-SQLI-RETEST",
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/api/search",
            "affected_parameter": "q",
        }
        res = self.engine.verify_fix(self.target_url, finding)

        self.assertEqual(res.status, "FIXED_VERIFIED")
        self.assertIn("FIXED_VERIFIED", res.proof_of_fix_details)
        self.assertIn("parameterized", res.proof_of_fix_details.lower())

    # --- 2. Reflected XSS: Still Vulnerable vs. Fixed Verified ---

    def test_xss_retest_vulnerable_mode(self):
        """Tests that retesting Reflected XSS in vulnerable mode reports STILL_VULNERABLE."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "vulnerable"}, timeout=2.0)

        finding = {
            "id": "FIND-XSS-RETEST",
            "vuln_type": "REFLECTED_XSS",
            "cwe_id": "CWE-79",
            "endpoint": "/api/greet",
            "affected_parameter": "name",
        }
        res = self.engine.verify_fix(self.target_url, finding)

        self.assertEqual(res.status, "STILL_VULNERABLE")
        self.assertIn("reproduced", res.proof_of_fix_details.lower())

    def test_xss_retest_secure_mode(self):
        """Tests that retesting Reflected XSS in secure mode reports FIXED_VERIFIED."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "secure"}, timeout=2.0)

        finding = {
            "id": "FIND-XSS-RETEST",
            "vuln_type": "REFLECTED_XSS",
            "cwe_id": "CWE-79",
            "endpoint": "/api/greet",
            "affected_parameter": "name",
        }
        res = self.engine.verify_fix(self.target_url, finding)

        self.assertEqual(res.status, "FIXED_VERIFIED")
        self.assertIn("neutralized", res.proof_of_fix_details.lower())

    # --- 3. Broken Access Control / IDOR: Still Vulnerable vs. Fixed Verified ---

    def test_idor_retest_vulnerable_mode(self):
        """Tests that retesting IDOR in vulnerable mode reports STILL_VULNERABLE due to cross-tenant leak."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "vulnerable"}, timeout=2.0)

        finding = {
            "id": "FIND-IDOR-RETEST",
            "vuln_type": "BROKEN_ACCESS_CONTROL",
            "cwe_id": "CWE-639",
            "endpoint": "/api/record/<record_id>",
        }
        res = self.engine.verify_fix(self.target_url, finding)

        self.assertEqual(res.status, "STILL_VULNERABLE")
        self.assertIn("cross-tenant", res.proof_of_fix_details.lower())

    def test_idor_retest_secure_mode(self):
        """Tests that retesting IDOR in secure mode reports FIXED_VERIFIED with 403 Forbidden verified."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "secure"}, timeout=2.0)

        finding = {
            "id": "FIND-IDOR-RETEST",
            "vuln_type": "BROKEN_ACCESS_CONTROL",
            "cwe_id": "CWE-639",
            "endpoint": "/api/record/<record_id>",
        }
        res = self.engine.verify_fix(self.target_url, finding)

        self.assertEqual(res.status, "FIXED_VERIFIED")
        self.assertIn("403", res.proof_of_fix_details)

    # --- 4. Out-of-Scope Target Blocking ---

    def test_out_of_scope_target_blocking(self):
        """Tests that retest requests against unauthorized external targets are blocked immediately."""
        unauthorized = "https://unauthorized-remote-site.com"
        finding = {
            "id": "FIND-UNAUTH",
            "vuln_type": "SQL_INJECTION",
            "endpoint": "/search",
        }
        res = self.engine.verify_fix(unauthorized, finding)

        self.assertEqual(res.status, "BLOCKED_OUT_OF_SCOPE")
        self.assertIn("Scope violation", res.proof_of_fix_details)

    # --- 5. Persistence in SQLite and JSON Reports ---

    def test_retest_persistence_in_sqlite_and_json(self):
        """Tests that proof-of-fix outcomes are persisted in SQLite retests table and reports directory."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "secure"}, timeout=2.0)

        fid = f"FIND-RETEST-PERSIST-{uuid.uuid4().hex[:6]}"
        finding = {
            "id": fid,
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/api/search",
            "affected_parameter": "q",
        }

        res = self.engine.verify_fix(self.target_url, finding, persist=True)

        # Check JSON artifact
        self.assertIsNotNone(res.report_file)
        self.assertTrue(Path(res.report_file).exists())
        with open(res.report_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["finding_id"], fid)
        self.assertEqual(data["status"], "FIXED_VERIFIED")

        # Check SQLite retests table
        with get_db_connection() as conn:
            cursor = conn.cursor()
            rows = cursor.execute(
                "SELECT * FROM retests WHERE finding_id = ?", (fid,)
            ).fetchall()
            self.assertGreaterEqual(len(rows), 1)
            row = dict(rows[0])
            self.assertEqual(row["finding_id"], fid)
            self.assertEqual(row["status"], "FIXED_VERIFIED")

    # --- 6. RemediationPlan Integration & Verification Steps ---

    def test_remediation_plan_integration(self):
        """Tests that RemediationPlan object verification steps are consumed and checked during retest."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "secure"}, timeout=2.0)

        plan = RemediationPlan(
            remediation_id="rem-plan-01",
            finding_id="FIND-PLAN-RETEST",
            vuln_type="REFLECTED_XSS",
            cwe_id="CWE-79",
            title="Context-Aware Output Encoding",
            root_cause="Unescaped input",
            guidance="Use html.escape",
            code_patch="html.escape(raw_input)",
            verification_steps=[
                "Send standard input and verify normal greeting.",
                "Send probe containing '<poc_probe_nonexec>' and verify '&lt;...&gt;' in response.",
            ],
            severity="HIGH",
            remediation_priority="P2",
            endpoint="/api/greet",
            affected_parameter="name",
            created_at="2026-09-25T10:00:00",
        )

        res = self.engine.verify_fix(self.target_url, plan)

        self.assertEqual(res.status, "FIXED_VERIFIED")
        self.assertEqual(len(res.verification_steps_checked), 2)
        self.assertIn("Verification steps evaluated", res.proof_of_fix_details)

    # --- 7. Inconclusive Handling ---

    def test_inconclusive_retest_handling(self):
        """Tests that unsupported or non-responsive endpoints yield INCONCLUSIVE status."""
        finding = {
            "id": "FIND-UNKNOWN-RETEST",
            "vuln_type": "UNKNOWN_CUSTOM_BUG",
            "cwe_id": "CWE-999",
            "endpoint": "/api/health",
        }
        res = self.engine.verify_fix(self.target_url, finding)

        self.assertEqual(res.status, "INCONCLUSIVE")
        self.assertIn("inconclusive", res.proof_of_fix_details.lower())

    # --- 8. Batch Retesting ---

    def test_retest_all_batch(self):
        """Tests batch retesting of multiple findings across an authorized target."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "secure"}, timeout=2.0)

        findings = [
            {"id": "F-SQLI", "vuln_type": "SQL_INJECTION", "cwe_id": "CWE-89", "endpoint": "/api/search", "param": "q"},
            {"id": "F-XSS", "vuln_type": "REFLECTED_XSS", "cwe_id": "CWE-79", "endpoint": "/api/greet", "param": "name"},
        ]
        results = self.engine.retest_all(self.target_url, findings, persist=False)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].status, "FIXED_VERIFIED")
        self.assertEqual(results[1].status, "FIXED_VERIFIED")


if __name__ == "__main__":
    unittest.main()
