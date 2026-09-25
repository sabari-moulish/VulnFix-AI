"""
Unit and integration tests for Phase 5: Vulnerability Validator.
Validates safe, deterministic proof verification of SQLi, XSS, and IDOR hypotheses
across Vulnerable and Secure modes on the authorized local laboratory.
"""

import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import json
import requests

from modules.validator import (
    VulnerabilityValidator,
    ValidationOutcome,
    ValidationRunResult,
)
from modules.vulnerability_detector import FindingCandidate, VulnerabilityDetector
from modules.scope_controller import ScopeController
from config import get_db_connection, EVIDENCE_DIR


class TestVulnerabilityValidator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.target_url = "http://127.0.0.1:5000"
        # Verify local testbed is reachable
        try:
            requests.get(f"{cls.target_url}/api/health", timeout=2.0)
        except Exception:
            pass

    def setUp(self):
        self.scope_controller = ScopeController()
        self.validator = VulnerabilityValidator(
            scope_controller=self.scope_controller,
            max_requests=25,
            timeout=2.5,
        )
        # Ensure lab defaults to vulnerable mode before test starts
        try:
            requests.post(f"{self.target_url}/api/mode", json={"mode": "vulnerable"}, timeout=2.0)
        except Exception:
            pass

    def tearDown(self):
        # Reset lab to vulnerable mode
        try:
            requests.post(f"{self.target_url}/api/mode", json={"mode": "vulnerable"}, timeout=2.0)
        except Exception:
            pass

    # --- 1. Authorized & Unauthorized Validation ---

    def test_authorized_target_validation(self):
        """Tests that validation executes successfully against the authorized local target."""
        finding = {
            "id": "FIND-SQLI-TEST01",
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/api/search",
            "affected_parameter": "q",
            "is_vulnerable": True,
        }
        outcome = self.validator.validate_finding(self.target_url, finding)

        self.assertIsInstance(outcome, ValidationOutcome)
        self.assertEqual(outcome.finding_id, "FIND-SQLI-TEST01")
        self.assertIn(outcome.validation_status, ("CONFIRMED", "NOT_CONFIRMED"))
        self.assertGreater(self.validator._request_count, 0)

    def test_unauthorized_target_blocking(self):
        """Tests that unauthorized external targets are immediately rejected with 0 network requests sent."""
        unauthorized_target = "https://unauthorized-remote-site.com"
        finding = {
            "id": "FIND-SQLI-UNAUTH",
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/search",
            "affected_parameter": "q",
        }
        outcome = self.validator.validate_finding(unauthorized_target, finding)

        self.assertEqual(outcome.validation_status, "BLOCKED_OUT_OF_SCOPE")
        self.assertFalse(outcome.is_confirmed)
        self.assertEqual(outcome.confidence_score, 0.0)
        self.assertEqual(self.validator._request_count, 0)

        # Batch validation should also block unauthorized targets
        batch_res = self.validator.validate_candidates(unauthorized_target, [finding])
        self.assertFalse(batch_res.success)
        self.assertEqual(batch_res.blocked_count, 1)
        self.assertEqual(batch_res.total_requests, 0)

    # --- 2. SQL Injection Validation (Vulnerable vs. Secure) ---

    def test_sqli_validation_vulnerable_mode(self):
        """Tests that SQL Injection boolean differential is confirmed in vulnerable mode."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "vulnerable"}, timeout=2.0)

        finding = {
            "id": "FIND-SQLI-VULN",
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/api/search",
            "affected_parameter": "q",
        }
        outcome = self.validator.validate_finding(self.target_url, finding)

        self.assertEqual(outcome.validation_status, "CONFIRMED")
        self.assertTrue(outcome.is_confirmed)
        self.assertGreaterEqual(outcome.confidence_score, 0.90)
        self.assertIn("' OR '1'='1", outcome.proof_of_concept_safe)
        self.assertIn("differential confirmed", outcome.details.lower())

    def test_sqli_validation_secure_mode(self):
        """Tests that SQL Injection is NOT confirmed when lab is in secure/remediated mode."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "secure"}, timeout=2.0)

        finding = {
            "id": "FIND-SQLI-SECURE",
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/api/search",
            "affected_parameter": "q",
        }
        outcome = self.validator.validate_finding(self.target_url, finding)

        self.assertEqual(outcome.validation_status, "NOT_CONFIRMED")
        self.assertFalse(outcome.is_confirmed)
        self.assertIn("parameterized", outcome.details.lower())

    # --- 3. Reflected XSS Validation (Vulnerable vs. Secure) ---

    def test_xss_validation_vulnerable_mode(self):
        """Tests that Reflected XSS is confirmed via non-executable canary reflection in vulnerable mode."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "vulnerable"}, timeout=2.0)

        finding = {
            "id": "FIND-XSS-VULN",
            "vuln_type": "REFLECTED_XSS",
            "cwe_id": "CWE-79",
            "endpoint": "/api/greet",
            "affected_parameter": "name",
        }
        outcome = self.validator.validate_finding(self.target_url, finding)

        self.assertEqual(outcome.validation_status, "CONFIRMED")
        self.assertTrue(outcome.is_confirmed)
        self.assertGreaterEqual(outcome.confidence_score, 0.90)
        self.assertIn("<poc_probe_nonexec>", outcome.proof_of_concept_safe)
        self.assertIn("reflected xss", outcome.details.lower())

    def test_xss_validation_secure_mode(self):
        """Tests that Reflected XSS is NOT confirmed when lab output encoding is active in secure mode."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "secure"}, timeout=2.0)

        finding = {
            "id": "FIND-XSS-SECURE",
            "vuln_type": "REFLECTED_XSS",
            "cwe_id": "CWE-79",
            "endpoint": "/api/greet",
            "affected_parameter": "name",
        }
        outcome = self.validator.validate_finding(self.target_url, finding)

        self.assertEqual(outcome.validation_status, "NOT_CONFIRMED")
        self.assertFalse(outcome.is_confirmed)
        self.assertIn("sanitization verified", outcome.details.lower())

    # --- 4. IDOR / Broken Access Control (Vulnerable vs. Secure) ---

    def test_idor_validation_vulnerable_mode(self):
        """Tests that IDOR is confirmed when foreign tenant Record 2 is accessible in vulnerable mode."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "vulnerable"}, timeout=2.0)

        finding = {
            "id": "FIND-IDOR-VULN",
            "vuln_type": "BROKEN_ACCESS_CONTROL",
            "cwe_id": "CWE-639",
            "endpoint": "/api/record/<record_id>",
        }
        outcome = self.validator.validate_finding(self.target_url, finding)

        self.assertEqual(outcome.validation_status, "CONFIRMED")
        self.assertTrue(outcome.is_confirmed)
        self.assertGreaterEqual(outcome.confidence_score, 0.90)
        self.assertIn("api/record/2", outcome.proof_of_concept_safe)
        self.assertIn("cross-tenant", outcome.differential_observed.lower())

    def test_idor_validation_secure_mode(self):
        """Tests that IDOR is NOT confirmed when tenant isolation blocks cross-tenant access in secure mode."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "secure"}, timeout=2.0)

        finding = {
            "id": "FIND-IDOR-SECURE",
            "vuln_type": "BROKEN_ACCESS_CONTROL",
            "cwe_id": "CWE-639",
            "endpoint": "/api/record/<record_id>",
        }
        outcome = self.validator.validate_finding(self.target_url, finding)

        self.assertEqual(outcome.validation_status, "NOT_CONFIRMED")
        self.assertFalse(outcome.is_confirmed)
        self.assertIn("403", outcome.differential_observed)

    # --- 5. Request Limit Enforcement ---

    def test_request_limit_enforcement(self):
        """Tests that validator strictly enforces request limits and stops bounded execution."""
        limited_validator = VulnerabilityValidator(
            scope_controller=self.scope_controller,
            max_requests=2,
            timeout=2.0,
        )
        candidates = [
            {"id": "F1", "vuln_type": "SQL_INJECTION", "cwe_id": "CWE-89", "endpoint": "/api/search", "param": "q"},
            {"id": "F2", "vuln_type": "REFLECTED_XSS", "cwe_id": "CWE-79", "endpoint": "/api/greet", "param": "name"},
            {"id": "F3", "vuln_type": "BROKEN_ACCESS_CONTROL", "cwe_id": "CWE-639", "endpoint": "/api/record"},
        ]
        result = limited_validator.validate_candidates(self.target_url, candidates)

        self.assertTrue(result.success)
        self.assertLessEqual(result.total_requests, 3)  # stopped once limit hit
        self.assertEqual(len(result.outcomes), 3)
        # Candidates after limit reached should be marked INCONCLUSIVE
        self.assertTrue(any(o.validation_status == "INCONCLUSIVE" for o in result.outcomes))

    # --- 6. Timeout Handling ---

    def test_timeout_handling(self):
        """Tests that network timeouts are handled safely without unhandled exceptions."""
        with patch("requests.Session.request", side_effect=requests.Timeout("Simulated Timeout")):
            origin = self.validator._normalize_origin(self.target_url)
            resp, out_of_scope, err = self.validator._safe_request(
                "GET", f"{self.target_url}/api/search", origin
            )
            self.assertIsNone(resp)
            self.assertFalse(out_of_scope)
            self.assertIn("timed out", err.lower())

            # Validating a finding during timeout yields INCONCLUSIVE
            finding = {"id": "FIND-TIMEOUT", "vuln_type": "SQL_INJECTION", "endpoint": "/api/search"}
            outcome = self.validator.validate_finding(self.target_url, finding)
            self.assertEqual(outcome.validation_status, "INCONCLUSIVE")
            self.assertFalse(outcome.is_confirmed)

    # --- 7. Out-of-Scope Redirect Blocking ---

    def test_out_of_scope_redirect_blocking(self):
        """Tests that redirects pointing to external domains are blocked and flagged."""
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "https://malicious-external-target.com/exploit"}
        mock_resp.text = "Redirecting..."

        with patch("requests.Session.request", return_value=mock_resp):
            origin = self.validator._normalize_origin(self.target_url)
            resp, out_of_scope, err = self.validator._safe_request(
                "GET", f"{self.target_url}/api/search", origin
            )
            self.assertTrue(out_of_scope)
            self.assertIn("Redirect to external origin", err)

    # --- 8. Evidence Persistence ---

    def test_evidence_persistence(self):
        """Tests that reproducible validation evidence is saved to disk and SQLite database."""
        requests.post(f"{self.target_url}/api/mode", json={"mode": "vulnerable"}, timeout=2.0)

        finding = {
            "id": "FIND-PERSIST-TEST",
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/api/search",
            "affected_parameter": "q",
        }
        outcome = self.validator.validate_finding(self.target_url, finding)

        # Check evidence JSON artifact exists on disk
        self.assertIsNotNone(outcome.evidence_id)
        self.assertIsNotNone(outcome.evidence_file)
        self.assertTrue(Path(outcome.evidence_file).exists())

        with open(outcome.evidence_file, "r", encoding="utf-8") as f:
            evidence_data = json.load(f)
        self.assertEqual(evidence_data["finding_id"], "FIND-PERSIST-TEST")
        self.assertEqual(evidence_data["evidence_type"], "PROOF_OF_CONCEPT_VALIDATION")

        # Check SQLite database validations table
        with get_db_connection() as conn:
            cursor = conn.cursor()
            val_rows = cursor.execute(
                "SELECT * FROM validations WHERE finding_id = ?", ("FIND-PERSIST-TEST",)
            ).fetchall()
            self.assertGreaterEqual(len(val_rows), 1)

    # --- 9. Inconclusive Handling ---

    def test_inconclusive_handling(self):
        """Tests that unsupported types or neutral endpoints are marked INCONCLUSIVE."""
        finding = {
            "id": "FIND-UNKNOWN",
            "vuln_type": "UNKNOWN_CUSTOM_FLAW",
            "cwe_id": "CWE-999",
            "endpoint": "/api/health",
        }
        outcome = self.validator.validate_finding(self.target_url, finding)

        self.assertEqual(outcome.validation_status, "INCONCLUSIVE")
        self.assertFalse(outcome.is_confirmed)
        self.assertEqual(outcome.confidence_score, 0.0)
        self.assertIn("unsupported", outcome.details.lower())

    # --- 10. FindingCandidate Integration ---

    def test_finding_candidate_integration(self):
        """Tests that validator seamlessly consumes actual FindingCandidate dataclass objects from detector."""
        candidate = FindingCandidate(
            id="FIND-CAND-INTEG",
            vuln_type="REFLECTED_XSS",
            cwe_id="CWE-79",
            title="Reflected XSS on /api/greet",
            endpoint="/api/greet",
            http_method="GET",
            affected_parameter="name",
            input_location="query_param",
            detection_status="LIKELY_VULNERABLE",
            confidence=0.95,
            evidence={"request_payload": "probe"},
            observed_behavior="Reflected unescaped",
            potential_impact="XSS",
            remediation_reference="OWASP",
            timestamp="2026-09-25T00:00:00",
            target_url=f"{self.target_url}/api/greet",
            severity="MEDIUM",
            is_vulnerable=True,
        )

        outcome = self.validator.validate_finding(self.target_url, candidate)
        self.assertIsInstance(outcome, ValidationOutcome)
        self.assertEqual(outcome.finding_id, "FIND-CAND-INTEG")
        self.assertIn(outcome.validation_status, ("CONFIRMED", "NOT_CONFIRMED"))

        batch_result = self.validator.validate_candidates(self.target_url, [candidate])
        self.assertIsInstance(batch_result, ValidationRunResult)
        self.assertTrue(batch_result.success)
        self.assertEqual(batch_result.total_validated, 1)


if __name__ == "__main__":
    unittest.main()
