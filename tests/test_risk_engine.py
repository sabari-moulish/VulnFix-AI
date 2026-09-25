"""
Unit and integration tests for Phase 6: Risk Assessment Engine.
Tests multi-dimensional risk scoring, contextual modifiers, exploitability, impact,
confidence, evidence strength, score bounds, priority mapping, and persistence.
"""

import unittest
from pathlib import Path
import json
import tempfile
import shutil

from modules.risk_engine import RiskEngine, RiskAssessment, RiskFactors
from modules.vulnerability_detector import FindingCandidate
from modules.validator import ValidationOutcome
from config import get_db_connection


class TestRiskEngine(unittest.TestCase):

    def setUp(self):
        self.temp_reports_dir = Path(tempfile.mkdtemp())
        self.engine = RiskEngine(reports_dir=self.temp_reports_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_reports_dir, ignore_errors=True)

    # --- 1. Confirmed SQL Injection Risk Assessment ---

    def test_confirmed_sqli_risk_assessment(self):
        """Tests that confirmed SQLi is scored with high/critical severity, high exploitability, and P1/P2 priority."""
        finding = FindingCandidate(
            id="FIND-SQLI-001",
            vuln_type="SQL_INJECTION",
            cwe_id="CWE-89",
            title="SQL Injection on /api/search",
            endpoint="/api/search",
            http_method="GET",
            affected_parameter="q",
            input_location="query_param",
            detection_status="LIKELY_VULNERABLE",
            confidence=0.95,
            evidence={
                "request_payload": "' OR '1'='1",
                "differential_observed": "JSON Item Differential: Baseline=1, True=3, False=0",
                "raw_interactions": [{"probe": "true"}, {"probe": "false"}],
            },
            observed_behavior="Boolean tautology expanded result set",
            potential_impact="Data disclosure",
            remediation_reference="OWASP",
            timestamp="2026-09-25T10:00:00",
            target_url="http://127.0.0.1:5000/api/search",
            severity="HIGH",
            is_vulnerable=True,
        )

        validation = ValidationOutcome(
            finding_id="FIND-SQLI-001",
            is_confirmed=True,
            confidence_score=0.98,
            validation_method="DeterministicBooleanDifferential",
            proof_of_concept_safe="GET http://127.0.0.1:5000/api/search?q=' OR '1'='1",
            details="Deterministic boolean differential confirmed.",
            validation_status="CONFIRMED",
            differential_observed="Item count differential verified",
        )

        assessment = self.engine.assess(finding, validation)

        self.assertIsInstance(assessment, RiskAssessment)
        self.assertEqual(assessment.finding_id, "FIND-SQLI-001")
        self.assertIn(assessment.severity, ("CRITICAL", "HIGH"))
        self.assertGreaterEqual(assessment.risk_score, 8.5)
        self.assertIn(assessment.remediation_priority, ("P1", "P2"))
        self.assertGreaterEqual(assessment.exploitability, 8.5)
        self.assertGreaterEqual(assessment.impact, 9.0)
        self.assertEqual(assessment.factors.validation_multiplier, 1.0)
        self.assertTrue(assessment.factors.is_confirmed)

    # --- 2. Confirmed Reflected XSS Risk Assessment ---

    def test_confirmed_xss_risk_assessment(self):
        """Tests that confirmed XSS produces appropriate High/Medium risk with client-side impact bounds."""
        finding = {
            "id": "FIND-XSS-001",
            "vuln_type": "REFLECTED_XSS",
            "cwe_id": "CWE-79",
            "endpoint": "/api/greet",
            "input_location": "query_param",
            "confidence": 0.95,
            "evidence": {
                "differential_observed": "Unescaped reflection observed",
                "raw_interactions": [{"status": 200}, {"status": 200}],
            },
            "is_vulnerable": True,
        }

        validation = {
            "finding_id": "FIND-XSS-001",
            "validation_status": "CONFIRMED",
            "is_confirmed": True,
            "confidence_score": 0.98,
            "proof_of_concept_safe": "GET http://127.0.0.1:5000/api/greet?name=token<poc_probe_nonexec>",
            "differential_observed": "Canary reflected verbatim",
        }

        assessment = self.engine.assess(finding, validation)

        self.assertIn(assessment.severity, ("HIGH", "MEDIUM"))
        self.assertGreaterEqual(assessment.risk_score, 6.5)
        self.assertLessEqual(assessment.risk_score, 8.5)
        self.assertEqual(assessment.remediation_priority, "P2")
        # XSS technical impact (6.0-6.5) should be lower than SQLi (9.0+)
        self.assertLess(assessment.impact, 9.0)

    # --- 3. Confirmed IDOR with Cross-Tenant Context ---

    def test_confirmed_idor_cross_tenant_risk_assessment(self):
        """Tests that confirmed IDOR with multi-tenant breach context triggers maximum severity and P1 priority."""
        finding = FindingCandidate(
            id="FIND-IDOR-001",
            vuln_type="BROKEN_ACCESS_CONTROL",
            cwe_id="CWE-639",
            title="IDOR on /api/record/<record_id>",
            endpoint="/api/record/2",
            http_method="GET",
            affected_parameter=None,
            input_location="path_param",
            detection_status="LIKELY_VULNERABLE",
            confidence=0.95,
            evidence={
                "differential_observed": "Cross-tenant access allowed: foreign tenant Record 2 accessible",
                "raw_interactions": [{"probe": "auth"}, {"probe": "foreign"}],
            },
            observed_behavior="Cross-tenant record leaked",
            potential_impact="Unauthorized data access across organizations",
            remediation_reference="OWASP",
            timestamp="2026-09-25T10:00:00",
            target_url="http://127.0.0.1:5000/api/record/2",
            severity="CRITICAL",
            is_vulnerable=True,
        )

        validation = ValidationOutcome(
            finding_id="FIND-IDOR-001",
            is_confirmed=True,
            confidence_score=0.98,
            validation_method="SyntheticMultiTenantBoundaryCheck",
            proof_of_concept_safe="GET http://127.0.0.1:5000/api/record/2",
            details="IDOR confirmed: foreign tenant object accessed.",
            validation_status="CONFIRMED",
            differential_observed="Cross-tenant access allowed: Record 2 (Org 2) returned HTTP 200",
        )

        assessment = self.engine.assess(finding, validation)

        self.assertEqual(assessment.severity, "CRITICAL")
        self.assertGreaterEqual(assessment.risk_score, 9.0)
        self.assertEqual(assessment.remediation_priority, "P1")
        self.assertEqual(assessment.remediation_urgency, "CRITICAL_IMMEDIATE")
        # Verify cross-tenant modifier applied to impact
        self.assertIn("cross_tenant_data_leak", assessment.factors.context_modifiers["impact_modifiers"])
        self.assertEqual(assessment.impact, 10.0)

    # --- 4. Unconfirmed / Remediated Finding ---

    def test_unconfirmed_finding_low_risk(self):
        """Tests that findings not confirmed during validation receive minimal risk scores and Low/Info priority."""
        finding = {
            "id": "FIND-SQLI-REMEDIATED",
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/api/search",
            "confidence": 0.50,
            "is_vulnerable": False,
        }

        validation = {
            "finding_id": "FIND-SQLI-REMEDIATED",
            "validation_status": "NOT_CONFIRMED",
            "is_confirmed": False,
            "confidence_score": 0.95,
            "proof_of_concept_safe": "",
            "differential_observed": "Parameterized query verified: 0 records returned",
        }

        assessment = self.engine.assess(finding, validation)

        self.assertLessEqual(assessment.risk_score, 1.5)
        self.assertIn(assessment.severity, ("LOW", "INFO"))
        self.assertEqual(assessment.remediation_priority, "P4")
        self.assertEqual(assessment.remediation_urgency, "LOW_PRIORITY")
        self.assertEqual(assessment.factors.validation_multiplier, 0.1)

    # --- 5. Confidence & Evidence Affecting Score ---

    def test_confidence_and_evidence_affecting_score(self):
        """Tests that findings with high confidence and verified PoC differential score higher than low-evidence findings."""
        high_evidence_finding = {
            "id": "FIND-HIGH-EVID",
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/api/search",
            "confidence": 0.95,
            "evidence": {
                "differential_observed": "Significant count differential observed",
                "raw_interactions": [{"probe": 1}, {"probe": 2}, {"probe": 3}],
            },
        }
        high_validation = {
            "finding_id": "FIND-HIGH-EVID",
            "validation_status": "CONFIRMED",
            "is_confirmed": True,
            "confidence_score": 0.98,
            "proof_of_concept_safe": "GET http://127.0.0.1:5000/api/search?q=' OR '1'='1",
            "differential_observed": "Confirmed differential",
        }

        low_evidence_finding = {
            "id": "FIND-LOW-EVID",
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/api/search",
            "confidence": 0.30,
            "evidence": {},
        }
        low_validation = {
            "finding_id": "FIND-LOW-EVID",
            "validation_status": "INCONCLUSIVE",
            "is_confirmed": False,
            "confidence_score": 0.30,
            "proof_of_concept_safe": "",
            "differential_observed": "",
        }

        assessment_high = self.engine.assess(high_evidence_finding, high_validation)
        assessment_low = self.engine.assess(low_evidence_finding, low_validation)

        self.assertGreater(assessment_high.risk_score, assessment_low.risk_score)
        self.assertGreater(assessment_high.confidence, assessment_low.confidence)
        self.assertGreater(assessment_high.factors.evidence_strength, assessment_low.factors.evidence_strength)

    # --- 6. Score Bounds Strictly Between 0.0 and 10.0 ---

    def test_score_bounds_zero_to_ten(self):
        """Tests that risk scores, exploitability, impact, and confidence are strictly bounded within [0, 10]."""
        # Test extreme high conditions
        extreme_high_finding = {
            "id": "FIND-EXTREME-HIGH",
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/api/extremely/critical/endpoint",
            "input_location": "query_param",
            "confidence": 1.0,
            "evidence": {
                "differential_observed": "Massive differential",
                "raw_interactions": [{"p": 1}, {"p": 2}],
            },
        }
        extreme_high_val = {
            "finding_id": "FIND-EXTREME-HIGH",
            "validation_status": "CONFIRMED",
            "is_confirmed": True,
            "confidence_score": 1.0,
            "proof_of_concept_safe": "GET ...",
            "differential_observed": "Confirmed",
        }
        assessment_high = self.engine.assess(extreme_high_finding, extreme_high_val)

        self.assertLessEqual(assessment_high.risk_score, 10.0)
        self.assertGreaterEqual(assessment_high.risk_score, 0.0)
        self.assertLessEqual(assessment_high.exploitability, 10.0)
        self.assertLessEqual(assessment_high.impact, 10.0)
        self.assertLessEqual(assessment_high.confidence, 1.0)

        # Test extreme low / blocked conditions
        blocked_finding = {
            "id": "FIND-BLOCKED",
            "vuln_type": "UNKNOWN",
            "cwe_id": "CWE-000",
            "endpoint": "/external",
            "confidence": 0.0,
        }
        blocked_val = {
            "finding_id": "FIND-BLOCKED",
            "validation_status": "BLOCKED_OUT_OF_SCOPE",
            "is_confirmed": False,
            "confidence_score": 0.0,
        }
        assessment_low = self.engine.assess(blocked_finding, blocked_val)

        self.assertEqual(assessment_low.risk_score, 0.0)
        self.assertEqual(assessment_low.severity, "INFO")
        self.assertEqual(assessment_low.remediation_priority, "P4")

    # --- 7. Priority and Urgency Mapping ---

    def test_priority_and_urgency_mapping(self):
        """Tests that risk scores map correctly to priority (P1-P4) and urgency tiers."""
        p1, u1 = self.engine._determine_priority_and_urgency(9.5)
        self.assertEqual(p1, "P1")
        self.assertEqual(u1, "CRITICAL_IMMEDIATE")

        p2, u2 = self.engine._determine_priority_and_urgency(7.5)
        self.assertEqual(p2, "P2")
        self.assertEqual(u2, "HIGH_PRIORITY")

        p3, u3 = self.engine._determine_priority_and_urgency(5.0)
        self.assertEqual(p3, "P3")
        self.assertEqual(u3, "MODERATE_PRIORITY")

        p4, u4 = self.engine._determine_priority_and_urgency(2.0)
        self.assertEqual(p4, "P4")
        self.assertEqual(u4, "LOW_PRIORITY")

    # --- 8. Persistence in SQLite and JSON Reports ---

    def test_persistence_in_sqlite_and_json(self):
        """Tests that risk assessments are recorded in SQLite risk_assessments table and JSON reports directory."""
        finding = {
            "id": "FIND-PERSIST-RISK",
            "vuln_type": "SQL_INJECTION",
            "cwe_id": "CWE-89",
            "endpoint": "/api/search",
            "confidence": 0.95,
        }
        validation = {
            "finding_id": "FIND-PERSIST-RISK",
            "validation_status": "CONFIRMED",
            "is_confirmed": True,
            "confidence_score": 0.98,
            "proof_of_concept_safe": "GET http://127.0.0.1:5000/api/search?q=' OR '1'='1",
        }

        assessment = self.engine.assess(finding, validation, persist=True)

        # Check JSON report artifact
        self.assertIsNotNone(assessment.report_file)
        self.assertTrue(Path(assessment.report_file).exists())
        with open(assessment.report_file, "r", encoding="utf-8") as f:
            report_data = json.load(f)
        self.assertEqual(report_data["finding_id"], "FIND-PERSIST-RISK")
        self.assertEqual(report_data["risk_score"], assessment.risk_score)

        # Check SQLite risk_assessments table
        with get_db_connection() as conn:
            cursor = conn.cursor()
            rows = cursor.execute(
                "SELECT * FROM risk_assessments WHERE finding_id = ?", ("FIND-PERSIST-RISK",)
            ).fetchall()
            self.assertGreaterEqual(len(rows), 1)
            row = dict(rows[0])
            self.assertEqual(row["finding_id"], "FIND-PERSIST-RISK")
            self.assertEqual(row["severity"], assessment.severity)
            self.assertEqual(row["remediation_priority"], assessment.remediation_priority)

    # --- 9. Backward Compatibility with calculate_score ---

    def test_calculate_score_backward_compatibility(self):
        """Tests that static calculate_score method continues to function for legacy calls."""
        res_crit = RiskEngine.calculate_score("SQL_INJECTION", "CRITICAL", True)
        self.assertEqual(res_crit["severity"], "CRITICAL")
        self.assertEqual(res_crit["score"], 10.0)
        self.assertEqual(res_crit["remediation_urgency"], "IMMEDIATE")

        res_low = RiskEngine.calculate_score("INFO_LEAK", "LOW", False)
        self.assertEqual(res_low["severity"], "LOW")
        self.assertEqual(res_low["score"], 2.0)
        self.assertEqual(res_low["remediation_urgency"], "LOW")

    # --- 10. Batch Assessment with assess_all ---

    def test_assess_all_batch_processing(self):
        """Tests that assess_all correctly correlates findings and validations in batch."""
        findings = [
            {"id": "F1", "vuln_type": "SQL_INJECTION", "cwe_id": "CWE-89", "endpoint": "/api/search"},
            {"id": "F2", "vuln_type": "REFLECTED_XSS", "cwe_id": "CWE-79", "endpoint": "/api/greet"},
        ]
        validations = [
            {"finding_id": "F1", "validation_status": "CONFIRMED", "is_confirmed": True, "confidence_score": 0.95},
            {"finding_id": "F2", "validation_status": "NOT_CONFIRMED", "is_confirmed": False, "confidence_score": 0.95},
        ]

        assessments = self.engine.assess_all(findings, validations, persist=False)
        self.assertEqual(len(assessments), 2)
        self.assertEqual(assessments[0].finding_id, "F1")
        self.assertGreaterEqual(assessments[0].risk_score, 7.0)
        self.assertEqual(assessments[1].finding_id, "F2")
        self.assertLessEqual(assessments[1].risk_score, 2.0)


if __name__ == "__main__":
    unittest.main()
