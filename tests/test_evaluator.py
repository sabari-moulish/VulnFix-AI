"""
Unit and integration tests for modules.evaluator (AI Defense Lab Evaluation Suite).
Validates the 5 required evaluation cases:
1. Normal Case
2. Attack/Positive Case
3. Negative Case
4. Failure Case
5. Adversarial Case
"""

import unittest
from pathlib import Path
import json
import requests

from modules.evaluator import (
    DefenseLabEvaluator,
    EvaluationCaseResult,
    EvaluationReport,
)
from modules.scope_controller import ScopeController
from config import REPORTS_DIR


class TestDefenseLabEvaluator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.target_url = "http://127.0.0.1:5000"
        # Ensure lab is responsive
        try:
            requests.get(f"{cls.target_url}/api/health", timeout=2.0)
        except Exception:
            pass

    def setUp(self):
        self.scope_controller = ScopeController()
        self.evaluator = DefenseLabEvaluator(
            scope_controller=self.scope_controller,
            timeout=2.5,
        )
        # Ensure lab is reset to vulnerable mode
        try:
            requests.post(f"{self.target_url}/api/mode", json={"mode": "vulnerable"}, timeout=2.0)
        except Exception:
            pass

    def tearDown(self):
        # Reset lab mode
        try:
            requests.post(f"{self.target_url}/api/mode", json={"mode": "vulnerable"}, timeout=2.0)
        except Exception:
            pass

    # --- 1. Normal Case ---

    def test_normal_case(self):
        """Tests that legitimate requests succeed with HTTP 200 and expected data."""
        result = self.evaluator.evaluate_normal_case(self.target_url)

        self.assertIsInstance(result, EvaluationCaseResult)
        self.assertEqual(result.case_num, 1)
        self.assertEqual(result.case_name, "Normal Case")
        self.assertEqual(result.status, "PASS")
        self.assertGreater(len(result.subchecks), 0)
        for subcheck in result.subchecks:
            self.assertTrue(subcheck["passed"], f"Failed subcheck: {subcheck['check']}")

    # --- 2. Attack / Positive Case ---

    def test_attack_positive_case(self):
        """Tests that controlled SQLi, XSS, and IDOR are detected and validated in vulnerable mode."""
        result = self.evaluator.evaluate_attack_positive_case(self.target_url)

        self.assertIsInstance(result, EvaluationCaseResult)
        self.assertEqual(result.case_num, 2)
        self.assertEqual(result.case_name, "Attack / Positive Case")
        self.assertEqual(result.status, "PASS")
        self.assertIn("SQLi", result.vulnerabilities_covered)
        self.assertIn("XSS", result.vulnerabilities_covered)
        self.assertIn("IDOR", result.vulnerabilities_covered)
        for subcheck in result.subchecks:
            self.assertTrue(subcheck["passed"], f"Failed subcheck: {subcheck['check']}")

    # --- 3. Negative Case ---

    def test_negative_case(self):
        """Tests that benign inputs produce 0 false alerts and secure mode neutralizes attacks."""
        result = self.evaluator.evaluate_negative_case(self.target_url)

        self.assertIsInstance(result, EvaluationCaseResult)
        self.assertEqual(result.case_num, 3)
        self.assertEqual(result.case_name, "Negative Case")
        self.assertEqual(result.status, "PASS")
        for subcheck in result.subchecks:
            self.assertTrue(subcheck["passed"], f"Failed subcheck: {subcheck['check']}")

    # --- 4. Failure Case ---

    def test_failure_case(self):
        """Tests safe handling of out-of-scope, malformed, and unreachable targets."""
        result = self.evaluator.evaluate_failure_case()

        self.assertIsInstance(result, EvaluationCaseResult)
        self.assertEqual(result.case_num, 4)
        self.assertEqual(result.case_name, "Failure Case")
        self.assertEqual(result.status, "PASS")
        for subcheck in result.subchecks:
            self.assertTrue(subcheck["passed"], f"Failed subcheck: {subcheck['check']}")

    # --- 5. Adversarial Case ---

    def test_adversarial_case(self):
        """Tests that SSRF, non-loopback IP, scheme evasion, port evasion, and flooding are blocked."""
        result = self.evaluator.evaluate_adversarial_case()

        self.assertIsInstance(result, EvaluationCaseResult)
        self.assertEqual(result.case_num, 5)
        self.assertEqual(result.case_name, "Adversarial Case")
        self.assertEqual(result.status, "PASS")
        for subcheck in result.subchecks:
            self.assertTrue(subcheck["passed"], f"Failed subcheck: {subcheck['check']}")

    # --- 6. Batch Suite Execution & Report Persistence ---

    def test_run_all_evaluations_and_persistence(self):
        """Tests full 5-case evaluation batch runner and JSON persistence."""
        report = self.evaluator.run_all_evaluations(self.target_url, persist=True)

        self.assertIsInstance(report, EvaluationReport)
        self.assertEqual(report.total_cases, 5)
        self.assertEqual(report.passed_cases, 5)
        self.assertEqual(report.failed_cases, 0)
        self.assertEqual(report.overall_status, "PASS")
        self.assertEqual(report.pass_rate, 100.0)
        self.assertEqual(len(report.cases), 5)
        self.assertIsNotNone(report.report_file)

        # Check report on disk
        report_path = Path(report.report_file)
        self.assertTrue(report_path.exists())
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["overall_status"], "PASS")
        self.assertEqual(data["total_cases"], 5)

    # --- 7. Serialization ---

    def test_case_result_serialization(self):
        """Tests to_dict serialization of case result dataclass."""
        case = EvaluationCaseResult(
            case_num=1,
            case_name="Normal Case",
            category="Test",
            vulnerabilities_covered="None",
            test_input="input",
            expected_behavior="expect",
            actual_result="actual",
            status="PASS",
        )
        d = case.to_dict()
        self.assertEqual(d["case_num"], 1)
        self.assertEqual(d["status"], "PASS")
