"""
Unit tests for strict ScopeController safety boundaries and authorized target management.
Uses Python's standard unittest framework (also compatible with pytest).
"""

import unittest
from modules.scope_controller import ScopeController


class TestScopeController(unittest.TestCase):

    def setUp(self):
        self.controller = ScopeController()

    # --- Existing 9 Tests (Preserved Exactly) ---

    def test_allow_localhost(self):
        result = self.controller.validate_target("http://localhost:5000")
        self.assertTrue(result.is_allowed)
        self.assertTrue(result.is_loopback)

    def test_allow_127_0_0_1(self):
        result = self.controller.validate_target("http://127.0.0.1:8080/api/v1/test")
        self.assertTrue(result.is_allowed)
        self.assertTrue(result.is_loopback)

    def test_reject_external_domain(self):
        result = self.controller.validate_target("https://example.com")
        self.assertFalse(result.is_allowed)
        self.assertIn("Forbidden target host", result.reason)

    def test_reject_public_ip(self):
        result = self.controller.validate_target("http://8.8.8.8:8080")
        self.assertFalse(result.is_allowed)
        self.assertIn("Forbidden target host", result.reason)

    def test_reject_cloud_metadata(self):
        result = self.controller.validate_target("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(result.is_allowed)
        self.assertIn("Forbidden target host", result.reason)

    def test_reject_disallowed_scheme(self):
        result = self.controller.validate_target("ftp://localhost:21")
        self.assertFalse(result.is_allowed)
        self.assertIn("Unsupported scheme", result.reason)

    def test_reject_disallowed_port(self):
        # Port 2222 is not in standard testbed port list
        result = self.controller.validate_target("http://localhost:2222")
        self.assertFalse(result.is_allowed)
        self.assertIn("not in the allowed local testing ports list", result.reason)

    def test_explicit_target_authorization(self):
        result = self.controller.validate_target("http://localhost:3000/app")
        self.assertTrue(result.is_allowed)

    def test_reject_external_addition_in_strict_mode(self):
        result = self.controller.add_explicit_target("https://malicious-or-remote.com:8080")
        self.assertFalse(result.is_allowed)
        self.assertIn("Strict local-only mode rejects non-local hosts", result.reason)

    # --- New Target Authorization & Scope Management Tests ---

    def test_valid_localhost_target(self):
        """Tests valid localhost target without explicit port (defaults to 80)."""
        result = self.controller.validate_target("http://localhost")
        self.assertTrue(result.is_allowed)
        self.assertEqual(result.normalized_host, "localhost")
        self.assertEqual(result.port, 80)
        self.assertTrue(result.is_loopback)

    def test_valid_127_0_0_1_target(self):
        """Tests valid 127.0.0.1 target without explicit port (defaults to 80)."""
        result = self.controller.validate_target("http://127.0.0.1")
        self.assertTrue(result.is_allowed)
        self.assertEqual(result.normalized_host, "127.0.0.1")
        self.assertEqual(result.port, 80)
        self.assertTrue(result.is_loopback)

    def test_explicitly_configured_authorized_target(self):
        """Tests adding and validating a custom authorized local testbed."""
        target = "http://localhost:8443"
        add_res = self.controller.add_explicit_target(target)
        self.assertTrue(add_res.is_allowed)
        self.assertIn(target, self.controller.get_authorized_targets())

        # Validate that checking this target now succeeds
        check_res = self.controller.validate_target(f"{target}/api/v1/auth")
        self.assertTrue(check_res.is_allowed)

    def test_unauthorized_target(self):
        """Tests rejection of an unauthorized internal network target or non-allowed port."""
        # Non-loopback LAN IP
        result_lan = self.controller.validate_target("http://192.168.1.50:8080")
        self.assertFalse(result_lan.is_allowed)
        self.assertIn("Forbidden target host", result_lan.reason)

        # Disallowed port
        result_port = self.controller.validate_target("http://127.0.0.1:44444")
        self.assertFalse(result_port.is_allowed)
        self.assertIn("not in the allowed local testing ports list", result_port.reason)

    def test_malformed_url(self):
        """Tests rejection of malformed or empty URLs."""
        # Empty string
        res_empty = self.controller.validate_target("")
        self.assertFalse(res_empty.is_allowed)

        # Whitespace
        res_spaces = self.controller.validate_target("   ")
        self.assertFalse(res_spaces.is_allowed)

        # Missing scheme
        res_no_scheme = self.controller.validate_target("not_a_valid_url")
        self.assertFalse(res_no_scheme.is_allowed)

        # Incomplete scheme/netloc
        res_incomplete = self.controller.validate_target("http://")
        self.assertFalse(res_incomplete.is_allowed)

    def test_external_public_target(self):
        """Tests strict rejection of public web targets and public IPs."""
        public_targets = [
            "https://google.com",
            "http://1.1.1.1:80",
            "https://github.com/login",
            "http://54.239.28.85:8080",
        ]
        for target in public_targets:
            res = self.controller.validate_target(target)
            self.assertFalse(res.is_allowed, f"Target {target} should be rejected")
            self.assertIn("Forbidden target host", res.reason)

    def test_scope_decision_audit_log(self):
        """Tests that scope decisions are recorded with timestamp, target, operation, decision, reason."""
        target = "http://localhost:5000"
        self.controller.authorize_operation(target, operation="UNIT_TEST_DISCOVERY")
        
        logs = self.controller.get_audit_logs(limit=10)
        self.assertTrue(len(logs) > 0)
        
        matching = [l for l in logs if l["operation"] == "UNIT_TEST_DISCOVERY" and l["target"] == target]
        self.assertTrue(len(matching) > 0)
        entry = matching[0]
        
        self.assertIn("timestamp", entry)
        self.assertEqual(entry["target"], target)
        self.assertEqual(entry["operation"], "UNIT_TEST_DISCOVERY")
        self.assertEqual(entry["decision"], "ALLOWED")
        self.assertIn("reason", entry)

    def test_target_selection_and_status(self):
        """Tests target selection and status reporting."""
        # Valid selection
        val_res = self.controller.set_selected_target("http://localhost:5000")
        self.assertTrue(val_res.is_allowed)
        self.assertEqual(self.controller.get_selected_target(), "http://localhost:5000")
        
        status = self.controller.get_target_status()
        self.assertTrue(status["is_authorized"])
        self.assertEqual(status["status_text"], "AUTHORIZED")

        # Invalid selection should be rejected and not overwrite valid target
        invalid_res = self.controller.set_selected_target("https://unauthorized-domain.com")
        self.assertFalse(invalid_res.is_allowed)
        self.assertEqual(self.controller.get_selected_target(), "http://localhost:5000")

    def test_authorize_operation_blocks_unauthorized(self):
        """Tests that authorize_operation strictly blocks unauthorized targets and logs REJECTED."""
        target = "http://8.8.8.8:8080"
        res = self.controller.authorize_operation(target, operation="INVASIVE_OPERATION")
        self.assertFalse(res.is_allowed)
        
        logs = self.controller.get_audit_logs(limit=5)
        matching = [l for l in logs if l["target"] == target and l["operation"] == "INVASIVE_OPERATION"]
        self.assertTrue(len(matching) > 0)
        self.assertEqual(matching[0]["decision"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
