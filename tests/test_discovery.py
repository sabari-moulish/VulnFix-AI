"""
Unit and integration tests for the Discovery Engine.
Verifies bounded attack surface mapping, parameter extraction, and safety controls.
"""

import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import json
import requests

from modules.discovery import DiscoveryEngine, DiscoveryResult, DiscoveredEndpoint
from modules.scope_controller import ScopeController


class TestDiscoveryEngine(unittest.TestCase):

    def setUp(self):
        self.scope_controller = ScopeController()
        self.engine = DiscoveryEngine(
            scope_controller=self.scope_controller,
            max_requests=25,
            timeout=2.0,
        )
        self.lab_target = "http://127.0.0.1:5000"

    # --- 1. Authorized Target Discovery ---

    def test_authorized_target_discovery(self):
        """Tests that discovery runs successfully against an authorized target and produces evidence."""
        result = self.engine.discover(self.lab_target)

        self.assertTrue(result.success)
        self.assertIsNone(result.error)
        self.assertEqual(result.target_url, self.lab_target)
        self.assertTrue(result.scope_decision["is_allowed"])
        self.assertGreater(len(result.endpoints), 0)
        self.assertGreater(len(result.all_inputs), 0)
        self.assertGreater(result.total_requests, 0)
        self.assertIsNotNone(result.evidence_file)

        # Check evidence file on disk
        evidence_path = Path(result.evidence_file)
        self.assertTrue(evidence_path.exists())
        with open(evidence_path, "r", encoding="utf-8") as f:
            evidence_data = json.load(f)
        
        self.assertIn("timestamp", evidence_data)
        self.assertEqual(evidence_data["authorized_target"], self.lab_target)
        self.assertIn("discovered_endpoints", evidence_data)
        self.assertIn("discovered_inputs", evidence_data)
        self.assertIn("scope_decision", evidence_data)

    # --- 2. Unauthorized Target Blocked ---

    def test_unauthorized_target_blocked(self):
        """Tests that discovery strictly refuses to touch an unauthorized target and makes 0 requests."""
        unauthorized_target = "https://unauthorized-domain.com"
        result = self.engine.discover(unauthorized_target)

        self.assertFalse(result.success)
        self.assertIn("Scope violation", result.error)
        self.assertEqual(result.total_requests, 0)
        self.assertEqual(len(result.endpoints), 0)

    # --- 3. Endpoint Discovery Model Verification ---

    def test_endpoint_discovery_model(self):
        """Tests that discovered endpoints adhere to the required schema."""
        result = self.engine.discover(self.lab_target)
        self.assertTrue(result.success)

        # Find key endpoints
        endpoints_by_path = {ep["endpoint"]: ep for ep in result.endpoints}
        
        expected_routes = ["/sqli", "/xss", "/idor", "/api/health"]
        for route in expected_routes:
            self.assertIn(route, endpoints_by_path, f"Route {route} should be discovered")

        # Verify endpoint model fields
        sample_ep = endpoints_by_path["/sqli"]
        self.assertIn("endpoint", sample_ep)
        self.assertIn("method", sample_ep)
        self.assertIn("parameter_name", sample_ep)
        self.assertIn("input_location", sample_ep)
        self.assertIn("status_code", sample_ep)
        self.assertIn("content_type", sample_ep)
        self.assertIn("discovery_source", sample_ep)
        self.assertEqual(sample_ep["endpoint"], "/sqli")
        self.assertEqual(sample_ep["method"], "GET")

    # --- 4. Parameter Discovery ---

    def test_parameter_discovery(self):
        """Tests that query parameters, form fields, and path parameters are discovered."""
        result = self.engine.discover(self.lab_target)
        self.assertTrue(result.success)

        input_names = {inp["name"] for inp in result.all_inputs}
        input_locations = {inp["location"] for inp in result.all_inputs}

        # Query param from /sqli form or probe
        self.assertIn("query", input_names)
        # Query param from /xss form or probe
        self.assertIn("name", input_names)
        # Path param from /record/1 or /record/2
        self.assertIn("record_id", input_names)

        # Input locations
        self.assertIn("query_param", input_locations)
        self.assertIn("path_param", input_locations)

    # --- 5. Timeout & Failure Handling ---

    def test_timeout_failure_handling(self):
        """Tests that HTTP timeouts and network errors are handled gracefully without crashing."""
        with patch("requests.Session.get", side_effect=requests.Timeout("Simulated Connection Timeout")):
            result = self.engine.discover(self.lab_target)
            # Should not crash, returns valid result structure
            self.assertTrue(result.success)
            self.assertGreaterEqual(result.total_requests, 1)
            self.assertEqual(len(result.endpoints), 0)

    # --- 6. Redirect Outside Scope ---

    def test_redirect_outside_scope_blocked(self):
        """Tests that external redirects are blocked and recorded in redirect_violations."""
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "https://attacker-external-site.com/login", "Content-Type": "text/html"}
        mock_resp.text = "<html><body>Redirecting...</body></html>"

        with patch("requests.Session.get", return_value=mock_resp):
            result = self.engine.discover(self.lab_target)
            self.assertTrue(result.success)
            self.assertGreater(len(result.redirect_violations), 0)
            
            violation = result.redirect_violations[0]
            self.assertIn("attacker-external-site.com", violation["target"])
            self.assertIn("leaves authorized origin scope", violation["reason"])

    # --- 7. Request Limit Enforcement ---

    def test_request_limit_enforcement(self):
        """Tests that discovery strictly halts once max_requests limit is reached."""
        max_limit = 5
        limited_engine = DiscoveryEngine(
            scope_controller=self.scope_controller,
            max_requests=max_limit,
            timeout=2.0,
        )
        result = limited_engine.discover(self.lab_target)
        self.assertTrue(result.success)
        self.assertLessEqual(result.total_requests, max_limit)


if __name__ == "__main__":
    unittest.main()
