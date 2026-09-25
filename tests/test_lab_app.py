"""
Unit and integration tests for the VulnLab vulnerable test application.
Verifies the 3 demonstration scenarios (SQLi, XSS, IDOR) in both Vulnerable and Secure modes.
"""

import unittest
from lab_app.app import app
import lab_app.app as lab_module
from lab_app.database import init_db, get_db


class TestLabApp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Reset and seed database with synthetic test data
        init_db(reset=True)

    def setUp(self):
        self.client = app.test_client()
        lab_module.SECURITY_MODE = "vulnerable"

    def tearDown(self):
        lab_module.SECURITY_MODE = "vulnerable"

    # --- Database & Health Tests ---

    def test_database_synthetic_seed(self):
        """Verify that only synthetic fake data is seeded."""
        with get_db() as conn:
            cursor = conn.cursor()
            users = cursor.execute("SELECT username FROM users").fetchall()
            usernames = [u[0] for u in users]
            self.assertIn("User A", usernames)
            self.assertIn("User B", usernames)

            records = cursor.execute("SELECT record_code, organization_id FROM records").fetchall()
            record_codes = [r[0] for r in records]
            self.assertIn("REC-001", record_codes)
            self.assertIn("REC-002", record_codes)

    def test_api_health(self):
        """Test health endpoint responds."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["app"], "VulnLab Local Laboratory")

    # --- Scenario 1: SQL Injection Tests ---

    def test_sqli_vulnerable_mode(self):
        """In vulnerable mode, SQL syntax manipulation executes dynamically."""
        # Standard search
        res = self.client.get("/api/search?q=Sensor")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertGreaterEqual(data["count"], 1)

        # SQL Injection payload: ' OR '1'='1 should return all products
        res_inject = self.client.get("/api/search?q=' OR '1'='1")
        self.assertEqual(res_inject.status_code, 200)
        data_inject = res_inject.get_json()
        # All 3 products returned by boolean bypass
        self.assertEqual(data_inject["count"], 3)

    def test_sqli_secure_mode(self):
        """In secure mode, parameterized queries neutralize injection syntax."""
        lab_module.SECURITY_MODE = "secure"
        
        # Injected string is treated literally, matching 0 products
        res = self.client.get("/api/search?q=' OR '1'='1")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["count"], 0)

    # --- Scenario 2: Reflected XSS Tests ---

    def test_xss_vulnerable_mode(self):
        """In vulnerable mode, input is reflected raw without HTML entity encoding."""
        payload = "<script>var canary=1;</script>"
        res = self.client.get(f"/api/greet?name={payload}")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["reflected"], payload)
        self.assertFalse(data["is_escaped"])

        # In HTML view
        res_html = self.client.get(f"/xss?name={payload}")
        self.assertEqual(res_html.status_code, 200)
        self.assertIn(payload, res_html.get_data(as_text=True))

    def test_xss_secure_mode(self):
        """In secure mode, input is HTML entity encoded."""
        lab_module.SECURITY_MODE = "secure"
        payload = "<script>var canary=1;</script>"
        escaped_payload = "&lt;script&gt;var canary=1;&lt;/script&gt;"

        res = self.client.get(f"/api/greet?name={payload}")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["reflected"], escaped_payload)
        self.assertTrue(data["is_escaped"])

    # --- Scenario 3: Broken Access Control / IDOR Tests ---

    def test_idor_legitimate_access(self):
        """User A can legitimately access their own Organization's Record 1."""
        res = self.client.get("/api/record/1")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["record"]["id"], 1)
        self.assertFalse(data["data_leaked_across_tenancy"])

    def test_idor_vulnerable_mode_cross_tenant_leak(self):
        """In vulnerable mode, User A can fetch Record 2 belonging to Organization B."""
        res = self.client.get("/api/record/2")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["record"]["id"], 2)
        # Data leaked across tenancy
        self.assertTrue(data["data_leaked_across_tenancy"])

    def test_idor_secure_mode_blocks_cross_tenant_access(self):
        """In secure mode, cross-tenant access is blocked with 403 Forbidden."""
        lab_module.SECURITY_MODE = "secure"
        res = self.client.get("/api/record/2")
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertEqual(data["status"], 403)

    # --- Mode Toggle & Lifecycle Tests ---

    def test_toggle_security_mode(self):
        """Test API mode toggle to support Proof-of-Fix demonstration."""
        # Initial
        self.assertEqual(lab_module.SECURITY_MODE, "vulnerable")
        
        # Switch to secure
        res = self.client.post("/api/mode", json={"mode": "secure"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["security_mode"], "secure")
        self.assertEqual(lab_module.SECURITY_MODE, "secure")

        # Switch back to vulnerable
        res = self.client.post("/api/mode", json={"mode": "vulnerable"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["security_mode"], "vulnerable")
        self.assertEqual(lab_module.SECURITY_MODE, "vulnerable")


if __name__ == "__main__":
    unittest.main()
