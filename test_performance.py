import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
import json
import os
import shutil
import tempfile
from ipaddress import IPv4Address

# Import classes and functions from the auditor file
from Ollama_Security_Auditor_Final import (
    OllamaSecurityAuditor,
    OllamaRangeScanner,
    AuditFinding,
    Severity,
    CheckStatus,
    resolve_target_url,
    validate_ip_range_static,
)

class TestOllamaSecurityAuditor(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.target_url = "http://localhost:11434"
        self.auditor = OllamaSecurityAuditor(target_url=self.target_url)
        self.session_mock = MagicMock()

        # Setup clean async context manager for session.get
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        self.session_mock.get = MagicMock(return_value=mock_response)

    async def test_resolve_target_url(self):
        self.assertEqual(resolve_target_url("127.0.0.1"), "http://127.0.0.1:11434")
        self.assertEqual(resolve_target_url("https://example.com"), "https://example.com:11434")
        self.assertEqual(resolve_target_url("http://[::1]"), "http://[::1]:11434")

    def test_validate_ip_range_static(self):
        ips = validate_ip_range_static("192.168.1.1-3")
        self.assertEqual(ips, ["192.168.1.1", "192.168.1.2", "192.168.1.3"])
        ips_cidr = validate_ip_range_static("192.168.1.0/30")
        self.assertEqual(ips_cidr, ["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"])
        ips_single = validate_ip_range_static("10.0.0.1")
        self.assertEqual(ips_single, ["10.0.0.1"])

    @patch("Ollama_Security_Auditor_Final.OllamaSecurityAuditor._safe_request")
    async def test_check_connectivity_success(self, mock_safe_request):
        mock_safe_request.return_value = (200, {"version": "0.1.45"}, "http://localhost:11434/api/version")
        finding = await self.auditor.check_connectivity(self.session_mock)
        self.assertEqual(finding.status, CheckStatus.SECURE)
        self.assertEqual(self.auditor.detected_version, "0.1.45")

    @patch("Ollama_Security_Auditor_Final.OllamaSecurityAuditor._safe_request")
    async def test_check_connectivity_failure(self, mock_safe_request):
        mock_safe_request.return_value = (None, None, "http://localhost:11434/api/version")
        finding = await self.auditor.check_connectivity(self.session_mock)
        self.assertEqual(finding.status, CheckStatus.ERROR)

    @patch("Ollama_Security_Auditor_Final.OllamaSecurityAuditor._safe_request")
    async def test_check_authentication_vulnerable(self, mock_safe_request):
        mock_safe_request.return_value = (200, {}, "")
        finding = await self.auditor.check_authentication(self.session_mock)
        self.assertEqual(finding.status, CheckStatus.VULNERABLE)
        self.assertEqual(finding.severity, Severity.CRITICAL)

    @patch("Ollama_Security_Auditor_Final.OllamaSecurityAuditor._safe_request")
    async def test_check_info_disclosure(self, mock_safe_request):
        mock_safe_request.return_value = (200, {"models": []}, "")
        finding = await self.auditor.check_info_disclosure(self.session_mock)
        self.assertEqual(finding.status, CheckStatus.VULNERABLE)
        self.assertEqual(finding.severity, Severity.HIGH)

    @patch("Ollama_Security_Auditor_Final.OllamaSecurityAuditor._safe_request")
    async def test_extract_model_configs(self, mock_safe_request):
        # Setup tags first
        mock_safe_request.side_effect = [
            (200, {"models": [{"name": "llama3"}]}, "/api/tags"),
            (200, {
                "system": "System instructions",
                "template": "template text",
                "parameters": "num_ctx 4096",
                "modelfile": "FROM base\nLICENSE custom-lic"
            }, "/api/show")
        ]

        # We need a temporary directory to avoid writing to extracted_prompts in the repo root
        temp_dir = tempfile.mkdtemp()
        try:
            with patch("os.makedirs"), patch("builtins.open", unittest.mock.mock_open()):
                findings = await self.auditor.extract_model_configs(self.session_mock)
                self.assertTrue(len(findings) > 0)
                self.assertEqual(findings[0].status, CheckStatus.WARNING)
        finally:
            shutil.rmtree(temp_dir)

    @patch("Ollama_Security_Auditor_Final.OllamaSecurityAuditor._safe_request")
    async def test_run_audit_concurrent_efficiency(self, mock_safe_request):
        # Return dummy values for tags, versions, and checks
        mock_safe_request.side_effect = lambda session, method, endpoint, **kwargs: (
            (200, {"version": "0.1.45"}, "/api/version") if "version" in endpoint else
            (200, {"models": [{"name": "test-model"}]}, "/api/tags") if "tags" in endpoint else
            (404, {}, endpoint)
        )

        with patch.object(self.auditor, "_fetch_dynamic_advisories", AsyncMock()) as mock_fetch, \
             patch.object(self.auditor, "discover_models", AsyncMock()) as mock_discover:

            # Record start time
            start = asyncio.get_event_loop().time()
            findings = await self.auditor.run_audit(self.session_mock)
            duration = asyncio.get_event_loop().time() - start

            # The audit should finish quickly since probes are mocked
            self.assertGreater(len(findings), 0)
            self.assertTrue(mock_fetch.called)
            self.assertTrue(mock_discover.called)

    async def test_metadata_endpoint_caching(self):
        # Create a mock response for session.request
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.json = AsyncMock(return_value={"version": "1.2.3"})
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        # Configure the session mock's request method
        session_mock = MagicMock()
        session_mock.request = MagicMock(return_value=mock_response)

        # Perform duplicate calls to /api/version
        status1, body1, url1 = await self.auditor._safe_request(session_mock, "GET", "/api/version")
        status2, body2, url2 = await self.auditor._safe_request(session_mock, "GET", "/api/version")

        # Verify both returned the correct data
        self.assertEqual(status1, 200)
        self.assertEqual(body1, {"version": "1.2.3"})
        self.assertEqual(status2, 200)
        self.assertEqual(body2, {"version": "1.2.3"})

        # Verify session.request was only called once due to caching
        session_mock.request.assert_called_once()

        # Verify that dynamic / unauthorized requests bypass cache
        session_mock.request.reset_mock()

        # Request with authorization header
        status3, body3, url3 = await self.auditor._safe_request(
            session_mock, "GET", "/api/version", headers={"Authorization": "Bearer token"}
        )
        self.assertEqual(status3, 200)
        session_mock.request.assert_called_once()

    async def test_dynamic_advisories_global_caching(self):
        # We need to test that _fetch_github_advisories, _fetch_nvd_advisories, _fetch_exploitdb_advisories are only called once.
        import Ollama_Security_Auditor_Final
        Ollama_Security_Auditor_Final._GLOBAL_ADVISORIES_FETCHED = False
        Ollama_Security_Auditor_Final._GLOBAL_ADVISORIES_CACHE = []

        with patch.object(self.auditor, "_fetch_github_advisories", AsyncMock(return_value=[{"cve_id": "CVE-2024-TEST", "summary": "test"}])) as mock_gh, \
             patch.object(self.auditor, "_fetch_nvd_advisories", AsyncMock(return_value=[])) as mock_nvd, \
             patch.object(self.auditor, "_fetch_exploitdb_advisories", AsyncMock(return_value=[])) as mock_edb:

            # Call 1
            await self.auditor._fetch_dynamic_advisories(self.session_mock)
            # Call 2
            await self.auditor._fetch_dynamic_advisories(self.session_mock)

            # Assert they were only called once globally
            mock_gh.assert_called_once()
            mock_nvd.assert_called_once()
            mock_edb.assert_called_once()

            # Assert cache has been populated and copied to auditor instance
            self.assertEqual(len(self.auditor._dynamic_advisories_cache), 1)
            self.assertEqual(self.auditor._dynamic_advisories_cache[0]["cve_id"], "CVE-2024-TEST")

    async def test_report_generation(self):
        # Setup sample findings
        findings = [
            AuditFinding(
                check_name="Test Auth Check", severity=Severity.CRITICAL, status=CheckStatus.VULNERABLE,
                details="Authentication is completely bypassed.", remediation="Restrict API access.",
                evidence={"exposed_endpoints": ["/api/tags"]}
            )
        ]
        temp_dir = tempfile.mkdtemp()
        try:
            output_path = os.path.join(temp_dir, "test_report")
            self.auditor.stats = {"total_checks": 1, "CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

            # Test markdown report
            report_md_path = self.auditor.generate_report(findings, output_path, format_type="md")
            self.assertTrue(os.path.exists(report_md_path))
            with open(report_md_path, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertIn("Authentication is completely bypassed.", content)
                self.assertIn("Test Auth Check", content)

            # Test JSON report
            report_json_path = self.auditor.generate_report(findings, output_path, format_type="json")
            self.assertTrue(os.path.exists(report_json_path))
            with open(report_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.assertEqual(data["findings"][0]["severity"], "CRITICAL")
                self.assertEqual(data["findings"][0]["status"], "VULNERABLE")
        finally:
            shutil.rmtree(temp_dir)

class TestOllamaRangeScanner(unittest.IsolatedAsyncioTestCase):
    @patch("Ollama_Security_Auditor_Final.OllamaRangeScanner._check_port")
    async def test_range_scanner_concurrency_control(self, mock_check_port):
        # We mock port check to always return False to avoid triggering actual scan,
        # but check that it calls open_connection concurrently.
        mock_check_port.return_value = False
        scanner = OllamaRangeScanner(timeout=0.1, max_concurrent=10)

        # Scan a range of 5 IPs
        await scanner.run("192.168.1.1-5", 11434, "")
        self.assertEqual(mock_check_port.call_count, 5)

if __name__ == "__main__":
    unittest.main()
