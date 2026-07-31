import os
import sys
import unittest
import shutil
from unittest.mock import AsyncMock, MagicMock, patch
import re

import aiohttp
from Ollama_Security_Auditor_Final import OllamaSecurityAuditor, CheckStatus, Severity, validate_ip_range_static

# Context manager mock for aiohttp request
class MockRequestCtx:
    def __init__(self, response):
        self.response = response
    async def __aenter__(self):
        return self.response
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

class TestOllamaAuditorSecurity(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.target_url = "http://localhost:11434"
        self.auditor = OllamaSecurityAuditor(self.target_url)
        # Ensure extracted_prompts directory doesn't exist or is clean
        self.prompts_dir = "extracted_prompts"
        if os.path.exists(self.prompts_dir):
            shutil.rmtree(self.prompts_dir)

    def tearDown(self):
        if os.path.exists(self.prompts_dir):
            shutil.rmtree(self.prompts_dir)

    async def test_safe_request_read_body_true(self):
        """Test _safe_request with read_body=True parses JSON body."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {}
        expected_json = {"version": "0.1.48"}
        mock_response.json = AsyncMock(return_value=expected_json)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=MockRequestCtx(mock_response))

        status, body, url = await self.auditor._safe_request(
            mock_session, "GET", "/api/version", read_body=True
        )

        self.assertEqual(status, 200)
        self.assertEqual(body, expected_json)
        mock_response.json.assert_called_once()

    async def test_safe_request_read_body_false(self):
        """Test _safe_request with read_body=False does NOT read response body."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.json = AsyncMock()

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=MockRequestCtx(mock_response))

        status, body, url = await self.auditor._safe_request(
            mock_session, "GET", "/api/blobs/sha256:123", read_body=False
        )

        self.assertEqual(status, 200)
        self.assertIsNone(body)
        mock_response.json.assert_not_called()

    async def test_extract_model_configs_safepath(self):
        """Test standard model config extraction writes files to extracted_prompts."""
        # Mock GET /api/tags
        mock_response_tags = MagicMock()
        mock_response_tags.status = 200
        mock_response_tags.headers = {}
        mock_response_tags.json = AsyncMock(return_value={
            "models": [{"name": "llama3:latest"}]
        })

        # Mock POST /api/show
        mock_response_show = MagicMock()
        mock_response_show.status = 200
        mock_response_show.headers = {}
        mock_response_show.json = AsyncMock(return_value={
            "system": "You are a helpful assistant.",
            "template": "...",
            "parameters": "num_predict 256",
            "modelfile": "FROM llama3"
        })

        # We need to construct a session that returns tags first, then show
        mock_session = MagicMock()

        # When called first for /api/tags (GET), then for /api/show (POST)
        async def side_effect(method, url, **kwargs):
            if "/api/tags" in url:
                return mock_response_tags
            elif "/api/show" in url:
                return mock_response_show
            raise ValueError(f"Unexpected URL: {url}")

        mock_session.request = MagicMock(side_effect=lambda method, url, **kwargs: MockRequestCtx(
            mock_response_tags if "/api/tags" in url else mock_response_show
        ))

        findings = await self.auditor.extract_model_configs(mock_session)

        # File should be created in extracted_prompts/llama3_latest.md
        expected_path = os.path.join(self.prompts_dir, "llama3_latest.md")
        self.assertTrue(os.path.exists(expected_path))
        with open(expected_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("You are a helpful assistant.", content)

    async def test_extract_model_configs_directory_traversal_prevention(self):
        """Test directory traversal prevention blocks writing outside extracted_prompts."""
        # Mock GET /api/tags with a model name that tries to do directory traversal
        mock_response_tags = MagicMock()
        mock_response_tags.status = 200
        mock_response_tags.headers = {}
        mock_response_tags.json = AsyncMock(return_value={
            "models": [{"name": "traversal_model"}]
        })

        mock_response_show = MagicMock()
        mock_response_show.status = 200
        mock_response_show.headers = {}
        mock_response_show.json = AsyncMock(return_value={
            "system": "system prompt",
            "template": "template",
            "parameters": "parameters",
            "modelfile": "modelfile"
        })

        mock_session = MagicMock()
        mock_session.request = MagicMock(side_effect=lambda method, url, **kwargs: MockRequestCtx(
            mock_response_tags if "/api/tags" in url else mock_response_show
        ))

        # We will patch re.sub to return a path-traversal sequence "../../traversal_test"
        # when it is called to sanitize the model name.
        # This will construct prompt_path = os.path.join("extracted_prompts", "../../traversal_test.md")
        original_re_sub = re.sub
        def mock_re_sub(pattern, repl, string, *args, **kwargs):
            if string == "traversal_model":
                return "../../traversal_test"
            return original_re_sub(pattern, repl, string, *args, **kwargs)

        with patch("re.sub", side_effect=mock_re_sub):
            findings = await self.auditor.extract_model_configs(mock_session)

        # Ensure that no file was written outside extracted_prompts
        traversal_file_path = os.path.abspath(os.path.join(self.prompts_dir, "../../traversal_test.md"))
        self.assertFalse(os.path.exists(traversal_file_path))

        # Verify that the directory itself was not escaped
        self.assertEqual(len(os.listdir(self.prompts_dir)), 0)

    def test_validate_ip_range_static_limits(self):
        """Test that validate_ip_range_static prevents OOM via large range limits."""
        # 1. Safe CIDR range should pass
        ips = validate_ip_range_static("192.168.1.0/24")
        self.assertEqual(len(ips), 256)

        # 2. Too large CIDR range should raise ValueError
        with self.assertRaises(ValueError) as ctx:
            validate_ip_range_static("10.0.0.0/8")
        self.assertIn("IP range too large", str(ctx.exception))

        # 3. Safe hyphen range should pass
        ips = validate_ip_range_static("192.168.1.1-100")
        self.assertEqual(len(ips), 100)

        # 4. Too large hyphen range should raise ValueError
        with self.assertRaises(ValueError) as ctx:
            validate_ip_range_static("10.0.0.1-10.5.0.1")
        self.assertIn("IP range too large", str(ctx.exception))

    async def test_safe_request_oom_prevention_via_content_length(self):
        """Test that _safe_request skips reading the body if Content-Length exceeds 10MB."""
        mock_response = MagicMock()
        mock_response.status = 200
        # 11MB Content-Length
        mock_response.headers = {'Content-Length': str(11 * 1024 * 1024)}
        mock_response.json = AsyncMock()

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=MockRequestCtx(mock_response))

        status, body, url = await self.auditor._safe_request(
            mock_session, "GET", "/api/version", read_body=True
        )

        self.assertEqual(status, 200)
        self.assertIsNone(body)
        mock_response.json.assert_not_called()

    async def test_safe_request_oom_prevention_via_stream_read(self):
        """Test that _safe_request skips parsing if the streamed content exceeds 10MB."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {}
        # Set our flag to force stream reading
        mock_response._test_stream_read = True

        # Mock response.content.read to return more than 10MB
        # Let's return 10MB + 1 bytes of dummy content
        oversized_content = b"a" * (10 * 1024 * 1024 + 1)
        mock_response.content = MagicMock()
        mock_response.content.read = AsyncMock(return_value=oversized_content)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=MockRequestCtx(mock_response))

        status, body, url = await self.auditor._safe_request(
            mock_session, "GET", "/api/version", read_body=True
        )

        self.assertEqual(status, 200)
        self.assertIsNone(body)

    async def test_safe_request_successful_stream_read(self):
        """Test that _safe_request successfully reads and parses a safe stream response under 10MB."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response._test_stream_read = True

        mock_response.content = MagicMock()
        mock_response.content.read = AsyncMock(return_value=b'{"status": "ok"}')

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=MockRequestCtx(mock_response))

        status, body, url = await self.auditor._safe_request(
            mock_session, "GET", "/api/version", read_body=True
        )

        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok"})

    async def test_external_advisories_use_safe_request(self):
        """Test that _fetch_github_advisories, _fetch_nvd_advisories, and _fetch_exploitdb_advisories leverage _safe_request."""
        with patch.object(self.auditor, "_safe_request", AsyncMock()) as mock_safe_request:
            # 1. GH Advisories
            mock_safe_request.return_value = (200, [{"ghsa_id": "GHSA-123", "summary": "test advis", "description": "desc"}], "")
            mock_session = MagicMock()
            findings_gh = await self.auditor._fetch_github_advisories(mock_session)
            mock_safe_request.assert_called_with(
                mock_session, "GET", "https://api.github.com/repos/ollama/ollama/security/advisories?state=open&per_page=10",
                headers={"Accept": "application/vnd.github+json", "User-Agent": "OllamaAuditor/1.5"}, timeout_override=5.0
            )
            self.assertEqual(len(findings_gh), 1)
            self.assertEqual(findings_gh[0]["cve_id"], "GHSA-123")

            # 2. NVD Advisories
            mock_safe_request.reset_mock()
            mock_safe_request.return_value = (200, {
                "vulnerabilities": [{"cve": {"id": "CVE-2024-9999", "descriptions": [{"value": "test desc"}]}}]
            }, "")
            findings_nvd = await self.auditor._fetch_nvd_advisories(mock_session)
            mock_safe_request.assert_called_with(
                mock_session, "GET", "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=ollama&resultsPerPage=5",
                timeout_override=5.0
            )
            self.assertEqual(len(findings_nvd), 1)
            self.assertEqual(findings_nvd[0]["cve_id"], "CVE-2024-9999")

            # 3. ExploitDB Advisories
            mock_safe_request.reset_mock()
            mock_safe_request.return_value = (200, {
                "data": [{"id": "12345", "title": "RCE exploit", "description": "vuln details"}]
            }, "")
            findings_edb = await self.auditor._fetch_exploitdb_advisories(mock_session)
            mock_safe_request.assert_called_with(
                mock_session, "GET", "https://www.exploit-db.com/api/v1/exploits?search=ollama&pageSize=5",
                headers={"Accept": "application/json", "User-Agent": "OllamaAuditor/1.5"}, timeout_override=5.0
            )
            self.assertEqual(len(findings_edb), 1)
            self.assertEqual(findings_edb[0]["cve_id"], "EDB-12345")

if __name__ == "__main__":
    unittest.main()
