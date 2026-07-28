import os
import sys
import unittest
import shutil
from unittest.mock import AsyncMock, MagicMock, patch
import re

import aiohttp
from Ollama_Security_Auditor_Final import OllamaSecurityAuditor, CheckStatus, Severity

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

if __name__ == "__main__":
    unittest.main()
