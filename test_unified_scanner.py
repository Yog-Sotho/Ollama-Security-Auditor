"""
Comprehensive test suite for Ollama Unified Security Scanner v2.0.0
Merges and extends tests from both source repos.
"""
import asyncio
import json
import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Import under test
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(__file__))
import ollama_unified_scanner as ous


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class MockResponse:
    """Minimal aiohttp.ClientResponse mock."""

    def __init__(
        self,
        status: int,
        json_data=None,
        headers=None,
        raise_on_read: Exception = None,
        content_length: str = None,
    ):
        self.status = status
        self._json_data = json_data
        self.headers = headers or {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length
        self._raise_on_read = raise_on_read
        self.content = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def json(self):
        if self._raise_on_read:
            raise self._raise_on_read
        return self._json_data

    async def read(self, n=-1):
        if self._raise_on_read:
            raise self._raise_on_read
        raw = json.dumps(self._json_data).encode() if self._json_data else b"{}"
        return raw[:n] if n != -1 else raw


class MockSession:
    def __init__(self, responses: dict):
        self._responses = responses
        self._calls: list = []

    def request(self, method, url, **kwargs):
        self._calls.append((method, url))
        resp = self._responses.get(url) or self._responses.get("*")
        if resp is None:
            resp = MockResponse(404)
        return resp

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


# ---------------------------------------------------------------------------
# Sanitization tests
# ---------------------------------------------------------------------------

class TestSanitizeText(unittest.TestCase):

    def test_ansi_escape_removed(self):
        self.assertEqual(ous.sanitize_text("\x1b[31mhello\x1b[0m"), "hello")

    def test_soft_hyphen_removed(self):
        self.assertEqual(ous.sanitize_text("hello\xadworld"), "helloworld")

    def test_zero_width_space_removed(self):
        self.assertEqual(ous.sanitize_text("hello​world"), "helloworld")

    def test_zero_width_non_joiner_removed(self):
        self.assertEqual(ous.sanitize_text("hello‌world"), "helloworld")

    def test_zero_width_joiner_removed(self):
        self.assertEqual(ous.sanitize_text("hello‍world"), "helloworld")

    def test_ltr_mark_removed(self):
        self.assertEqual(ous.sanitize_text("hello‎world"), "helloworld")

    def test_rtl_mark_removed(self):
        self.assertEqual(ous.sanitize_text("hello‏world"), "helloworld")

    def test_word_joiner_removed(self):
        self.assertEqual(ous.sanitize_text("hello⁠world"), "helloworld")

    def test_bidi_isolate_removed(self):
        self.assertEqual(ous.sanitize_text("hello⁦world"), "helloworld")

    def test_bom_removed(self):
        self.assertEqual(ous.sanitize_text("hello﻿world"), "helloworld")

    def test_newline_removed(self):
        self.assertEqual(ous.sanitize_text("hello\nworld"), "helloworld")

    def test_max_len_truncates(self):
        result = ous.sanitize_text("a" * 2000, max_len=100)
        self.assertLessEqual(len(result), 100)

    def test_non_str_coerced(self):
        result = ous.sanitize_text(42)
        self.assertEqual(result, "42")

    def test_clean_string_unchanged(self):
        self.assertEqual(ous.sanitize_text("hello world"), "hello world")


class TestSanitizeHelpers(unittest.TestCase):

    def test_sanitize_version_whitelist(self):
        self.assertEqual(ous.sanitize_version("1.2.3"), "1.2.3")
        self.assertEqual(ous.sanitize_version("0.6.0-rc1"), "0.6.0-rc1")

    def test_sanitize_version_path_traversal(self):
        result = ous.sanitize_version("1.2.3/../../../etc/passwd")
        self.assertNotIn("/", result)

    def test_sanitize_model_name(self):
        self.assertEqual(ous.sanitize_model_name("llama3:8b"), "llama3:8b")
        self.assertEqual(ous.sanitize_model_name("namespace/model:tag"), "namespace/model:tag")

    def test_sanitize_model_name_path_traversal(self):
        result = ous.sanitize_model_name("../../etc/shadow")
        self.assertNotIn("..", result)

    def test_sanitize_digest_valid(self):
        d = "sha256:abc123def456"
        self.assertEqual(ous.sanitize_digest(d), d)

    def test_sanitize_digest_injection(self):
        result = ous.sanitize_digest("sha256:abc; rm -rf /")
        self.assertNotIn(";", result)
        self.assertNotIn(" ", result)

    def test_safe_display_truncates(self):
        long_str = "a" * 200
        result = ous.safe_display(long_str, max_len=48)
        self.assertIn("truncated", result)
        self.assertLessEqual(len(result), 60)

    def test_safe_display_short_unchanged(self):
        self.assertEqual(ous.safe_display("hello", max_len=48), "hello")


# ---------------------------------------------------------------------------
# IP range / CIDR utilities
# ---------------------------------------------------------------------------

class TestValidateIpRangeStatic(unittest.TestCase):

    def test_single_ipv4(self):
        result = list(ous.validate_ip_range_static("192.168.1.1"))
        self.assertEqual(result, [("192.168.1.1", "IPv4")])

    def test_cidr_v4_small(self):
        result = list(ous.validate_ip_range_static("192.168.1.0/30"))
        ips = [r[0] for r in result]
        self.assertIn("192.168.1.0", ips)
        self.assertIn("192.168.1.3", ips)
        self.assertEqual(len(result), 4)

    def test_dash_range_suffix(self):
        result = list(ous.validate_ip_range_static("10.0.0.1-5"))
        ips = [r[0] for r in result]
        self.assertEqual(ips, ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"])

    def test_dash_range_full(self):
        result = list(ous.validate_ip_range_static("10.0.0.1-10.0.0.3"))
        ips = [r[0] for r in result]
        self.assertEqual(ips, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_single_ipv6(self):
        result = list(ous.validate_ip_range_static("::1"))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][1], "IPv6")

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            list(ous.validate_ip_range_static(""))

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            list(ous.validate_ip_range_static("not-an-ip"))

    def test_dash_inverted_raises(self):
        with self.assertRaises(ValueError):
            list(ous.validate_ip_range_static("10.0.0.5-10.0.0.1"))


class TestCountIpsInRangeStatic(unittest.TestCase):

    def test_single_ip(self):
        self.assertEqual(ous.count_ips_in_range_static("192.168.1.1"), 1)

    def test_cidr_v4_slash30(self):
        self.assertEqual(ous.count_ips_in_range_static("192.168.1.0/30"), 4)

    def test_cidr_v4_slash24(self):
        self.assertEqual(ous.count_ips_in_range_static("192.168.1.0/24"), 256)

    def test_dash_range(self):
        self.assertEqual(ous.count_ips_in_range_static("10.0.0.1-10"), 10)

    def test_dash_range_full(self):
        self.assertEqual(ous.count_ips_in_range_static("10.0.0.1-10.0.0.5"), 5)


class TestParseIpFromInput(unittest.TestCase):

    def test_single_ip(self):
        result = list(ous.parse_ip_from_input("10.0.0.1"))
        self.assertEqual(result, [("10.0.0.1", "IPv4")])

    def test_cidr(self):
        result = list(ous.parse_ip_from_input("10.0.0.0/30"))
        self.assertEqual(len(result), 4)

    def test_file_input(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as fh:
            fh.write("# comment\n")
            fh.write("10.0.0.1\n")
            fh.write("10.0.0.2\n")
            fname = fh.name
        try:
            result = list(ous.parse_ip_from_input(fname, is_file=True))
            ips = [r[0] for r in result]
            self.assertIn("10.0.0.1", ips)
            self.assertIn("10.0.0.2", ips)
        finally:
            os.unlink(fname)

    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            list(ous.parse_ip_from_input("/nonexistent/path.txt", is_file=True))


# ---------------------------------------------------------------------------
# URL utilities
# ---------------------------------------------------------------------------

class TestResolveTargetUrl(unittest.TestCase):

    def test_bare_ip(self):
        self.assertEqual(ous.resolve_target_url("192.168.1.100"), "http://192.168.1.100:11434")

    def test_ip_with_port(self):
        self.assertEqual(ous.resolve_target_url("192.168.1.100:8080"), "http://192.168.1.100:8080")

    def test_already_http(self):
        self.assertEqual(
            ous.resolve_target_url("http://192.168.1.100:11434"),
            "http://192.168.1.100:11434",
        )

    def test_https_preserved(self):
        result = ous.resolve_target_url("https://example.com")
        self.assertTrue(result.startswith("https://"))

    def test_unsupported_scheme_raises(self):
        with self.assertRaises(ValueError):
            ous.resolve_target_url("ftp://192.168.1.100")

    def test_trailing_slash_stripped(self):
        result = ous.resolve_target_url("192.168.1.100/")
        self.assertFalse(result.endswith("/"))


class TestFormatTargetUrl(unittest.TestCase):

    def test_ipv4(self):
        self.assertEqual(ous.format_target_url("192.168.1.1", 11434), "http://192.168.1.1:11434")

    def test_ipv6_explicit(self):
        self.assertEqual(
            ous.format_target_url("::1", 11434, is_ipv6=True),
            "http://[::1]:11434",
        )

    def test_ipv6_auto_detect(self):
        result = ous.format_target_url("fd00::1", 11434)
        self.assertIn("[", result)
        self.assertIn("]", result)


# ---------------------------------------------------------------------------
# Version utilities
# ---------------------------------------------------------------------------

class TestVersionParsing(unittest.TestCase):

    def test_basic_tuple(self):
        self.assertEqual(ous._parse_version_tuple("0.3.14"), (0, 3, 14))

    def test_pads_short(self):
        self.assertEqual(ous._parse_version_tuple("1.0"), (1, 0, 0))

    def test_rc_stripped(self):
        t = ous._parse_version_tuple("0.6.0-rc1")
        self.assertEqual(t[:3], (0, 6, 0))

    def test_in_range_lt(self):
        self.assertTrue(ous._version_in_range("0.3.0", "<0.3.14"))

    def test_not_in_range_lt(self):
        self.assertFalse(ous._version_in_range("0.3.14", "<0.3.14"))

    def test_in_range_gte_lte(self):
        self.assertTrue(ous._version_in_range("0.3.0", ">=0.1.0,<0.3.14"))

    def test_exact_match(self):
        self.assertTrue(ous._version_in_range("1.2.3", "==1.2.3"))
        self.assertFalse(ous._version_in_range("1.2.4", "==1.2.3"))


# ---------------------------------------------------------------------------
# Secure file write
# ---------------------------------------------------------------------------

class TestSecureWriteFile(unittest.TestCase):

    def test_creates_file_with_restricted_perms(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test_secure.txt")
            ous._secure_write_file(path, "hello")
            self.assertTrue(os.path.exists(path))
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)
            with open(path, "r") as fh:
                self.assertEqual(fh.read(), "hello")

    def test_overwrites_existing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "overwrite.txt")
            ous._secure_write_file(path, "first")
            ous._secure_write_file(path, "second")
            with open(path, "r") as fh:
                self.assertEqual(fh.read(), "second")


# ---------------------------------------------------------------------------
# OllamaSecurityAuditor — unit tests
# ---------------------------------------------------------------------------

class TestAuditorInit(unittest.TestCase):

    def test_resolves_bare_ip(self):
        a = ous.OllamaSecurityAuditor("192.168.1.100")
        self.assertEqual(a.base_url, "http://192.168.1.100:11434")

    def test_deep_mode_flag(self):
        a = ous.OllamaSecurityAuditor("192.168.1.100", deep_mode=True)
        self.assertTrue(a.deep_mode)


class TestAuditorSafeRequest(unittest.IsolatedAsyncioTestCase):

    async def test_returns_body_on_200(self):
        auditor = ous.OllamaSecurityAuditor("192.168.1.100")
        resp = MockResponse(200, {"version": "0.5.0"})
        session = MockSession({"*": resp})
        status, body, url = await auditor._safe_request(session, "GET", "/api/version")
        self.assertEqual(status, 200)
        self.assertEqual(body["version"], "0.5.0")

    async def test_returns_none_on_timeout(self):
        auditor = ous.OllamaSecurityAuditor("192.168.1.100", timeout=1.0)

        class TimeoutSession:
            def request(self, method, url, **kwargs):
                raise asyncio.TimeoutError()

            def get(self, url, **kwargs):
                raise asyncio.TimeoutError()

        status, body, _ = await auditor._safe_request(TimeoutSession(), "GET", "/api/version")
        self.assertIsNone(status)

    async def test_oom_guard_content_length(self):
        auditor = ous.OllamaSecurityAuditor("192.168.1.100")
        resp = MockResponse(200, {"data": "x"}, content_length="99999999")
        session = MockSession({"*": resp})
        status, body, _ = await auditor._safe_request(session, "GET", "/api/tags")
        self.assertEqual(status, 200)
        self.assertIsNone(body)

    async def test_oom_guard_stream_read(self):
        auditor = ous.OllamaSecurityAuditor("192.168.1.100")
        big_data = b"x" * (10 * 1024 * 1024 + 1)

        class BigResponse(MockResponse):
            async def read(self, n=-1):
                return big_data[:n] if n != -1 else big_data

        resp = BigResponse(200)
        resp._test_stream_read = True
        session = MockSession({"*": resp})
        status, body, _ = await auditor._safe_request(session, "GET", "/api/tags")
        self.assertEqual(status, 200)
        self.assertIsNone(body)

    async def test_caches_get_api_tags(self):
        auditor = ous.OllamaSecurityAuditor("192.168.1.100")
        resp = MockResponse(200, {"models": []})
        session = MockSession({f"{auditor.base_url}/api/tags": resp})
        s1, b1, _ = await auditor._safe_request(session, "GET", "/api/tags")
        s2, b2, _ = await auditor._safe_request(session, "GET", "/api/tags")
        self.assertEqual(s1, 200)
        self.assertEqual(s2, 200)


class TestAuditorChecks(unittest.IsolatedAsyncioTestCase):

    async def _make_auditor(self):
        a = ous.OllamaSecurityAuditor("192.168.1.100")
        a.detected_version = "0.3.0"
        a.discovered_models = ["llama3:8b"]
        a._dynamic_advisories_cache = []
        return a

    async def test_check_authentication_vulnerable(self):
        a = await self._make_auditor()
        resp_200 = MockResponse(200, {"models": []})
        session = MockSession({"*": resp_200})
        finding = await a.check_authentication(session)
        self.assertEqual(finding.status, ous.CheckStatus.VULNERABLE)

    async def test_check_authentication_secure(self):
        a = await self._make_auditor()
        session = MockSession({"*": MockResponse(401)})
        finding = await a.check_authentication(session)
        self.assertEqual(finding.status, ous.CheckStatus.SECURE)

    async def test_check_cors_wildcard(self):
        import aiohttp
        a = await self._make_auditor()

        class WildcardCorsResp:
            status = 200
            headers = {"access-control-allow-origin": "*"}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        def fake_get(self_sess, url, **kwargs):
            return WildcardCorsResp()

        with patch.object(aiohttp.ClientSession, "get", fake_get):
            async with aiohttp.ClientSession() as sess:
                finding = await a.check_cors_policy(sess)

        self.assertEqual(finding.status, ous.CheckStatus.VULNERABLE)

    async def test_check_known_cves_matches_range(self):
        a = await self._make_auditor()
        a.detected_version = "0.3.0"
        session = MockSession({"*": MockResponse(404)})
        findings = await a.check_known_cves(session)
        cve_ids = [f.cve_id for f in findings]
        self.assertIn("CVE-2024-37032", cve_ids)

    async def test_check_known_cves_safe_version(self):
        a = await self._make_auditor()
        a.detected_version = "1.0.0"
        session = MockSession({"*": MockResponse(404)})
        findings = await a.check_known_cves(session)
        # Version 1.0.0 is outside all static CVE ranges; only behavioral probes
        # may still fire (they test behavior, not version). No version-matched hits.
        static_ver_hits = [
            f for f in findings
            if f.evidence and "affected_range" in f.evidence
            and ous._version_in_range("1.0.0", f.evidence["affected_range"])
        ]
        self.assertEqual(len(static_ver_hits), 0)

    async def test_check_dangerous_endpoints_exposed(self):
        a = await self._make_auditor()
        session = MockSession({"*": MockResponse(200, {})})
        finding = await a.check_dangerous_endpoints(session)
        self.assertEqual(finding.status, ous.CheckStatus.VULNERABLE)

    async def test_check_dangerous_endpoints_blocked(self):
        a = await self._make_auditor()
        session = MockSession({"*": MockResponse(401)})
        finding = await a.check_dangerous_endpoints(session)
        self.assertEqual(finding.status, ous.CheckStatus.SECURE)

    async def test_model_config_extraction_directory_traversal_blocked(self):
        a = await self._make_auditor()
        traversal_name = "../../../../etc/passwd"
        body = {
            "models": [{"name": traversal_name}],
        }
        show_resp = MockResponse(200, {
            "system": "test", "template": "", "parameters": "", "modelfile": ""
        })
        session = MockSession({
            f"{a.base_url}/api/tags": MockResponse(200, body),
            f"{a.base_url}/api/show": show_resp,
            "*": show_resp,
        })

        with tempfile.TemporaryDirectory() as tmpdir:
            orig_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                await a.extract_model_configs(session)
                # Ensure no file was written outside extracted_prompts
                prompts_dir = os.path.join(tmpdir, "extracted_prompts")
                if os.path.exists(prompts_dir):
                    for fname in os.listdir(prompts_dir):
                        self.assertFalse(fname.startswith(".."))
            finally:
                os.chdir(orig_cwd)

    async def test_check_waf_rate_limit_no_headers(self):
        a = await self._make_auditor()
        a._waf_detected = False
        a._rate_limit_detected = False
        finding = await a.check_waf_rate_limit()
        self.assertEqual(finding.status, ous.CheckStatus.SECURE)

    async def test_check_waf_rate_limit_detected(self):
        a = await self._make_auditor()
        a._waf_detected = True
        a._rate_limit_detected = False
        finding = await a.check_waf_rate_limit()
        self.assertIn("WAF", finding.details)

    async def test_check_modelfile_rce_rejected(self):
        a = await self._make_auditor()
        resp = MockResponse(400, {"error": "RUN not permitted"})
        session = MockSession({"*": resp})
        finding = await a.check_modelfile_rce(session)
        self.assertEqual(finding.status, ous.CheckStatus.SECURE)

    async def test_check_modelfile_rce_accepted(self):
        a = await self._make_auditor()
        resp = MockResponse(200, {})
        session = MockSession({"*": resp})
        finding = await a.check_modelfile_rce(session)
        self.assertEqual(finding.status, ous.CheckStatus.VULNERABLE)

    async def test_check_token_brute_blocked(self):
        a = await self._make_auditor()
        session = MockSession({"*": MockResponse(401)})
        finding = await a.check_token_brute(session)
        self.assertEqual(finding.status, ous.CheckStatus.SECURE)

    async def test_ssrf_skipped_without_deep(self):
        a = await self._make_auditor()
        a.deep_mode = False
        session = MockSession({"*": MockResponse(404)})
        finding = await a.check_cloud_metadata_ssrf(session)
        self.assertEqual(finding.status, ous.CheckStatus.SKIPPED)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

class TestReportGeneration(unittest.TestCase):

    def _make_auditor_with_findings(self):
        a = ous.OllamaSecurityAuditor("192.168.1.100")
        a.target_ip_display = "192.168.1.100:11434"
        a.detected_version = "0.3.0"
        a.discovered_models = ["llama3:8b"]
        a.loaded_models = []
        a.stats = {
            "total_checks": 2,
            "CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "INFO": 0,
        }
        findings = [
            ous.AuditFinding(
                check_name="Test Finding",
                severity=ous.Severity.CRITICAL,
                status=ous.CheckStatus.VULNERABLE,
                details="A critical test finding",
                remediation="Fix it now",
                cve_id="CVE-2024-TEST",
            ),
            ous.AuditFinding(
                check_name="Secure Check",
                severity=ous.Severity.LOW,
                status=ous.CheckStatus.SECURE,
                details="All good",
                remediation="N/A",
            ),
        ]
        return a, findings

    def test_md_report_returns_abs_path(self):
        a, findings = self._make_auditor_with_findings()
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "test_report")
            path = a.generate_report(findings, out, "md")
            self.assertTrue(os.path.isabs(path))
            self.assertTrue(os.path.exists(path))

    def test_md_report_contains_cve(self):
        a, findings = self._make_auditor_with_findings()
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "test_report")
            path = a.generate_report(findings, out, "md")
            with open(path, "r") as fh:
                content = fh.read()
            self.assertIn("CVE-2024-TEST", content)
            # Severity label appears as "Critical" in stats section
            self.assertIn("Critical", content)
            # Status appears as VULNERABLE in findings
            self.assertIn("VULNERABLE", content)

    def test_json_report_valid(self):
        a, findings = self._make_auditor_with_findings()
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "test_report")
            path = a.generate_report(findings, out, "json")
            with open(path, "r") as fh:
                data = json.load(fh)
            self.assertIn("findings", data)
            self.assertIn("metadata", data)
            self.assertEqual(data["findings"][0]["cve_id"], "CVE-2024-TEST")

    def test_json_report_secure_perms(self):
        a, findings = self._make_auditor_with_findings()
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "test_report")
            path = a.generate_report(findings, out, "json")
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)

    def test_unsupported_format_raises(self):
        a, findings = self._make_auditor_with_findings()
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "test")
            with self.assertRaises(ValueError):
                a.generate_report(findings, out, "xml")


# ---------------------------------------------------------------------------
# LLMDiscoveryEngine
# ---------------------------------------------------------------------------

class TestLLMDiscoveryEngine(unittest.IsolatedAsyncioTestCase):

    async def test_detect_ollama(self):
        import aiohttp as _aiohttp
        engine = ous.LLMDiscoveryEngine(timeout=2.0)
        models_resp = {"models": [{"name": "llama3:8b"}]}

        resp = MockResponse(200, models_resp)

        class FakeCtx:
            async def __aenter__(self_):
                return resp

            async def __aexit__(self_, *args):
                pass

        def fake_get(self_sess, url, **kwargs):
            if "/api/tags" in url:
                return FakeCtx()
            raise Exception("wrong url")

        with patch.object(_aiohttp.ClientSession, "get", fake_get):
            async with _aiohttp.ClientSession() as sess:
                result = await engine._probe_endpoint(
                    sess,
                    "http://10.0.0.1:11434/api/tags",
                    ous.ServerType.OLLAMA,
                    lambda d: [m["name"] for m in d.get("models", [])],
                )
        self.assertIsNotNone(result)
        self.assertEqual(result[0], ous.ServerType.OLLAMA)
        self.assertIn("llama3:8b", result[1])

    async def test_probe_redirects_blocked(self):
        """allow_redirects=False means 302 returns None, not content from redirect target."""
        engine = ous.LLMDiscoveryEngine(timeout=2.0)
        import aiohttp

        redirect_resp = MockResponse(302, {})
        redirect_resp.headers = {"Location": "http://127.0.0.1:9999/api/tags"}

        class RedirectCtx:
            async def __aenter__(self_):
                return redirect_resp

            async def __aexit__(self_, *args):
                pass

        with patch.object(aiohttp.ClientSession, "get", lambda self_s, *a, **kw: RedirectCtx()):
            async with aiohttp.ClientSession() as sess:
                result = await engine._probe_endpoint(
                    sess,
                    "http://10.0.0.1:11434/api/tags",
                    ous.ServerType.OLLAMA,
                    lambda d: [m["name"] for m in d.get("models", [])],
                )
        self.assertIsNone(result)

    async def test_oom_guard_2mb(self):
        """Probe must reject bodies > 2 MB."""
        engine = ous.LLMDiscoveryEngine(timeout=2.0)
        import aiohttp

        big_body = b"x" * (2 * 1024 * 1024 + 1)

        class BigBodyResp:
            status = 200
            headers = {}
            content = None

            async def __aenter__(self_):
                self_.content = self_
                return self_

            async def __aexit__(self_, *args):
                pass

            async def read(self_, n=-1):
                return big_body[:n] if n != -1 else big_body

        with patch.object(aiohttp.ClientSession, "get", lambda self_s, *a, **kw: BigBodyResp()):
            async with aiohttp.ClientSession() as sess:
                result = await engine._probe_endpoint(
                    sess,
                    "http://10.0.0.1:11434/api/tags",
                    ous.ServerType.OLLAMA,
                    lambda d: [],
                )
        # JSONDecodeError → returns None
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Scanner stats & report
# ---------------------------------------------------------------------------

class TestOllamaUnifiedScannerReport(unittest.TestCase):

    def _make_scanner_with_results(self):
        scanner = ous.OllamaUnifiedScanner(
            timeout=2.0, max_concurrent=5, audit_mode=False
        )
        scanner.stats["successful_queries"] = 2
        scanner.stats["ollama_count"] = 2

        results = [
            ous.ScanResult(
                ip="10.0.0.1",
                port=11434,
                server_type=ous.ServerType.OLLAMA,
                models=["llama3:8b", "mistral:7b"],
                process_list=[],
                model_configs=[],
                url="http://10.0.0.1:11434",
                is_accessible=True,
                status=ous.ScanStatus.SUCCESS,
            ),
            ous.ScanResult(
                ip="10.0.0.2",
                port=1234,
                server_type=ous.ServerType.LM_STUDIO,
                models=["Phi-3"],
                process_list=[],
                model_configs=[],
                url="http://10.0.0.2:1234",
                is_accessible=True,
                status=ous.ScanStatus.SUCCESS,
            ),
        ]
        return scanner, results

    def test_json_report_valid(self):
        scanner, results = self._make_scanner_with_results()
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "scan")
            path = scanner.generate_scan_report(results, out, "json")
            with open(path, "r") as fh:
                data = json.load(fh)
            self.assertIn("servers", data)
            self.assertEqual(len(data["servers"]), 2)
            urls = [s["url"] for s in data["servers"]]
            self.assertIn("http://10.0.0.1:11434", urls)

    def test_text_report_valid(self):
        scanner, results = self._make_scanner_with_results()
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "scan")
            path = scanner.generate_scan_report(results, out, "text")
            with open(path, "r") as fh:
                content = fh.read()
            self.assertIn("ollama", content)
            self.assertIn("lmstudio", content)

    def test_unsupported_format_raises(self):
        scanner, results = self._make_scanner_with_results()
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "scan")
            with self.assertRaises(ValueError):
                scanner.generate_scan_report(results, out, "yaml")


# ---------------------------------------------------------------------------
# ANSI color
# ---------------------------------------------------------------------------

class TestAnsiColor(unittest.TestCase):

    def test_no_color_env(self):
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            result = ous._ansi_color("hello", "1;31")
            self.assertEqual(result, "hello")

    def test_pytest_env(self):
        with patch.dict(os.environ, {"PYTEST_CURRENT_TEST": "some::test"}):
            result = ous._ansi_color("hello", "1;31")
            self.assertEqual(result, "hello")


# ---------------------------------------------------------------------------
# Enums round-trip
# ---------------------------------------------------------------------------

class TestEnums(unittest.TestCase):

    def test_severity_values(self):
        self.assertEqual(ous.Severity.CRITICAL.value, "CRITICAL")
        self.assertEqual(ous.Severity.INFO.value, "INFO")

    def test_server_type_values(self):
        self.assertEqual(ous.ServerType.OLLAMA.value, "ollama")
        self.assertEqual(ous.ServerType.LM_STUDIO.value, "lmstudio")
        self.assertEqual(ous.ServerType.TEXTGEN_WEBUI.value, "textgen_webui")

    def test_scan_status_values(self):
        self.assertEqual(ous.ScanStatus.SUCCESS.value, "success")
        self.assertEqual(ous.ScanStatus.PORT_CLOSED.value, "port_closed")


# ---------------------------------------------------------------------------
# Custom JSON encoder
# ---------------------------------------------------------------------------

class TestCustomEncoder(unittest.TestCase):

    def test_enum_serialized(self):
        data = {"severity": ous.Severity.CRITICAL}
        result = json.dumps(data, cls=ous._CustomEncoder)
        self.assertIn("CRITICAL", result)

    def test_bytes_serialized(self):
        data = {"raw": b"hello"}
        result = json.dumps(data, cls=ous._CustomEncoder)
        self.assertIn("hello", result)


if __name__ == "__main__":
    unittest.main()
