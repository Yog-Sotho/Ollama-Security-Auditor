import os
import sys
import asyncio
import pytest
from Ollama_Security_Auditor_Final import (
    resolve_target_url,
    validate_ip_range_static,
    OllamaSecurityAuditor,
    AuditFinding,
    Severity,
    CheckStatus
)

def test_resolve_target_url():
    assert resolve_target_url("192.168.1.100") == "http://192.168.1.100:11434"
    assert resolve_target_url("http://localhost") == "http://localhost:11434"
    assert resolve_target_url("https://secure-ollama:12345") == "https://secure-ollama:12345"

def test_validate_ip_range_static():
    ips = validate_ip_range_static("192.168.1.1-192.168.1.3")
    assert ips == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

def test_report_generation_status_mapping(tmp_path):
    auditor = OllamaSecurityAuditor(target_url="localhost")
    auditor.detected_version = "0.1.48"
    auditor.discovered_models = ["llama3:latest"]
    auditor.stats = {"total_checks": 5, "CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1}

    findings = [
        AuditFinding(
            check_name="Check 1", severity=Severity.CRITICAL, status=CheckStatus.VULNERABLE,
            details="Crit vuln", remediation="Fix it"
        ),
        AuditFinding(
            check_name="Check 2", severity=Severity.HIGH, status=CheckStatus.WARNING,
            details="High warning", remediation="Review it"
        ),
        AuditFinding(
            check_name="Check 3", severity=Severity.MEDIUM, status=CheckStatus.ERROR,
            details="Failed to scan", remediation="Check logs"
        ),
        AuditFinding(
            check_name="Check 4", severity=Severity.LOW, status=CheckStatus.SKIPPED,
            details="Not applicable", remediation="None"
        ),
        AuditFinding(
            check_name="Check 5", severity=Severity.INFO, status=CheckStatus.SECURE,
            details="Everything is fine", remediation="None"
        )
    ]

    output_base = os.path.join(tmp_path, "test_report")
    report_path = auditor.generate_report(findings, output_base, "md")

    assert os.path.exists(report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "- **Status:** ❌ VULNERABLE" in content
    assert "- **Status:** ⚠️ WARNING" in content
    assert "- **Status:** 💥 ERROR" in content
    assert "- **Status:** ⏭️ SKIPPED" in content
    assert "- **Status:** ✅ SECURE" in content

class MockResponse:
    def __init__(self, status, headers=None, body_json=None):
        self.status = status
        self.headers = headers or {}
        self._body_json = body_json

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    async def json(self):
        if self._body_json is None:
            raise ValueError("No JSON body")
        return self._body_json

class MockSession:
    def __init__(self):
        self._closed = False

    async def close(self):
        self._closed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    def get(self, url, **kwargs):
        headers = {}
        if "Origin" in kwargs.get("headers", {}):
            headers = {"access-control-allow-origin": "*"}
        return MockResponse(200, headers=headers, body_json={"models": []})

    def post(self, url, **kwargs):
        return MockResponse(200, body_json={"status": "ok"})

    def request(self, method, url, **kwargs):
        if "/api/version" in url:
            return MockResponse(200, body_json={"version": "0.1.48"})
        elif "/api/tags" in url:
            return MockResponse(200, body_json={"models": [{"name": "llama3:latest", "digest": "sha256:12345"}]})
        elif "/api/ps" in url:
            return MockResponse(200, body_json={"models": []})
        elif "/api/show" in url:
            return MockResponse(200, body_json={"system": "You are a helpful assistant", "template": "", "parameters": "", "modelfile": "FROM base"})
        elif "/api/create" in url:
            return MockResponse(400, body_json={"error": "validation error"})
        else:
            return MockResponse(404)

def test_run_audit_terminal_summary(capsys, monkeypatch):
    auditor = OllamaSecurityAuditor(target_url="localhost")

    async def mock_fetch_dynamic_advisories(session):
        auditor._dynamic_advisories_cache = []

    monkeypatch.setattr(auditor, "_fetch_dynamic_advisories", mock_fetch_dynamic_advisories)

    async def run_test():
        mock_session = MockSession()
        return await auditor.run_audit(mock_session)

    findings = asyncio.run(run_test())

    captured = sys.stderr.getvalue() if hasattr(sys.stderr, "getvalue") else capsys.readouterr().err

    assert "📊 AUDIT FINDINGS SUMMARY" in captured
    assert "Summary: 🔴 CRITICAL:" in captured
    assert "HIGH:" in captured
    assert "MEDIUM:" in captured
    assert "LOW:" in captured
    assert "INFO:" in captured


@pytest.mark.asyncio
async def test_run_probe_with_feedback(capsys):
    auditor = OllamaSecurityAuditor(target_url="localhost")

    async def dummy_probe():
        return "success"

    res = await auditor._run_probe_with_feedback(dummy_probe(), "Test Probe")
    assert res == "success"

    captured = sys.stderr.getvalue() if hasattr(sys.stderr, "getvalue") else capsys.readouterr().err
    assert "✨ Completed: Test Probe" in captured


def test_generate_report_returns_absolute_path(tmp_path):
    auditor = OllamaSecurityAuditor(target_url="localhost")
    auditor.detected_version = "0.1.48"
    auditor.stats = {"total_checks": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    output_base = os.path.join(tmp_path, "test_report")
    report_path = auditor.generate_report([], output_base, "md")

    assert os.path.isabs(report_path)
    assert os.path.exists(report_path)


def test_colorize_and_degradation(monkeypatch):
    auditor = OllamaSecurityAuditor(target_url="localhost")

    # 1. Test when coloring should be active (mock TTY=True, clear NO_COLOR and PYTEST_CURRENT_TEST)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    result_colored = auditor._colorize("VULNERABLE", "91")
    assert result_colored == "\033[91mVULNERABLE\033[0m"

    # 2. Test when sys.stderr.isatty() is False -> should not colorize
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    assert auditor._colorize("VULNERABLE", "91") == "VULNERABLE"

    # 3. Test when NO_COLOR is present -> should not colorize
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    monkeypatch.setenv("NO_COLOR", "1")
    assert auditor._colorize("VULNERABLE", "91") == "VULNERABLE"

    # 4. Test when PYTEST_CURRENT_TEST is present -> should not colorize
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")
    assert auditor._colorize("VULNERABLE", "91") == "VULNERABLE"
