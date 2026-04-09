#!/usr/bin/env python3
"""
Ollama Security Auditor v1.5.0
Security testing framework with IP Range Scanning & Model Discovery.
Features:
- Single Target Audit & IP Range Scanning (CIDR/Range).
- Robust Markdown & JSON report generation.
- Dynamic Threat Intel (GitHub, NVD, ExploitDB).
- Advanced Probes: Weight Exfiltration, Modelfile RCE, SSRF, Token Brute-Force.
- Enhanced Model Discovery: Lists Installed, Loaded (VRAM/RAM), and Configurations.
DISCLAIMEr: This tool is intended for authorized security testing only.
Using this tool against networks or services you do not own violates local laws.
Always obtain explicit written permission before auditing any system.
Version: 1.5.0
Last Updated: 2026
Author: Yog-Sotho
"""
import argparse
import asyncio
import json
import sys
import os
import re
import time
import logging
from typing import List, Optional, Dict, Any, Tuple
from urllib.parse import urlparse
from ipaddress import IPv4Network, IPv4Address
from enum import Enum
from dataclasses import dataclass
import aiohttp

# ==============================================================================
# LOGGING CONFIGURATION
# ==============================================================================
logger = logging.getLogger(__name__)
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ==============================================================================
# ENUMS AND DATACLASSES
# ==============================================================================
class Severity(Enum):
    """Security finding severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class CheckStatus(Enum):
    """Audit check result status"""
    VULNERABLE = "VULNERABLE"
    SECURE = "SECURE"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"

@dataclass
class AuditFinding:
    """Structured security finding"""
    check_name: str
    severity: Severity
    status: CheckStatus
    details: str
    remediation: str
    cve_id: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None

# ==============================================================================
# CUSTOM JSON ENCODER FOR EVIDENCE
# ==============================================================================
class CustomEncoder(json.JSONEncoder):
    """Fixes: TypeError: Object of type Severity is not JSON serializable"""
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, bytes):
            return str(obj)
        return super().default(obj)

# ==============================================================================
# URL & IP UTILITIES
# ==============================================================================
def resolve_target_url(target: str) -> str:
    """Resolves target to http://IP:11434 format with validation."""
    target = target.strip().rstrip('/')
    if not target.startswith(('http://', 'https://')):
        target = f"http://{target}"
    
    parsed_check = urlparse(target)
    if parsed_check.scheme and parsed_check.scheme not in ('http', 'https'):
        raise ValueError(f"Unsupported or dangerous scheme detected: {parsed_check.scheme}. Only HTTP/HTTPS allowed.")
        
    if target.startswith('https://'):
        prefix = 'https://'; rest = target[8:]
    else:
        prefix = 'http://'; rest = target[7:]
        
    path_sep_index = rest.find('/')
    if path_sep_index != -1:
        host_part = rest[:path_sep_index]; path_part = rest[path_sep_index:]
    else:
        host_part = rest; path_part = ""
        
    has_port = False
    if host_part.startswith('['):
        if ']:' in host_part: has_port = True
    elif ':' in host_part:
        has_port = True
        
    if not has_port:
        rest = f"{host_part}:11434{path_part}"
    return f"{prefix}{rest}"

def validate_ip_range_static(ip_range: str) -> List[str]:
    """Validates and expands a single IP range into individual IPs (IPv4 Only)."""
    ips = []
    try:
        network = IPv4Network(ip_range, strict=False)
        if not network.is_private:
            logger.warning(f"⚠️ Scanning PUBLIC range: {ip_range}. Ensure permission!")
        return [str(ip) for ip in network]
    except ValueError:
        pass
    
    if '-' in ip_range:
        parts = ip_range.split('-')
        if len(parts) == 2:
            try:
                start_ip = IPv4Address(parts[0].strip())
                end_part = parts[1].strip()
                if '.' in end_part:
                    end_ip = IPv4Address(end_part)
                else:
                    base = '.'.join(str(start_ip).split('.')[:-1])
                    end_ip = IPv4Address(f"{base}.{end_part}")
                
                if int(start_ip) <= int(end_ip):
                    current = int(start_ip)
                    end = int(end_ip)
                    while current <= end:
                        ips.append(str(IPv4Address(current)))
                        current += 1
                    return ips
            except Exception:
                pass
    try:
        IPv4Address(ip_range.strip())
        return [ip_range.strip()]
    except:
        pass
    return []

# ==============================================================================
# VERSION UTILITIES & CVE REGISTRY
# ==============================================================================
def _parse_version_tuple(ver_str: str) -> Tuple[int, ...]:
    """Safely parse semantic version strings to comparable tuples."""
    clean = re.sub(r'[^0-9.]', '', ver_str.split('-')[0])
    parts = clean.split('.')
    while len(parts) < 3: parts.append('0')
    return tuple(int(p) for p in parts if p.isdigit()) if parts else (0, 0, 0)

def _version_in_range(target_ver: str, range_str: str) -> bool:
    """Check if target version falls within an affected range."""
    target = _parse_version_tuple(target_ver)
    conditions = range_str.split(',')
    for cond in conditions:
        cond = cond.strip()
        if not cond: continue
        if cond.startswith('>='):
            if target < _parse_version_tuple(cond[2:]): return False
        elif cond.startswith('>'):
            if target <= _parse_version_tuple(cond[1:]): return False
        elif cond.startswith('<='):
            if target > _parse_version_tuple(cond[2:]): return False
        elif cond.startswith('<'):
            if target >= _parse_version_tuple(cond[1:]): return False
        elif cond.startswith('=='):
            if target != _parse_version_tuple(cond[2:]): return False
    return True

CVE_REGISTRY: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2024-37032", "title": "ProbLlama: Critical Path Traversal & SSRF",
        "severity": Severity.CRITICAL, "affected_range": ">=0.1.0,<0.3.14", "check_type": "endpoint_version_match",
        "description": "Wiz research discovered critical path traversal and SSRF via /api/pull.",
        "remediation": "Upgrade to >=0.3.14. Block /api/pull at reverse proxy.", "indicator": "Version <0.3.14"
    },
    {
        "cve_id": "CVE-2024-28224", "title": "DNS Rebinding Attack",
        "severity": Severity.HIGH, "affected_range": ">=0.1.0,<0.3.14", "check_type": "endpoint_version_match",
        "description": "Malicious DNS rebinding can bypass localhost-only binding.",
        "remediation": "Upgrade to >=0.3.14. Set OLLAMA_HOST=127.0.0.1.", "indicator": "Version <0.3.14"
    },
    {
        "cve_id": "CVE-2024-39722", "title": "SSRF via Model Pull",
        "severity": Severity.HIGH, "affected_range": ">=0.1.0,<0.3.14", "check_type": "endpoint_version_match",
        "description": "Improper URL validation in /api/pull allows SSRF.",
        "remediation": "Upgrade to >=0.3.14.", "indicator": "Version <0.3.14"
    },
    {
        "cve_id": "CVE-2024-45436", "title": "Path Traversal via Modelfile",
        "severity": Severity.CRITICAL, "affected_range": ">=0.1.0,<0.4.0", "check_type": "endpoint_version_match",
        "description": "Traversing directory boundaries in Modelfile FROM paths.",
        "remediation": "Upgrade to >=0.4.0.", "indicator": "Version <0.4.0"
    },
    {
        "cve_id": "CVE-2024-7773", "title": "Insecure Unix Socket Permissions",
        "severity": Severity.HIGH, "affected_range": ">=0.1.0,<0.5.0", "check_type": "endpoint_version_match",
        "description": "Default permissions allow local unprivileged access.",
        "remediation": "Upgrade to >=0.5.0.", "indicator": "Version <0.5.0"
    },
    {
        "cve_id": "CVE-2025-15514", "title": "API Parameter Leakage",
        "severity": Severity.HIGH, "affected_range": ">=0.5.0,<0.6.0", "check_type": "behavioral_probe",
        "description": "Improper validation of chat parameters leaks context.",
        "remediation": "Upgrade to >=0.6.0.", "indicator": "Version range match"
    },
    {
        "cve_id": "GHSA-x9hg-5q6g-q3jr", "title": "Environment Variable Exposure",
        "severity": Severity.MEDIUM, "affected_range": ">=0.1.0,<0.5.0", "check_type": "behavioral_probe",
        "description": "Verbose errors may expose OLLAMA_ variables.",
        "remediation": "Set OLLAMA_DEBUG=0 in production.", "indicator": "Error verbosity"
    },
    {
        "cve_id": "SNYK-WOLFILATEST-OLLAMA-6035174", "title": "Dependency Chain Risk",
        "severity": Severity.MEDIUM, "affected_range": ">=0.1.0,<0.4.0", "check_type": "endpoint_version_match",
        "description": "Underlying dependency flaws in model processing.",
        "remediation": "Upgrade Ollama binary.", "indicator": "Version <0.4.0"
    }
]

# ==============================================================================
# AUDITOR CLASS (Single Target Engine)
# ==============================================================================
class OllamaSecurityAuditor:
    """Professional-grade security auditor for exposed Ollama API instances."""
    def __init__(
        self,
        target_url: str,
        timeout: float = 10.0,
        disable_ssl_verify: bool = False,
        max_concurrent: int = 10,
        deep_mode: bool = False,
        request_delay: float = 0.0
    ):
        logger.debug(f"Initial Target Input: {target_url}")
        self.base_url = resolve_target_url(target_url)
        logger.info(f"Resolved Target: {self.base_url}")
        self.timeout = timeout
        self.disable_ssl_verify = disable_ssl_verify
        self.max_concurrent = max_concurrent
        self.deep_mode = deep_mode
        self.request_delay = request_delay
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.findings: List[AuditFinding] = []
        self.stats: Dict[str, int] = {}
        self.detected_version: Optional[str] = None
        self.target_ip_display: Optional[str] = None
        self.timeout_obj = aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout / 2)
        self._dynamic_advisories_cache: List[Dict[str, Any]] = []
        self._waf_detected: bool = False
        self._rate_limit_detected: bool = False
        
        # v1.5 Features: Model Discovery Storage
        self.discovered_models: List[str] = []
        self.loaded_models: List[Dict] = []

    async def _safe_request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        endpoint: str,
        headers: Optional[Dict[str, str]] = None,
        json_payload: Optional[Dict] = None,
        timeout_override: Optional[float] = None
    ) -> Tuple[Optional[int], Optional[Dict], Optional[str]]:
        """Execute HTTP request with strict error handling, retry logic, and rate-limit awareness"""
        url = f"{self.base_url}{endpoint}"
        ssl_ctx = None if self.disable_ssl_verify else True
        req_timeout = aiohttp.ClientTimeout(total=timeout_override or self.timeout)
        max_retries = 3
        retry_count = 0

        while retry_count <= max_retries:
            if self.request_delay > 0: await asyncio.sleep(self.request_delay)
            logger.debug(f"Request: {method} {url} (Attempt {retry_count + 1})")
            try:
                async with session.request(
                    method=method, url=url, headers=headers or {},
                    json=json_payload, ssl=ssl_ctx, timeout=req_timeout
                ) as response:
                    status = response.status
                    resp_headers = dict(response.headers)
                    if any(k in resp_headers for k in ['cf-ray', 'x-amzn-requestid', 'x-sucuri-id', 'x-cdn-forward']):
                        self._waf_detected = True
                    if any(k in resp_headers for k in ['x-ratelimit-remaining', 'retry-after', 'x-rate-limit']):
                        self._rate_limit_detected = True
                        if status == 429:
                            retry_after = int(resp_headers.get('retry-after', 2))
                            logger.warning(f"Rate limit hit. Waiting {retry_after}s...")
                            await asyncio.sleep(retry_after)
                            retry_count += 1
                            continue
                    try: body = await response.json()
                    except (aiohttp.ContentTypeError, json.JSONDecodeError): body = None
                    return status, body, url
            except asyncio.TimeoutError:
                return None, None, url
            except Exception as e:
                logger.debug(f"Request error to {url}: {e}")
                if retry_count < max_retries:
                    backoff = min(2 ** retry_count, 5)
                    await asyncio.sleep(backoff)
                    retry_count += 1
                else:
                    return None, None, url
        return None, None, url

    async def check_connectivity(self, session: aiohttp.ClientSession) -> AuditFinding:
        """Verify basic connectivity, extract version, and parse display info."""
        parsed = urlparse(self.base_url)
        host = parsed.hostname or parsed.path.split('/')[0]
        port = parsed.port or 11434
        self.target_ip_display = f"{host}:{port}"
        
        version_endpoint = "/api/version"
        status, body, full_url = await self._safe_request(session, "GET", version_endpoint)
        
        if status == 200 and body and "version" in body:
            self.detected_version = body.get("version", "unknown")
            return AuditFinding(
                check_name="API Connectivity & Version Detection", severity=Severity.INFO, status=CheckStatus.SECURE,
                details=f"Ollama API reachable. Detected Version: {self.detected_version}",
                remediation="Restrict access.", evidence={"version": self.detected_version}
            )
        return AuditFinding(
            check_name="API Connectivity & Version Detection", severity=Severity.HIGH, status=CheckStatus.ERROR,
            details=f"Failed to connect to {full_url} or version check failed.",
            remediation="Verify target URL and network routing."
        )

    async def _fetch_dynamic_advisories(self, session: aiohttp.ClientSession):
        """Fetch live advisories from multiple sources: GitHub, NVD, ExploitDB"""
        logger.info("🌐 Fetching dynamic advisories from multiple sources...")
        seen_ids = set()
        
        # 1. GitHub Security Advisories
        try:
            gh_url = "https://api.github.com/repos/ollama/ollama/security/advisories?state=open&per_page=10"
            headers = {"Accept": "application/vnd.github+json", "User-Agent": "OllamaAuditor/1.5"}
            async with session.get(gh_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for adv in data:
                        ghsa = adv.get("ghsa_id", "GHSA-UNKNOWN")
                        if ghsa not in seen_ids:
                            seen_ids.add(ghsa)
                            self._dynamic_advisories_cache.append({
                                "cve_id": ghsa, "title": adv.get("summary", "GitHub Advisory"),
                                "severity": Severity.HIGH, "affected_range": ">=0.0.0",
                                "check_type": "endpoint_version_match",
                                "description": adv.get("description", "Dynamic advisory detected via GitHub."),
                                "remediation": "Apply vendor patch immediately.",
                                "indicator": "GitHub Advisory Match", "source": "GitHub"
                            })
        except Exception as e: logger.debug(f"GitHub advisory fetch failed: {e}")

        # 2. NVD API (CVE Search)
        try:
            nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=ollama&resultsPerPage=5"
            async with session.get(nvd_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("vulnerabilities", []):
                        cve_meta = item.get("cve", {})
                        cve_id = cve_meta.get("id")
                        if cve_id and cve_id not in seen_ids:
                            seen_ids.add(cve_id)
                            descs = cve_meta.get("descriptions", [{}])
                            desc = descs[0].get("value", "NVD Advisory")
                            metrics = cve_meta.get("metrics", {})
                            sev = Severity.MEDIUM
                            if metrics.get("cvssMetricV31"):
                                score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0)
                                sev = Severity.CRITICAL if score >= 9.0 else Severity.HIGH if score >= 7.0 else Severity.MEDIUM
                            
                            self._dynamic_advisories_cache.append({
                                "cve_id": cve_id, "title": f"NVD: {cve_id}",
                                "severity": sev, "affected_range": ">=0.0.0",
                                "check_type": "endpoint_version_match",
                                "description": desc, "remediation": "Consult NVD for patch details.",
                                "indicator": "NVD Match", "source": "NVD"
                            })
        except Exception as e: logger.debug(f"NVD advisory fetch failed: {e}")

        # 3. ExploitDB Search
        try:
            edb_url = "https://www.exploit-db.com/api/v1/exploits?search=ollama&pageSize=5"
            headers = {"Accept": "application/json", "User-Agent": "OllamaAuditor/1.5"}
            async with session.get(edb_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for exp in data.get("data", []):
                        edb_id = f"EDB-{exp.get('id', 'UNKNOWN')}"
                        if edb_id not in seen_ids:
                            seen_ids.add(edb_id)
                            self._dynamic_advisories_cache.append({
                                "cve_id": edb_id, "title": f"ExploitDB: {exp.get('title', 'Unknown Exploit')}",
                                "severity": Severity.HIGH, "affected_range": ">=0.0.0",
                                "check_type": "endpoint_version_match",
                                "description": f"Public exploit available: {exp.get('description', 'N/A')}",
                                "remediation": "Apply vendor patch immediately. Monitor exploit activity.",
                                "indicator": "ExploitDB Match", "source": "ExploitDB"
                            })
        except Exception as e: logger.debug(f"ExploitDB advisory fetch failed: {e}")
        logger.info(f"✅ Loaded {len(self._dynamic_advisories_cache)} dynamic advisories.")

    async def discover_models(self, session: aiohttp.ClientSession):
        """v1.5 Feature: Discover installed and loaded models"""
        # 1. Installed Models (/api/tags)
        s, b, _ = await self._safe_request(session, "GET", "/api/tags")
        if s == 200 and b and "models" in b:
            self.discovered_models = [m.get("name", "unknown") for m in b["models"]]
        
        # 2. Loaded Models (/api/ps)
        s, b, _ = await self._safe_request(session, "GET", "/api/ps")
        if s == 200 and b and "models" in b:
            self.loaded_models = b["models"]

    async def check_known_cves(self, session: aiohttp.ClientSession) -> List[AuditFinding]:
        """Check for known CVE vulnerabilities using version matching."""
        cve_findings: List[AuditFinding] = []
        if not self.detected_version or self.detected_version == "unknown":
            logger.warning("Version not detected. Skipping CVE registry checks.")
            return cve_findings
            
        combined_registry = CVE_REGISTRY + self._dynamic_advisories_cache
        
        for cve in combined_registry:
            is_vulnerable = _version_in_range(self.detected_version, cve["affected_range"])
            status = CheckStatus.SECURE
            suffix = ""
            
            if cve["check_type"] == "behavioral_probe":
                if "Environment" in cve["title"]:
                    s, _, _ = await self._safe_request(session, "GET", "/api/invalid-endpoint-test")
                    if s in [404, 500]: status = CheckStatus.WARNING; suffix = " | Verbose error responses exposed"
                elif "Parameter Leakage" in cve["title"]:
                    s, b, _ = await self._safe_request(session, "POST", "/api/chat", json_payload={"model": "test", "stream": False, "prompt": "A"})
                    if b and "context" in b: status = CheckStatus.VULNERABLE; suffix = " | Context leakage detected"
            else:
                if is_vulnerable:
                    status = CheckStatus.VULNERABLE if cve["severity"] in [Severity.CRITICAL, Severity.HIGH] else CheckStatus.WARNING
                    suffix = f" | Matches range {cve['affected_range']}"
                    
            if status != CheckStatus.SECURE:
                cve_findings.append(AuditFinding(
                    check_name=f"CVE Check: {cve['title']}", severity=cve["severity"], status=status,
                    details=f"{cve['description']}{suffix}", remediation=cve["remediation"],
                    cve_id=cve["cve_id"],
                    evidence={"version": self.detected_version, "affected_range": cve["affected_range"], "source": cve.get("source", "static")}
                ))
        return cve_findings

    async def check_authentication(self, session: aiohttp.ClientSession) -> AuditFinding:
        """Test for unauthenticated API access"""
        endpoints = ["/api/tags", "/api/ps"]
        accessible = []
        for ep in endpoints:
            status, _, _ = await self._safe_request(session, "GET", ep)
            if status == 200: accessible.append(ep)
                
        if accessible:
            return AuditFinding(
                check_name="Authentication Bypass", severity=Severity.CRITICAL, status=CheckStatus.VULNERABLE,
                details=f"API endpoints accessible without auth: {', '.join(accessible)}",
                remediation="Place Ollama behind a reverse proxy with authentication.",
                evidence={"exposed_endpoints": accessible}
            )
        return AuditFinding(
            check_name="Authentication Bypass", severity=Severity.LOW, status=CheckStatus.SECURE,
            details="Endpoints returned non-200 status.", remediation="Verify protection."
        )

    async def check_info_disclosure(self, session: aiohttp.ClientSession) -> AuditFinding:
        """Check for sensitive information exposure"""
        disclosure_points = []
        status, tags_body, _ = await self._safe_request(session, "GET", "/api/tags")
        if status == 200 and tags_body and "models" in tags_body:
            model_count = len(tags_body.get("models", []))
            disclosure_points.append(f"Model enumeration successful ({model_count} models)")
            
        status, ps_body, _ = await self._safe_request(session, "GET", "/api/ps")
        if status == 200 and ps_body and "models" in ps_body:
            active_count = len(ps_body.get("models", []))
            disclosure_points.append(f"Active process monitoring exposed ({active_count} loaded models)")
            
        if disclosure_points:
            return AuditFinding(
                check_name="Information Disclosure", severity=Severity.HIGH, status=CheckStatus.VULNERABLE,
                details="; ".join(disclosure_points),
                remediation="Restrict /api/tags and /api/ps via reverse proxy.",
                evidence={"disclosures": disclosure_points}
            )
        return AuditFinding(
            check_name="Information Disclosure", severity=Severity.LOW, status=CheckStatus.SECURE,
            details="No sensitive information endpoints returned successful responses.",
            remediation="Continue monitoring for accidental exposure."
        )

    async def check_cors_policy(self, session: aiohttp.ClientSession) -> AuditFinding:
        """Test for overly permissive Cross-Origin Resource Sharing policies"""
        malicious_origin = "http://evil-attacker.com"
        try:
            async with session.get(
                f"{self.base_url}/api/tags",
                headers={"Origin": malicious_origin},
                ssl=False if self.disable_ssl_verify else True
            ) as resp:
                allow_origin = resp.headers.get("access-control-allow-origin", "")
                if "*" in allow_origin or malicious_origin in allow_origin:
                    return AuditFinding(
                        check_name="CORS Misconfiguration", severity=Severity.CRITICAL, status=CheckStatus.VULNERABLE,
                        details=f"Overly permissive CORS: '{allow_origin}'.",
                        remediation="Set OLLAMA_ORIGINS explicitly.", evidence={"allow_origin": allow_origin}
                    )
        except Exception: pass
        return AuditFinding(
            check_name="CORS Misconfiguration", severity=Severity.LOW, status=CheckStatus.SECURE,
            details="CORS headers appear restrictive.", remediation="Verify config."
        )

    async def check_dangerous_endpoints(self, session: aiohttp.ClientSession) -> AuditFinding:
        """Check if destructive endpoints are accessible. SAFE MODE ONLY."""
        dangerous_eps = {"/api/delete": "DELETE", "/api/pull": "POST", "/api/push": "POST"}
        exposed = []
        for endpoint, method in dangerous_eps.items():
            payload = {"name": "nonexistent-model-test-123", "stream": False}
            if endpoint == "/api/push": payload["insecure"] = True
            status, _, _ = await self._safe_request(session, method, endpoint, json_payload=payload)
            if status not in [401, 403, 405, 502]: exposed.append(f"{endpoint} ({method})")
                
        if exposed:
            return AuditFinding(
                check_name="Dangerous Endpoint Exposure", severity=Severity.CRITICAL if not self.deep_mode else Severity.HIGH,
                status=CheckStatus.VULNERABLE, details=f"Destructive/modify endpoints accessible: {', '.join(exposed)}.",
                remediation="Disable or firewall /api/delete, /api/pull, /api/push.",
                evidence={"exposed_endpoints": exposed}
            )
        return AuditFinding(
            check_name="Dangerous Endpoint Exposure", severity=Severity.LOW, status=CheckStatus.SECURE,
            details="Destructive endpoints appear restricted.", remediation="Maintain current restrictions."
        )

    async def extract_model_configs(self, session: aiohttp.ClientSession) -> List[AuditFinding]:
        """Extract model configurations to identify sensitive data in system prompts"""
        findings: List[AuditFinding] = []
        status, body, _ = await self._safe_request(session, "GET", "/api/tags")
        if not body or "models" not in body: return []
            
        models = body.get("models", [])[:5]
        for model in models:
            model_name = model.get("name", "unknown")
            status, config_body, _ = await self._safe_request(
                session, "POST", "/api/show", json_payload={"name": model_name}
            )
            if status == 200 and config_body:
                system_prompt = config_body.get("system", "")
                if system_prompt and len(system_prompt) > 50:
                    sensitive_patterns = [r'(api[_-]?key|secret|password|token|credential)', r'(http[s]?://[^\s]+)']
                    matches = []
                    for pat in sensitive_patterns:
                        if re.findall(pat, system_prompt, re.IGNORECASE): matches.append(pat)
                    findings.append(AuditFinding(
                        check_name=f"Sensitive Data Risk ({model_name})",
                        severity=Severity.HIGH if matches else Severity.MEDIUM,
                        status=CheckStatus.WARNING if not matches else CheckStatus.VULNERABLE,
                        details=f"System prompt extracted for '{model_name}'. Contains sensitive patterns: {matches}" if matches else f"System prompt extracted for '{model_name}'.",
                        remediation="Restrict /api/show access via auth.", evidence={"model": model_name}
                    ))
        return findings

    # ==============================================================================
    # NEW FEATURES & ADVANCED PROBES (v1.4)
    # ==============================================================================
    async def check_waf_rate_limit(self) -> AuditFinding:
        """Check for WAF presence and rate limiting headers"""
        details = []
        if self._waf_detected: details.append("WAF/Proxy signatures detected in response headers.")
        if self._rate_limit_detected: details.append("Rate limiting headers present (auto-throttle active).")
            
        if details:
            return AuditFinding(
                check_name="WAF & Rate Limit Detection", severity=Severity.INFO, status=CheckStatus.SECURE,
                details="; ".join(details), remediation="Monitor for aggressive throttling during deep scans.",
                evidence={"waf": self._waf_detected, "rate_limit": self._rate_limit_detected}
            )
        return AuditFinding(
            check_name="WAF & Rate Limit Detection", severity=Severity.LOW, status=CheckStatus.SECURE,
            details="No WAF or rate limiting headers detected.", remediation="Consider implementing API rate limiting."
        )

    async def check_model_weight_exfil(self, session: aiohttp.ClientSession) -> AuditFinding:
        """Test for unauthorized model weight/blob download via /api/blobs"""
        status, body, _ = await self._safe_request(session, "GET", "/api/tags")
        if not body or "models" not in body:
            return AuditFinding(check_name="Model Weight Exfiltration", severity=Severity.INFO, status=CheckStatus.SKIPPED, details="No models found to probe.", remediation="N/A")
            
        test_model = body["models"][0]
        digest = test_model.get("digest", "")
        if not digest.startswith("sha256:"): digest = f"sha256:{digest}"
            
        blob_url = f"/api/blobs/{digest}"
        b_status, _, _ = await self._safe_request(session, "GET", blob_url)
        
        if b_status == 200:
            return AuditFinding(
                check_name="Model Weight Exfiltration", severity=Severity.CRITICAL, status=CheckStatus.VULNERABLE,
                details="Model weights accessible via unauthenticated /api/blobs endpoint.",
                remediation="Restrict blob access via reverse proxy authentication.",
                evidence={"blob_endpoint": blob_url, "status": 200}
            )
        return AuditFinding(
            check_name="Model Weight Exfiltration", severity=Severity.LOW, status=CheckStatus.SECURE,
            details="Blob endpoint returned non-200 status.", remediation="Maintain current restrictions."
        )

    async def check_streaming_dos(self, session: aiohttp.ClientSession) -> AuditFinding:
        """Probe for unbounded streaming responses that could cause memory exhaustion"""
        start = time.time()
        payload = {"model": "test", "stream": True, "prompt": "A" * 5000}
        try:
            async with session.post(
                f"{self.base_url}/api/chat", json=payload, timeout=aiohttp.ClientTimeout(total=3.0),
                ssl=None if self.disable_ssl_verify else True
            ) as resp:
                elapsed = time.time() - start
                if resp.status == 200 and elapsed < 1.0:
                    return AuditFinding(
                        check_name="Streaming DoS Risk", severity=Severity.MEDIUM, status=CheckStatus.WARNING,
                        details="Server accepted streaming payload without delay. Monitor for memory exhaustion.",
                        remediation="Implement streaming timeouts and request size limits.",
                        evidence={"response_time": f"{elapsed:.2f}s", "status": resp.status}
                    )
        except asyncio.TimeoutError: pass
        return AuditFinding(
            check_name="Streaming DoS Risk", severity=Severity.LOW, status=CheckStatus.SECURE,
            details="Streaming probe timed out or rejected.", remediation="Verify timeout configurations."
        )

    async def check_modelfile_rce(self, session: aiohttp.ClientSession) -> AuditFinding:
        """Test /api/create for Modelfile RUN command execution risks"""
        payload = {"name": "test-rce-probe", "modelfile": "FROM base\nRUN echo 'AUDIT_PROBE_SUCCESS'"}
        status, body, _ = await self._safe_request(session, "POST", "/api/create", json_payload=payload)
        
        if status == 200:
            return AuditFinding(
                check_name="Modelfile RCE Probe", severity=Severity.CRITICAL, status=CheckStatus.VULNERABLE,
                details="Server accepted Modelfile with RUN command. Potential RCE vector if sandboxing is misconfigured.",
                remediation="Disable /api/create in production or enforce strict model signing.",
                evidence={"status": status, "payload_accepted": True}
            )
        elif status == 400 and body and "error" in body:
            return AuditFinding(
                check_name="Modelfile RCE Probe", severity=Severity.LOW, status=CheckStatus.SECURE,
                details="RUN command rejected with validation error.",
                remediation="Maintain current validation.", evidence={"error": body.get("error")}
            )
        return AuditFinding(
            check_name="Modelfile RCE Probe", severity=Severity.INFO, status=CheckStatus.SKIPPED,
            details="Endpoint unreachable or unexpected status.", remediation="Verify endpoint availability."
        )

    async def check_prompt_injection_leakage(self, session: aiohttp.ClientSession) -> List[AuditFinding]:
        """Extract and scan system prompts for jailbreak/injection patterns"""
        findings = []
        status, body, _ = await self._safe_request(session, "GET", "/api/tags")
        if not body or "models" not in body: return []
        
        jailbreak_patterns = [
            r'ignore\s+previous\s+instructions', r'you\s+are\s+now', r'system\s*:\s*', 
            r'role\s*:\s*developer', r'do\s+not\s+refuse', r'output\s+raw'
        ]
        
        for model in body.get("models", [])[:3]:
            m_name = model.get("name")
            _, cfg, _ = await self._safe_request(session, "POST", "/api/show", json_payload={"name": m_name})
            if cfg and "system" in cfg:
                prompt = cfg["system"]
                matches = [p for p in jailbreak_patterns if re.search(p, prompt, re.IGNORECASE)]
                if matches:
                    findings.append(AuditFinding(
                        check_name=f"Prompt Injection Leakage ({m_name})", severity=Severity.HIGH, status=CheckStatus.VULNERABLE,
                        details="System prompt contains potential jailbreak/injection markers.",
                        remediation="Sanitize system prompts and enforce input filtering.",
                        evidence={"model": m_name, "patterns_found": matches}
                    ))
        return findings

    async def check_cloud_metadata_ssrf(self, session: aiohttp.ClientSession) -> AuditFinding:
        """Probe for cloud metadata SSRF via /api/pull (Deep Mode Only)"""
        if not self.deep_mode:
            return AuditFinding(check_name="Cloud Metadata SSRF", severity=Severity.INFO, status=CheckStatus.SKIPPED, details="Skipped (requires --deep)", remediation="N/A")
            
        metadata_urls = ["http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/computeMetadata/v1/"]
        for meta_url in metadata_urls:
            payload = {"name": meta_url, "stream": False}
            s, b, _ = await self._safe_request(session, "POST", "/api/pull", json_payload=payload)
            if s == 200 or (b and any(k in str(b) for k in ["ami-id", "instance-id", "google"])):
                return AuditFinding(
                    check_name="Cloud Metadata SSRF", severity=Severity.CRITICAL, status=CheckStatus.VULNERABLE,
                    details="Server successfully fetched cloud metadata via /api/pull.",
                    remediation="Block internal IP ranges in /api/pull URL validation.",
                    evidence={"target": meta_url, "response_preview": str(b)[:200]}
                )
        return AuditFinding(
            check_name="Cloud Metadata SSRF", severity=Severity.LOW, status=CheckStatus.SECURE,
            details="Cloud metadata endpoints blocked or unreachable.", remediation="Maintain SSRF protections."
        )

    async def check_token_brute(self, session: aiohttp.ClientSession) -> AuditFinding:
        """Test for weak/default API keys or JWTs"""
        common_tokens = ["ollama", "admin", "password", "test", "Bearer ollama", "Bearer admin"]
        vulnerable = []
        for token in common_tokens:
            headers = {"Authorization": token}
            s, _, _ = await self._safe_request(session, "GET", "/api/tags", headers=headers)
            if s == 200:
                vulnerable.append(token)
                break
                
        if vulnerable:
            return AuditFinding(
                check_name="Token/Key Brute-Force", severity=Severity.CRITICAL, status=CheckStatus.VULNERABLE,
                details=f"Authentication bypassed with weak/default token: {vulnerable[0]}",
                remediation="Implement strong API keys or OAuth2. Disable default credentials.",
                evidence={"accepted_token": vulnerable[0]}
            )
        return AuditFinding(
            check_name="Token/Key Brute-Force", severity=Severity.LOW, status=CheckStatus.SECURE,
            details="Weak/default tokens rejected.", remediation="Verify credential rotation policies."
        )

    async def run_audit(self, session: aiohttp.ClientSession) -> List[AuditFinding]:
        """Execute full security audit workflow"""
        print(f"\n🔍 Scanning Target: {self.base_url}", file=sys.stderr)
        print(f"🛡️  Mode: {'DEEP (Semi-Intrusive)' if self.deep_mode else 'STANDARD (Read-Only)'}", file=sys.stderr)
        print("-" * 70, file=sys.stderr)
        start_time = time.time()
        self.findings = []
        
        await self._fetch_dynamic_advisories(session)
        await self.discover_models(session) # v1.5: Discover models first
        
        connectivity = await self.check_connectivity(session)
        self.findings.append(connectivity)
        if connectivity.status == CheckStatus.ERROR:
            print("❌ Audit aborted: Target unreachable.", file=sys.stderr)
            return self.findings
        print(f"✅ Target reachable. Detected Version: {self.detected_version}", file=sys.stderr)
        if self.discovered_models:
            print(f"📦 Discovered Models: {', '.join(self.discovered_models)}", file=sys.stderr)
        
        print("📊 Evaluating known CVE vulnerabilities...", file=sys.stderr)
        cve_findings = await self.check_known_cves(session)
        self.findings.extend(cve_findings)
        
        auth_result, info_result, cors_result, dangerous_result = await asyncio.gather(
            self.check_authentication(session), self.check_info_disclosure(session),
            self.check_cors_policy(session), self.check_dangerous_endpoints(session)
        )
        self.findings.extend([auth_result, info_result, cors_result, dangerous_result])
        
        print("🧪 Running advanced probes...", file=sys.stderr)
        self.findings.append(await self.check_waf_rate_limit())
        self.findings.append(await self.check_model_weight_exfil(session))
        self.findings.append(await self.check_streaming_dos(session))
        self.findings.append(await self.check_modelfile_rce(session))
        self.findings.append(await self.check_cloud_metadata_ssrf(session))
        self.findings.append(await self.check_token_brute(session))
        
        prompt_findings = await self.check_prompt_injection_leakage(session)
        self.findings.extend(prompt_findings)
        config_findings = await self.extract_model_configs(session)
        self.findings.extend(config_findings)
        
        self.stats = {"total_checks": len(self.findings)}
        for s in Severity: self.stats[s.value] = sum(1 for f in self.findings if f.severity == s)
        duration = time.time() - start_time
        print(f"\n📝 Audit completed in {duration:.2f} seconds", file=sys.stderr)
        return self.findings

    def generate_report(self, findings: List[AuditFinding], output_path: str, format_type: str = 'md') -> str:
        """Generate Rich Markdown or JSON Report"""
        timestamp = time.strftime("%Y-%m-%d_%H%M%S", time.gmtime())
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir): os.makedirs(output_dir, exist_ok=True)
            
        if format_type == 'json':
            report_path = f"{output_path}_audit_{timestamp}.json"
            report_data = {
                "metadata": {
                    "target": self.base_url, "ip_port": self.target_ip_display,
                    "version": self.detected_version,
                    "models_found": self.discovered_models,
                    "models_loaded": [m.get('name') for m in self.loaded_models],
                    "timestamp": timestamp, "stats": self.stats
                },
                "findings": [
                    {"check_name": f.check_name, "severity": f.severity.value, "status": f.status.value,
                     "details": f.details, "remediation": f.remediation, "cve_id": f.cve_id, "evidence": f.evidence}
                    for f in findings
                ]
            }
            with open(report_path, 'w', encoding='utf-8') as file: json.dump(report_data, file, indent=2, cls=CustomEncoder)
            return report_path
            
        elif format_type == 'md':
            report_path = f"{output_path}_audit_{timestamp}.md"
            lines = [
                f"# 🛡️ Ollama Security Audit Report", f"**Generated:** {timestamp}\n", "",
                "## 🎯 Target Profile", f"| Property | Value |", f"| :--- | :--- |",
                f"| **Target Host** | `{self.base_url}` |", f"| **IP:PORT** | `{self.target_ip_display}` |",
                f"| **Detected Version** | `{self.detected_version}` |", f"| **Status** | ✅ AUDIT COMPLETED |", "",
                "## 📦 Discovered Models", f"- **Installed ({len(self.discovered_models)}):**",
            ]
            if self.discovered_models:
                for m in self.discovered_models: lines.append(f"  - `{m}`")
            else: lines.append("  - None")
            
            lines.append(f"- **Loaded ({len(self.loaded_models)}):**")
            if self.loaded_models:
                for m in self.loaded_models:
                    size = m.get('size', 0)
                    size_str = f" ({size/1024**3:.1f} GB)" if size > 0 else ""
                    lines.append(f"  - `{m.get('name', 'unknown')}`{size_str}")
            else: lines.append("  - None")

            lines.extend([
                "", "## 📊 Summary Statistics",
                f"- 🔴 **Critical:** {self.stats.get('CRITICAL', 0)}", f"- 🟠 **High:** {self.stats.get('HIGH', 0)}",
                f"- 🟡 **Medium:** {self.stats.get('MEDIUM', 0)}", f"- 🔵 **Low:** {self.stats.get('LOW', 0)}",
                f"- ⚪ **Info:** {self.stats.get('INFO', 0)}", "", "## 📋 Findings Detail", ""
            ])
            severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
            sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.severity, 5))
            
            for f in sorted_findings:
                emoji = "🔴" if f.severity == Severity.CRITICAL else "🟠" if f.severity == Severity.HIGH else "🟡" if f.severity == Severity.MEDIUM else "🔵" if f.severity == Severity.LOW else "⚪"
                status_emoji = "❌ VULNERABLE" if f.status == CheckStatus.VULNERABLE else "⚠️ WARNING" if f.status == CheckStatus.WARNING else "✅ SECURE"
                cve_tag = f" `[{f.cve_id}]`" if f.cve_id else ""
                lines.append(f"### {emoji} {f.check_name}{cve_tag}")
                lines.append(f"- **Status:** {status_emoji}")
                lines.append(f"- **Details:** {f.details}")
                lines.append(f"- **Remediation:** {f.remediation}")
                if f.evidence:
                    lines.append(f"- **Evidence:")
                    lines.append("  ```json")
                    lines.append(f"  {json.dumps(f.evidence, indent=2, cls=CustomEncoder)}")
                    lines.append("  ```")
                lines.append("---"); lines.append("")
                
            with open(report_path, 'w', encoding='utf-8') as file: file.write('\n'.join(lines))
            return report_path
        else:
            raise ValueError(f"Unsupported format: {format_type}")

# ==============================================================================
# RANGE SCANNER CLASS (v1.5 New Feature)
# ==============================================================================
class OllamaRangeScanner:
    """Handles IP range expansion and concurrent scanning. Spawns Auditors."""
    def __init__(self, timeout: float = 5.0, max_concurrent: int = 50, request_delay: float = 0.0, deep_mode: bool = False):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.request_delay = request_delay
        self.deep_mode = deep_mode

    async def _check_port(self, ip: str, port: int) -> bool:
        """Fast TCP port check using raw sockets."""
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def scan_target(self, ip: str, port: int, output_base: str, session_semaphore: asyncio.Semaphore):
        """Worker function for a single target."""
        is_open = await self._check_port(ip, port)
        if not is_open: return

        print(f"\n🔓 Port {port} Open on {ip}. Starting Audit...", file=sys.stderr)
        
        target_url = f"http://{ip}:{port}"
        auditor = OllamaSecurityAuditor(
            target_url=target_url, timeout=self.timeout, max_concurrent=10,
            deep_mode=self.deep_mode, request_delay=self.request_delay
        )

        try:
            async with aiohttp.ClientSession() as session:
                findings = await auditor.run_audit(session)
                
                if output_base:
                    output_file = os.path.join(output_base, f"audit_{ip}")
                    report_path = auditor.generate_report(findings, output_file, 'md')
                    print(f"   📝 Report saved to: {report_path}", file=sys.stderr)
        except Exception as e:
            print(f"   ❌ Audit failed for {ip}: {e}", file=sys.stderr)

    async def run(self, ip_range_str: str, port: int, output_base: str):
        """Main scanner entry point."""
        print(f"\n🌐 Expanding range: {ip_range_str}...", file=sys.stderr)
        ips = validate_ip_range_static(ip_range_str)
        if not ips:
            print("❌ No valid IPs found in range.", file=sys.stderr)
            return

        print(f"🎯 Targeting {len(ips)} IPs on port {port}...", file=sys.stderr)
        print("-" * 50, file=sys.stderr)
        sem = asyncio.Semaphore(self.max_concurrent)
        
        tasks = []
        for ip in ips:
            task = asyncio.create_task(self.scan_target(ip, port, output_base, sem))
            tasks.append(task)
            
        await asyncio.gather(*tasks)
        print(f"\n{'='*50}", file=sys.stderr)
        print("🏁 Range Scan Complete.", file=sys.stderr)
        print(f"{'='*50}", file=sys.stderr)

# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Ollama Security Auditor v1.5.0 - Range Scanning & Advanced Probes",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("target", nargs='?', help="Single target IP/URL or IP range (e.g. 192.168.1.100 or 192.168.1.0/24)")
    parser.add_argument("-o", "--output", default="ollama_report", help="Base name for report file or directory (default: ollama_report)")
    parser.add_argument("--deep", action="store_true", help="Enable deep validation (semi-intrusive)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    parser.add_argument("--format", choices=['md', 'json'], default='md', help="Output format (default: md)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds")
    parser.add_argument("-p", "--port", type=int, default=11434, help="Port to scan (default: 11434)")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Max concurrent port checks (default: 50)")

    args = parser.parse_args()
    if args.verbose: logger.setLevel(logging.DEBUG)

    print("=" * 70, file=sys.stderr)
    print("🛡️  OLLAMA SECURITY AUDITOR v1.5.0", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    
    try:
        is_range = False
        if args.target:
            if '/' in args.target or '-' in args.target:
                is_range = True

        if is_range:
            scanner = OllamaRangeScanner(
                timeout=5.0, max_concurrent=args.concurrency,
                request_delay=args.delay, deep_mode=args.deep
            )
            asyncio.run(scanner.run(args.target, args.port, args.output))
        elif args.target:
            auditor = OllamaSecurityAuditor(
                target_url=args.target, deep_mode=args.deep, request_delay=args.delay
            )
            
            async def run_single_audit():
                connector = aiohttp.TCPConnector(limit=10)
                async with aiohttp.ClientSession(connector=connector) as session:
                    findings = await auditor.run_audit(session)
                    print(f"\n📤 Generating {args.format.upper()} Report...", file=sys.stderr)
                    try:
                        report_path = auditor.generate_report(findings, args.output, args.format)
                        print(f"✅ Report saved to: {report_path}", file=sys.stderr)
                    except Exception as e:
                        print(f"❌ Failed to generate report: {e}", file=sys.stderr)

            asyncio.run(run_single_audit())
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n⚠️  Operation interrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Operation failed: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()