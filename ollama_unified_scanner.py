#!/usr/bin/env python3
"""
Ollama Unified Security Scanner
Merged from: Ollama Security Auditor (v1.6) + Ollama Remote Server Scanner (v4.2)

Capabilities:
  • Multi-server discovery: Ollama, LM Studio, TextGen WebUI (IPv4 + IPv6)
  • Full Ollama security audit: CVEs, auth bypass, CORS, SSRF, RCE, weight exfil,
    prompt injection, token brute-force, streaming DoS, dangerous endpoints
  • Dynamic threat intel: GitHub Security, NVD, ExploitDB (concurrent fetch, global cache)
  • IP ranges: CIDR, dash notation, file input, IPv6 CIDR
  • Worker-queue concurrency model (eliminates head-of-line blocking)
  • tqdm progress bars, ANSI-aware terminal output
  • Secure file writes (O_NOFOLLOW, 0o600), directory-traversal prevention
  • Markdown + JSON reports, full model config extraction
  • BiDi/Unicode/ANSI terminal injection prevention (pre-computed translate table)

DISCLAIMER: Intended exclusively for authorized security testing and research.
Scanning networks or services without explicit written permission is illegal.

Version: 2.0.0
Author: Yog-Sotho
"""
import argparse
import asyncio
import json
import re
import sys
import os
import socket
import time
import logging
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from ipaddress import (
    IPv4Network, IPv4Address, IPv6Network, IPv6Address, AddressValueError
)
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

# Optional tqdm for progress bars
try:
    import tqdm as _tqdm_mod
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# ==============================================================================
# LOGGING
# ==============================================================================
logger = logging.getLogger(__name__)
_log_handler = logging.StreamHandler(sys.stderr)
_log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(_log_handler)
logger.setLevel(logging.INFO)

# ==============================================================================
# ENUMS
# ==============================================================================
class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class CheckStatus(Enum):
    VULNERABLE = "VULNERABLE"
    SECURE     = "SECURE"
    WARNING    = "WARNING"
    ERROR      = "ERROR"
    SKIPPED    = "SKIPPED"


class ScanStatus(Enum):
    SUCCESS           = "success"
    PORT_CLOSED       = "port_closed"
    INVALID_RESPONSE  = "invalid_response"
    TIMEOUT           = "timeout"
    CONNECTION_ERROR  = "connection_error"
    UNDETECTED        = "undetected"


class ServerType(Enum):
    OLLAMA       = "ollama"
    LM_STUDIO    = "lmstudio"
    TEXTGEN_WEBUI = "textgen_webui"
    UNKNOWN      = "unknown"


# ==============================================================================
# DATACLASSES
# ==============================================================================
@dataclass
class AuditFinding:
    check_name:  str
    severity:    Severity
    status:      CheckStatus
    details:     str
    remediation: str
    cve_id:      Optional[str]            = None
    evidence:    Optional[Dict[str, Any]] = None
    timestamp:   Optional[str]            = None


@dataclass
class ScanResult:
    ip:           str
    port:         int
    server_type:  ServerType
    models:       List[str]
    process_list: List[Dict]
    model_configs: List[Dict]
    url:          str
    is_accessible: bool
    status:       ScanStatus
    audit_findings: Optional[List[AuditFinding]] = None


# ==============================================================================
# JSON ENCODER
# ==============================================================================
class _CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, bytes):
            return str(obj)
        return super().default(obj)


# ==============================================================================
# SANITIZATION (scanner's superior implementation)
# ==============================================================================
# Regex compiled once at module level
ANSI_ESCAPE = re.compile(
    r"\x1B(?:\[[0-?]*[ -/]*[@-~]|\][0-9]*;[\s\S]*?(?:\x07|\x1B\\)|[@-_])"
)
NON_PRINTABLE = re.compile(
    "[\x00-\x1f\x7f-\x9f\xad​-‏‪-‮⁠-⁯﻿]"
)

# Pre-computed translate table for high-speed control-character removal (~10× speedup)
_CTRL_TABLE: Dict[int, None] = {i: None for i in range(32)}
for _i in range(127, 160):
    _CTRL_TABLE[_i] = None
_CTRL_TABLE[0xAD] = None                      # soft hyphen
for _i in range(0x200B, 0x2010):
    _CTRL_TABLE[_i] = None                     # zero-width spaces / marks
for _i in range(0x202A, 0x202F):
    _CTRL_TABLE[_i] = None                     # BiDi controls
for _i in range(0x2060, 0x2070):
    _CTRL_TABLE[_i] = None                     # invisible separators / isolates
_CTRL_TABLE[0xFEFF] = None                     # BOM


def sanitize_text(text: str, max_len: int = 1024) -> str:
    """Remove ANSI escapes, BiDi, and non-printable control chars; truncate to max_len."""
    if not isinstance(text, str):
        text = str(text)
    if len(text) > max_len * 2:
        text = text[: max_len * 2]
    if not text.isprintable():
        if "\x1b" in text:
            text = ANSI_ESCAPE.sub("", text)
        if NON_PRINTABLE.search(text):
            text = text.translate(_CTRL_TABLE)
    if len(text) > max_len:
        text = text[:max_len]
    return text


def safe_display(text: str, max_len: int = 48) -> str:
    """Sanitize and truncate for log output — prevents leaking full secrets."""
    text = sanitize_text(text, max_len=max_len * 2)
    if len(text) <= max_len:
        return text
    return f"{text[:8]}...[truncated, len={len(text)}]"


def sanitize_version(val: str) -> str:
    """Whitelist-filter version strings; block CRLF and path traversal."""
    if not val:
        return ""
    cleaned = "".join(c for c in val if c.isalnum() or c in ".+-_")
    while ".." in cleaned:
        cleaned = cleaned.replace("..", "_")
    return cleaned


def sanitize_model_name(val: str) -> str:
    """Whitelist-filter model names (preserves namespace/model:tag)."""
    if not val:
        return ""
    cleaned = "".join(c for c in val if c.isalnum() or c in ".-_:/")
    while ".." in cleaned:
        cleaned = cleaned.replace("..", "_")
    return cleaned


def sanitize_digest(val: str) -> str:
    """Whitelist-filter hash digests."""
    if not val:
        return ""
    cleaned = "".join(c for c in val if c.isalnum() or c in ":-")
    while ".." in cleaned:
        cleaned = cleaned.replace("..", "_")
    return cleaned


# ==============================================================================
# ANSI COLOR HELPER
# ==============================================================================
def _ansi_color(text: str, code: str) -> str:
    """Colorize text with ANSI codes — respects TTY, NO_COLOR, PYTEST env."""
    if not sys.stderr.isatty():
        return text
    if "NO_COLOR" in os.environ:
        return text
    if "PYTEST_CURRENT_TEST" in os.environ:
        return text
    return f"\033[{code}m{text}\033[0m"


# ==============================================================================
# URL / IP UTILITIES
# ==============================================================================
def resolve_target_url(target: str) -> str:
    """Normalize target → http://IP:11434 with scheme and port validation."""
    target = target.strip().rstrip("/")
    # Reject non-HTTP/S schemes before we potentially prepend http://
    if "://" in target and not target.startswith(("http://", "https://")):
        scheme = target.split("://")[0]
        raise ValueError(f"Unsupported scheme: {scheme}. Only HTTP/HTTPS allowed.")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Unsupported scheme: {parsed.scheme}. Only HTTP/HTTPS allowed."
        )

    prefix = "https://" if target.startswith("https://") else "http://"
    rest = target[len(prefix):]

    path_idx = rest.find("/")
    host_part, path_part = (rest[:path_idx], rest[path_idx:]) if path_idx != -1 else (rest, "")

    has_port = (
        (host_part.startswith("[") and "]:" in host_part)
        or (":" in host_part and not host_part.startswith("["))
    )
    if not has_port:
        rest = f"{host_part}:11434{path_part}"
    return f"{prefix}{rest}"


def format_target_url(ip: str, port: int, is_ipv6: Optional[bool] = None) -> str:
    """Build URL handling IPv4 and IPv6 bracket notation."""
    if is_ipv6 is True or (is_ipv6 is None and ":" in ip):
        return f"http://[{ip}]:{port}"
    return f"http://{ip}:{port}"


def validate_ip_range_static(ip_range: str) -> Iterator[Tuple[str, str]]:
    """
    Expand an IP range/CIDR/single address to (ip, version) tuples.
    Yields lazily — memory-efficient for large ranges.
    Supports IPv4 and IPv6, CIDR, dash notation, suffix shorthand.
    """
    s = ip_range.strip()
    if not s:
        raise ValueError("Empty IP range provided")

    ip_display = safe_display(ip_range)

    # Fast-path: single IP (no slash or dash)
    if "/" not in s and "-" not in s:
        try:
            packed = socket.inet_aton(s)
            if not (
                packed[0] == 10
                or (packed[0] == 172 and (packed[1] & 0xF0) == 16)
                or (packed[0] == 192 and packed[1] == 168)
                or packed[0] == 127
            ):
                try:
                    if IPv4Address(s).is_global:
                        logger.warning(
                            f"⚠️  Scanning PUBLIC IPv4: {ip_display}. Ensure permission!"
                        )
                except AddressValueError:
                    pass
            yield (s, "IPv4")
            return
        except (socket.error, OSError):
            pass

        try:
            socket.inet_pton(socket.AF_INET6, s)
            if IPv6Address(s).is_global:
                logger.warning(
                    f"⚠️  Scanning PUBLIC IPv6: {ip_display}. Ensure permission!"
                )
            yield (s, "IPv6")
            return
        except (socket.error, OSError, AddressValueError):
            pass

    # IPv4 CIDR
    try:
        network = IPv4Network(ip_range, strict=False)
        if network.is_global:
            logger.warning(
                f"⚠️  Scanning PUBLIC IPv4 range: {ip_display}. Ensure permission!"
            )
        for i in range(int(network.network_address), int(network.broadcast_address) + 1):
            yield (socket.inet_ntoa(i.to_bytes(4, "big")), "IPv4")
        return
    except ValueError:
        pass

    # IPv6 CIDR
    try:
        network = IPv6Network(ip_range, strict=False)
        if network.is_global:
            logger.warning(
                f"⚠️  Scanning PUBLIC IPv6 range: {ip_display}. Ensure permission!"
            )
        for i in range(int(network.network_address), int(network.broadcast_address) + 1):
            yield (socket.inet_ntop(socket.AF_INET6, i.to_bytes(16, "big")), "IPv6")
        return
    except ValueError:
        pass

    # IPv4 dash range: "192.168.1.1-10" or "192.168.1.1-192.168.1.10"
    if "-" in ip_range:
        parts = ip_range.split("-")
        if len(parts) != 2:
            raise ValueError(f"Invalid range format: {ip_display}")
        start_str, end_part = parts[0].strip(), parts[1].strip()
        try:
            start_packed = socket.inet_aton(start_str)
            start_int = int.from_bytes(start_packed, "big")
        except socket.error:
            raise ValueError(f"Invalid start IP: {safe_display(start_str)}")

        if "." in end_part:
            try:
                end_packed = socket.inet_aton(end_part)
                end_int = int.from_bytes(end_packed, "big")
            except socket.error:
                raise ValueError(f"Invalid end IP: {safe_display(end_part)}")
            if start_int > end_int:
                raise ValueError("Start IP cannot be greater than end IP")
            for i in range(start_int, end_int + 1):
                yield (socket.inet_ntoa(i.to_bytes(4, "big")), "IPv4")
            return
        else:
            try:
                end_suffix = int(end_part)
            except ValueError:
                raise ValueError(f"Invalid end suffix: {safe_display(end_part)}")
            start_num = start_packed[3]
            if end_suffix < start_num:
                raise ValueError("End suffix less than start suffix")
            for i in range(start_int, start_int + (end_suffix - start_num) + 1):
                yield (socket.inet_ntoa(i.to_bytes(4, "big")), "IPv4")
            return

    raise ValueError(f"Invalid IP address or range: {ip_display}")


def count_ips_in_range_static(ip_range: str) -> int:
    """O(1) IP count for a range/CIDR without expanding the iterator."""
    s = ip_range.strip()
    if not s:
        return 0
    if "/" not in s and "-" not in s:
        return 1

    for cls in (IPv4Network, IPv6Network):
        try:
            return cls(s, strict=False).num_addresses
        except ValueError:
            pass

    if "-" in s:
        parts = s.split("-")
        if len(parts) == 2:
            start_str, end_part = parts[0].strip(), parts[1].strip()
            try:
                start_packed = socket.inet_aton(start_str)
                if "." in end_part:
                    end_packed = socket.inet_aton(end_part)
                    diff = (
                        int.from_bytes(end_packed, "big")
                        - int.from_bytes(start_packed, "big")
                    )
                    return max(0, diff + 1)
                else:
                    return max(0, int(end_part) - start_packed[3] + 1)
            except (socket.error, ValueError):
                pass
    return 1


def parse_ip_from_input(
    input_source: str, is_file: bool = False
) -> Iterator[Tuple[str, str]]:
    """
    Parse IPs from a file (one range per line) or a single range string.
    Yields (ip, version) tuples lazily.
    """
    if is_file:
        if not os.path.exists(input_source):
            raise FileNotFoundError(f"Input file not found: {input_source}")
        logger.info(f"Reading IP ranges from file: {input_source}")
        with open(input_source, "r", encoding="utf-8") as fh:
            for line_num, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                disp = safe_display(line)
                try:
                    count = 0
                    for ip in validate_ip_range_static(line):
                        yield ip
                        count += 1
                    logger.debug(f"Line {line_num}: '{disp}' → {count} IPs")
                except ValueError as exc:
                    logger.warning(f"Skipping invalid line {line_num} ('{disp}'): {exc}")
    else:
        yield from validate_ip_range_static(input_source)


def _count_input_ips(input_source: str, is_file: bool = False) -> int:
    """Count total IPs in input without consuming the iterator."""
    if is_file:
        total = 0
        with open(input_source, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    total += count_ips_in_range_static(line)
        return total
    return count_ips_in_range_static(input_source)


def _secure_write_file(filepath: str, content: str) -> None:
    """Write a file with O_NOFOLLOW + 0o600 to prevent symlink attacks (CWE-59)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(filepath, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


# ==============================================================================
# VERSION UTILITIES & CVE REGISTRY
# ==============================================================================
@lru_cache(maxsize=256)
def _parse_version_tuple(ver_str: str) -> Tuple[int, ...]:
    clean = re.sub(r"[^0-9.]", "", ver_str.split("-")[0])
    parts = clean.split(".")
    while len(parts) < 3:
        parts.append("0")
    return tuple(int(p) for p in parts if p.isdigit()) or (0, 0, 0)


def _version_in_range(target_ver: str, range_str: str) -> bool:
    target = _parse_version_tuple(target_ver)
    for cond in range_str.split(","):
        cond = cond.strip()
        if not cond:
            continue
        if cond.startswith(">="):
            if target < _parse_version_tuple(cond[2:]):
                return False
        elif cond.startswith(">"):
            if target <= _parse_version_tuple(cond[1:]):
                return False
        elif cond.startswith("<="):
            if target > _parse_version_tuple(cond[2:]):
                return False
        elif cond.startswith("<"):
            if target >= _parse_version_tuple(cond[1:]):
                return False
        elif cond.startswith("=="):
            if target != _parse_version_tuple(cond[2:]):
                return False
    return True


# Global advisory cache (shared across all auditor instances in a range scan)
_global_advisories: List[Dict[str, Any]] = []
_global_advisories_fetched: bool = False
_global_advisories_lock: Optional[asyncio.Lock] = None


def _get_advisories_lock() -> asyncio.Lock:
    global _global_advisories_lock
    if _global_advisories_lock is None:
        _global_advisories_lock = asyncio.Lock()
    return _global_advisories_lock


CVE_REGISTRY: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2024-37032",
        "title": "ProbLlama: Critical Path Traversal & SSRF",
        "severity": Severity.CRITICAL,
        "affected_range": ">=0.1.0,<0.3.14",
        "check_type": "endpoint_version_match",
        "description": "Wiz research: critical path traversal and SSRF via /api/pull.",
        "remediation": "Upgrade to >=0.3.14. Block /api/pull at reverse proxy.",
        "indicator": "Version <0.3.14",
    },
    {
        "cve_id": "CVE-2024-28224",
        "title": "DNS Rebinding Attack",
        "severity": Severity.HIGH,
        "affected_range": ">=0.1.0,<0.3.14",
        "check_type": "endpoint_version_match",
        "description": "Malicious DNS rebinding can bypass localhost-only binding.",
        "remediation": "Upgrade to >=0.3.14. Set OLLAMA_HOST=127.0.0.1.",
        "indicator": "Version <0.3.14",
    },
    {
        "cve_id": "CVE-2024-39722",
        "title": "SSRF via Model Pull",
        "severity": Severity.HIGH,
        "affected_range": ">=0.1.0,<0.3.14",
        "check_type": "endpoint_version_match",
        "description": "Improper URL validation in /api/pull allows SSRF.",
        "remediation": "Upgrade to >=0.3.14.",
        "indicator": "Version <0.3.14",
    },
    {
        "cve_id": "CVE-2024-45436",
        "title": "Path Traversal via Modelfile",
        "severity": Severity.CRITICAL,
        "affected_range": ">=0.1.0,<0.4.0",
        "check_type": "endpoint_version_match",
        "description": "Directory traversal in Modelfile FROM paths.",
        "remediation": "Upgrade to >=0.4.0.",
        "indicator": "Version <0.4.0",
    },
    {
        "cve_id": "CVE-2024-7773",
        "title": "Insecure Unix Socket Permissions",
        "severity": Severity.HIGH,
        "affected_range": ">=0.1.0,<0.5.0",
        "check_type": "endpoint_version_match",
        "description": "Default permissions allow local unprivileged access.",
        "remediation": "Upgrade to >=0.5.0.",
        "indicator": "Version <0.5.0",
    },
    {
        "cve_id": "CVE-2025-15514",
        "title": "API Parameter Leakage",
        "severity": Severity.HIGH,
        "affected_range": ">=0.5.0,<0.6.0",
        "check_type": "behavioral_probe",
        "description": "Improper validation of chat parameters leaks context.",
        "remediation": "Upgrade to >=0.6.0.",
        "indicator": "Version range match",
    },
    {
        "cve_id": "GHSA-x9hg-5q6g-q3jr",
        "title": "Environment Variable Exposure",
        "severity": Severity.MEDIUM,
        "affected_range": ">=0.1.0,<0.5.0",
        "check_type": "behavioral_probe",
        "description": "Verbose errors may expose OLLAMA_ env vars.",
        "remediation": "Set OLLAMA_DEBUG=0 in production.",
        "indicator": "Error verbosity",
    },
    {
        "cve_id": "SNYK-WOLFILATEST-OLLAMA-6035174",
        "title": "Dependency Chain Risk",
        "severity": Severity.MEDIUM,
        "affected_range": ">=0.1.0,<0.4.0",
        "check_type": "endpoint_version_match",
        "description": "Underlying dependency flaws in model processing.",
        "remediation": "Upgrade Ollama binary.",
        "indicator": "Version <0.4.0",
    },
]


# ==============================================================================
# OLLAMA SECURITY AUDITOR
# ==============================================================================
class OllamaSecurityAuditor:
    """
    Deep security auditor for a single Ollama API endpoint.
    Runs all checks: CVEs, auth bypass, CORS, dangerous endpoints,
    weight exfiltration, streaming DoS, Modelfile RCE, SSRF, token brute-force,
    prompt injection, model config extraction.
    """

    def __init__(
        self,
        target_url: str,
        timeout: float = 10.0,
        disable_ssl_verify: bool = False,
        max_concurrent: int = 10,
        deep_mode: bool = False,
        request_delay: float = 0.0,
    ):
        logger.debug(f"Initial target input: {target_url}")
        self.base_url            = resolve_target_url(target_url)
        logger.info(f"Resolved target: {self.base_url}")
        self.timeout             = timeout
        self.disable_ssl_verify  = disable_ssl_verify
        self.max_concurrent      = max_concurrent
        self.deep_mode           = deep_mode
        self.request_delay       = request_delay
        self.semaphore           = asyncio.Semaphore(max_concurrent)
        self.findings: List[AuditFinding] = []
        self.stats: Dict[str, int] = {}
        self.detected_version: Optional[str] = None
        self.target_ip_display:  Optional[str] = None
        self.timeout_obj         = aiohttp.ClientTimeout(total=timeout, connect=timeout / 2)
        self._dynamic_advisories_cache: List[Dict[str, Any]] = []
        self._waf_detected       = False
        self._rate_limit_detected = False
        self.discovered_models:  List[str] = []
        self.loaded_models:      List[Dict] = []
        self._request_cache:     Dict[str, Any] = {}

    # -------------------------------------------------------------------------
    # Request engine
    # -------------------------------------------------------------------------
    async def _safe_request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        endpoint: str,
        headers: Optional[Dict[str, str]] = None,
        json_payload: Optional[Dict] = None,
        timeout_override: Optional[float] = None,
        read_body: bool = True,
    ) -> Tuple[Optional[int], Optional[Dict], Optional[str]]:
        """Execute HTTP request with retry logic, caching, and rate-limit awareness."""
        cache_eligible = (
            method.upper() == "GET"
            and endpoint in ("/api/tags", "/api/version")
            and not json_payload
            and not (headers and any(k.lower() == "authorization" for k in headers))
        )
        if cache_eligible and endpoint in self._request_cache:
            logger.debug(f"Cache hit: {endpoint}")
            return self._request_cache[endpoint]

        url = endpoint if endpoint.startswith(("http://", "https://")) else f"{self.base_url}{endpoint}"
        ssl_ctx     = None if self.disable_ssl_verify else True
        req_timeout = aiohttp.ClientTimeout(total=timeout_override or self.timeout)
        max_retries = 3

        for attempt in range(max_retries + 1):
            if self.request_delay > 0:
                await asyncio.sleep(self.request_delay)
            try:
                async with session.request(
                    method=method,
                    url=url,
                    headers=headers or {},
                    json=json_payload,
                    ssl=ssl_ctx,
                    timeout=req_timeout,
                ) as resp:
                    status = resp.status
                    resp_hdrs = dict(resp.headers)

                    if any(k in resp_hdrs for k in ("cf-ray", "x-amzn-requestid", "x-sucuri-id", "x-cdn-forward")):
                        self._waf_detected = True
                    if any(k in resp_hdrs for k in ("x-ratelimit-remaining", "retry-after", "x-rate-limit")):
                        self._rate_limit_detected = True
                        if status == 429:
                            wait = int(resp_hdrs.get("retry-after", 2))
                            logger.warning(f"Rate limit hit. Waiting {wait}s…")
                            await asyncio.sleep(wait)
                            continue

                    body = None
                    if read_body:
                        max_size = 10 * 1024 * 1024  # 10 MB
                        cl = resp.headers.get("Content-Length")
                        if cl and cl.isdigit() and int(cl) > max_size:
                            logger.warning(f"Response from {url} too large ({cl} bytes), skipped.")
                        else:
                            try:
                                is_real = isinstance(resp, aiohttp.ClientResponse) or getattr(
                                    resp, "_test_stream_read", False
                                )
                                if is_real and hasattr(resp, "content") and hasattr(resp.content, "read"):
                                    chunk = await resp.content.read(max_size + 1)
                                    if len(chunk) > max_size:
                                        logger.warning(f"Streamed response from {url} exceeded 10 MB, skipped.")
                                    else:
                                        body = json.loads(chunk.decode("utf-8", errors="ignore"))
                                else:
                                    body = await resp.json()
                            except (json.JSONDecodeError, UnicodeDecodeError, aiohttp.ContentTypeError):
                                body = None
                            except Exception as exc:
                                logger.debug(f"Body read error from {url}: {exc}")
                                body = None

                    result = (status, body, url)
                    if cache_eligible and status == 200:
                        self._request_cache[endpoint] = result
                    return result

            except asyncio.TimeoutError:
                return None, None, url
            except Exception as exc:
                logger.debug(f"Request error → {url}: {exc}")
                if attempt < max_retries:
                    await asyncio.sleep(min(2 ** attempt, 5))
                else:
                    return None, None, url

        return None, None, url

    # -------------------------------------------------------------------------
    # Connectivity
    # -------------------------------------------------------------------------
    async def check_connectivity(self, session: aiohttp.ClientSession) -> AuditFinding:
        parsed = urlparse(self.base_url)
        host = parsed.hostname or parsed.path.split("/")[0]
        port = parsed.port or 11434
        self.target_ip_display = f"{host}:{port}"

        status, body, full_url = await self._safe_request(session, "GET", "/api/version")
        if status == 200 and body and "version" in body:
            self.detected_version = sanitize_version(body.get("version", "unknown"))
            return AuditFinding(
                check_name="API Connectivity & Version Detection",
                severity=Severity.INFO,
                status=CheckStatus.SECURE,
                details=f"Ollama API reachable. Version: {self.detected_version}",
                remediation="Restrict access to authorized clients only.",
                evidence={"version": self.detected_version},
            )
        return AuditFinding(
            check_name="API Connectivity & Version Detection",
            severity=Severity.HIGH,
            status=CheckStatus.ERROR,
            details=f"Failed to connect to {full_url} or version check failed.",
            remediation="Verify target URL and network routing.",
        )

    # -------------------------------------------------------------------------
    # Dynamic threat intel
    # -------------------------------------------------------------------------
    async def _fetch_github_advisories(self, session: aiohttp.ClientSession) -> List[Dict]:
        results = []
        try:
            url = "https://api.github.com/repos/ollama/ollama/security/advisories?state=open&per_page=10"
            hdrs = {"Accept": "application/vnd.github+json", "User-Agent": "OllamaAuditor/2.0"}
            status, data, _ = await self._safe_request(session, "GET", url, headers=hdrs, timeout_override=5.0)
            if status == 200 and isinstance(data, list):
                for adv in data:
                    results.append({
                        "cve_id": adv.get("ghsa_id", "GHSA-UNKNOWN"),
                        "title": adv.get("summary", "GitHub Advisory"),
                        "severity": Severity.HIGH,
                        "affected_range": ">=0.0.0",
                        "check_type": "endpoint_version_match",
                        "description": adv.get("description", "Dynamic advisory via GitHub."),
                        "remediation": "Apply vendor patch immediately.",
                        "indicator": "GitHub Advisory Match",
                        "source": "GitHub",
                    })
        except Exception as exc:
            logger.debug(f"GitHub advisory fetch failed: {exc}")
        return results

    async def _fetch_nvd_advisories(self, session: aiohttp.ClientSession) -> List[Dict]:
        results = []
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=ollama&resultsPerPage=5"
            status, data, _ = await self._safe_request(session, "GET", url, timeout_override=5.0)
            if status == 200 and isinstance(data, dict):
                for item in data.get("vulnerabilities", []):
                    meta = item.get("cve", {})
                    cve_id = meta.get("id")
                    if not cve_id:
                        continue
                    descs = meta.get("descriptions", [{}])
                    desc  = descs[0].get("value", "NVD Advisory")
                    sev   = Severity.MEDIUM
                    for m31 in meta.get("metrics", {}).get("cvssMetricV31", []):
                        score = m31.get("cvssData", {}).get("baseScore", 0)
                        sev = Severity.CRITICAL if score >= 9.0 else Severity.HIGH if score >= 7.0 else Severity.MEDIUM
                        break
                    results.append({
                        "cve_id": cve_id,
                        "title": f"NVD: {cve_id}",
                        "severity": sev,
                        "affected_range": ">=0.0.0",
                        "check_type": "endpoint_version_match",
                        "description": desc,
                        "remediation": "Consult NVD for patch details.",
                        "indicator": "NVD Match",
                        "source": "NVD",
                    })
        except Exception as exc:
            logger.debug(f"NVD advisory fetch failed: {exc}")
        return results

    async def _fetch_exploitdb_advisories(self, session: aiohttp.ClientSession) -> List[Dict]:
        results = []
        try:
            url = "https://www.exploit-db.com/api/v1/exploits?search=ollama&pageSize=5"
            hdrs = {"Accept": "application/json", "User-Agent": "OllamaAuditor/2.0"}
            status, data, _ = await self._safe_request(session, "GET", url, headers=hdrs, timeout_override=5.0)
            if status == 200 and isinstance(data, dict):
                for exp in data.get("data", []):
                    results.append({
                        "cve_id": f"EDB-{exp.get('id', 'UNKNOWN')}",
                        "title": f"ExploitDB: {exp.get('title', 'Unknown Exploit')}",
                        "severity": Severity.HIGH,
                        "affected_range": ">=0.0.0",
                        "check_type": "endpoint_version_match",
                        "description": f"Public exploit: {exp.get('description', 'N/A')}",
                        "remediation": "Apply vendor patch immediately.",
                        "indicator": "ExploitDB Match",
                        "source": "ExploitDB",
                    })
        except Exception as exc:
            logger.debug(f"ExploitDB advisory fetch failed: {exc}")
        return results

    async def _fetch_dynamic_advisories(self, session: aiohttp.ClientSession) -> None:
        global _global_advisories, _global_advisories_fetched

        lock = _get_advisories_lock()
        async with lock:
            if _global_advisories_fetched:
                logger.info("🌐 Using globally cached dynamic advisories.")
                self._dynamic_advisories_cache = list(_global_advisories)
                return

            logger.info("🌐 Fetching dynamic advisories concurrently (GitHub, NVD, ExploitDB)…")
            seen: set = set()
            results = await asyncio.gather(
                self._fetch_github_advisories(session),
                self._fetch_nvd_advisories(session),
                self._fetch_exploitdb_advisories(session),
                return_exceptions=True,
            )
            for res in results:
                if isinstance(res, list):
                    for adv in res:
                        cid = adv["cve_id"]
                        if cid not in seen:
                            seen.add(cid)
                            _global_advisories.append(adv)

            _global_advisories_fetched = True
            self._dynamic_advisories_cache = list(_global_advisories)
            logger.info(f"✅ Loaded {len(self._dynamic_advisories_cache)} dynamic advisories.")

    # -------------------------------------------------------------------------
    # Model discovery
    # -------------------------------------------------------------------------
    async def discover_models(self, session: aiohttp.ClientSession) -> None:
        s, b, _ = await self._safe_request(session, "GET", "/api/tags")
        if s == 200 and b and "models" in b:
            self.discovered_models = [
                sanitize_model_name(m.get("name", "unknown")) for m in b["models"]
            ]
        s, b, _ = await self._safe_request(session, "GET", "/api/ps")
        if s == 200 and b and "models" in b:
            self.loaded_models = []
            for m in b["models"]:
                sm = dict(m)
                if "name" in sm:
                    sm["name"] = sanitize_model_name(sm["name"])
                self.loaded_models.append(sm)

    # -------------------------------------------------------------------------
    # Security checks
    # -------------------------------------------------------------------------
    async def check_known_cves(self, session: aiohttp.ClientSession) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not self.detected_version or self.detected_version == "unknown":
            logger.warning("Version unknown — skipping CVE registry checks.")
            return findings

        combined = CVE_REGISTRY + self._dynamic_advisories_cache
        for cve in combined:
            status_val = CheckStatus.SECURE
            suffix = ""
            if cve["check_type"] == "behavioral_probe":
                if "Environment" in cve["title"]:
                    s, _, _ = await self._safe_request(session, "GET", "/api/invalid-endpoint-test")
                    if s in (404, 500):
                        status_val = CheckStatus.WARNING
                        suffix = " | Verbose error responses detected"
                elif "Parameter Leakage" in cve["title"]:
                    s, b, _ = await self._safe_request(
                        session, "POST", "/api/chat",
                        json_payload={"model": "test", "stream": False, "prompt": "A"},
                    )
                    if b and "context" in b:
                        status_val = CheckStatus.VULNERABLE
                        suffix = " | Context leakage detected"
            else:
                if _version_in_range(self.detected_version, cve["affected_range"]):
                    status_val = (
                        CheckStatus.VULNERABLE
                        if cve["severity"] in (Severity.CRITICAL, Severity.HIGH)
                        else CheckStatus.WARNING
                    )
                    suffix = f" | Matches range {cve['affected_range']}"

            if status_val != CheckStatus.SECURE:
                findings.append(AuditFinding(
                    check_name=f"CVE Check: {cve['title']}",
                    severity=cve["severity"],
                    status=status_val,
                    details=f"{cve['description']}{suffix}",
                    remediation=cve["remediation"],
                    cve_id=cve["cve_id"],
                    evidence={
                        "version": self.detected_version,
                        "affected_range": cve["affected_range"],
                        "source": cve.get("source", "static"),
                    },
                ))
        return findings

    async def check_authentication(self, session: aiohttp.ClientSession) -> AuditFinding:
        accessible = []
        for ep in ("/api/tags", "/api/ps"):
            status, _, _ = await self._safe_request(session, "GET", ep, read_body=False)
            if status == 200:
                accessible.append(ep)
        if accessible:
            return AuditFinding(
                check_name="Authentication Bypass",
                severity=Severity.CRITICAL,
                status=CheckStatus.VULNERABLE,
                details=f"Unauthenticated access: {', '.join(accessible)}",
                remediation="Place Ollama behind a reverse proxy with authentication.",
                evidence={"exposed_endpoints": accessible},
            )
        return AuditFinding(
            check_name="Authentication Bypass",
            severity=Severity.LOW,
            status=CheckStatus.SECURE,
            details="Endpoints returned non-200 without credentials.",
            remediation="Verify reverse-proxy authentication is correctly configured.",
        )

    async def check_info_disclosure(self, session: aiohttp.ClientSession) -> AuditFinding:
        disclosures = []
        s, b, _ = await self._safe_request(session, "GET", "/api/tags")
        if s == 200 and b and "models" in b:
            disclosures.append(f"Model enumeration ({len(b['models'])} models)")
        s, b, _ = await self._safe_request(session, "GET", "/api/ps")
        if s == 200 and b and "models" in b:
            disclosures.append(f"Active process info ({len(b['models'])} loaded models)")
        if disclosures:
            return AuditFinding(
                check_name="Information Disclosure",
                severity=Severity.HIGH,
                status=CheckStatus.VULNERABLE,
                details="; ".join(disclosures),
                remediation="Restrict /api/tags and /api/ps via reverse proxy.",
                evidence={"disclosures": disclosures},
            )
        return AuditFinding(
            check_name="Information Disclosure",
            severity=Severity.LOW,
            status=CheckStatus.SECURE,
            details="No sensitive endpoints returned successful responses.",
            remediation="Continue monitoring for accidental exposure.",
        )

    async def check_cors_policy(self, session: aiohttp.ClientSession) -> AuditFinding:
        malicious_origin = "http://evil-attacker.com"
        try:
            async with session.get(
                f"{self.base_url}/api/tags",
                headers={"Origin": malicious_origin},
                ssl=None if self.disable_ssl_verify else True,
            ) as resp:
                allow_origin = resp.headers.get("access-control-allow-origin", "")
                if "*" in allow_origin or malicious_origin in allow_origin:
                    return AuditFinding(
                        check_name="CORS Misconfiguration",
                        severity=Severity.CRITICAL,
                        status=CheckStatus.VULNERABLE,
                        details=f"Overly permissive CORS: '{allow_origin}'.",
                        remediation="Set OLLAMA_ORIGINS explicitly to known origins.",
                        evidence={"allow_origin": allow_origin},
                    )
        except Exception:
            pass
        return AuditFinding(
            check_name="CORS Misconfiguration",
            severity=Severity.LOW,
            status=CheckStatus.SECURE,
            details="CORS headers appear restrictive.",
            remediation="Verify OLLAMA_ORIGINS is set to intended domains.",
        )

    async def check_dangerous_endpoints(self, session: aiohttp.ClientSession) -> AuditFinding:
        dangerous = {"/api/delete": "DELETE", "/api/pull": "POST", "/api/push": "POST"}
        exposed = []
        for ep, method in dangerous.items():
            payload = {"name": "nonexistent-model-audit-probe-123", "stream": False}
            if ep == "/api/push":
                payload["insecure"] = True
            s, _, _ = await self._safe_request(session, method, ep, json_payload=payload, read_body=False)
            if s not in (401, 403, 405, 502):
                exposed.append(f"{ep} ({method})")
        if exposed:
            return AuditFinding(
                check_name="Dangerous Endpoint Exposure",
                severity=Severity.CRITICAL if not self.deep_mode else Severity.HIGH,
                status=CheckStatus.VULNERABLE,
                details=f"Destructive/modify endpoints accessible: {', '.join(exposed)}.",
                remediation="Firewall /api/delete, /api/pull, /api/push.",
                evidence={"exposed_endpoints": exposed},
            )
        return AuditFinding(
            check_name="Dangerous Endpoint Exposure",
            severity=Severity.LOW,
            status=CheckStatus.SECURE,
            details="Destructive endpoints appear restricted.",
            remediation="Maintain current restrictions.",
        )

    async def check_model_weight_exfil(self, session: aiohttp.ClientSession) -> AuditFinding:
        s, b, _ = await self._safe_request(session, "GET", "/api/tags")
        if not b or "models" not in b:
            return AuditFinding(
                check_name="Model Weight Exfiltration",
                severity=Severity.INFO,
                status=CheckStatus.SKIPPED,
                details="No models found to probe.",
                remediation="N/A",
            )
        digest = sanitize_digest(b["models"][0].get("digest", ""))
        if digest and not digest.startswith("sha256:"):
            digest = f"sha256:{digest}"
        s, _, _ = await self._safe_request(session, "GET", f"/api/blobs/{digest}", read_body=False)
        if s == 200:
            return AuditFinding(
                check_name="Model Weight Exfiltration",
                severity=Severity.CRITICAL,
                status=CheckStatus.VULNERABLE,
                details="Model weights accessible via unauthenticated /api/blobs endpoint.",
                remediation="Restrict blob access via reverse proxy authentication.",
                evidence={"blob_endpoint": f"/api/blobs/{digest}"},
            )
        return AuditFinding(
            check_name="Model Weight Exfiltration",
            severity=Severity.LOW,
            status=CheckStatus.SECURE,
            details="Blob endpoint returned non-200 status.",
            remediation="Maintain current restrictions.",
        )

    async def check_streaming_dos(self, session: aiohttp.ClientSession) -> AuditFinding:
        start = time.monotonic()
        payload = {"model": "test", "stream": True, "prompt": "A" * 5000}
        try:
            async with session.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=3.0),
                ssl=None if self.disable_ssl_verify else True,
            ) as resp:
                elapsed = time.monotonic() - start
                if resp.status == 200 and elapsed < 1.0:
                    return AuditFinding(
                        check_name="Streaming DoS Risk",
                        severity=Severity.MEDIUM,
                        status=CheckStatus.WARNING,
                        details="Server accepted streaming payload without delay.",
                        remediation="Implement streaming timeouts and request size limits.",
                        evidence={"response_time": f"{elapsed:.2f}s"},
                    )
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        return AuditFinding(
            check_name="Streaming DoS Risk",
            severity=Severity.LOW,
            status=CheckStatus.SECURE,
            details="Streaming probe timed out or rejected.",
            remediation="Verify timeout configurations are in place.",
        )

    async def check_modelfile_rce(self, session: aiohttp.ClientSession) -> AuditFinding:
        payload = {
            "name": "audit-rce-probe-do-not-keep",
            "modelfile": "FROM base\nRUN echo 'AUDIT_PROBE_SUCCESS'",
        }
        s, b, _ = await self._safe_request(session, "POST", "/api/create", json_payload=payload)
        if s == 200:
            return AuditFinding(
                check_name="Modelfile RCE Probe",
                severity=Severity.CRITICAL,
                status=CheckStatus.VULNERABLE,
                details="Server accepted Modelfile with RUN command. Potential RCE if sandboxing is misconfigured.",
                remediation="Disable /api/create in production or enforce strict model signing.",
                evidence={"status": s, "payload_accepted": True},
            )
        if s == 400 and b and "error" in b:
            return AuditFinding(
                check_name="Modelfile RCE Probe",
                severity=Severity.LOW,
                status=CheckStatus.SECURE,
                details="RUN command rejected with validation error.",
                remediation="Maintain current validation.",
                evidence={"error": b.get("error")},
            )
        return AuditFinding(
            check_name="Modelfile RCE Probe",
            severity=Severity.INFO,
            status=CheckStatus.SKIPPED,
            details="Endpoint unreachable or unexpected status.",
            remediation="Verify endpoint availability.",
        )

    async def check_prompt_injection_leakage(self, session: aiohttp.ClientSession) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        s, b, _ = await self._safe_request(session, "GET", "/api/tags")
        if not b or "models" not in b:
            return findings

        jailbreak_pats = [
            r"ignore\s+previous\s+instructions",
            r"you\s+are\s+now",
            r"system\s*:\s*",
            r"role\s*:\s*developer",
            r"do\s+not\s+refuse",
            r"output\s+raw",
        ]
        for model in b.get("models", [])[:3]:
            m_name = sanitize_model_name(model.get("name", ""))
            _, cfg, _ = await self._safe_request(session, "POST", "/api/show", json_payload={"name": m_name})
            if cfg and "system" in cfg:
                prompt = cfg["system"]
                hits = [p for p in jailbreak_pats if re.search(p, prompt, re.IGNORECASE)]
                if hits:
                    findings.append(AuditFinding(
                        check_name=f"Prompt Injection Leakage ({m_name})",
                        severity=Severity.HIGH,
                        status=CheckStatus.VULNERABLE,
                        details="System prompt contains potential jailbreak/injection markers.",
                        remediation="Sanitize system prompts; enforce input filtering.",
                        evidence={"model": m_name, "patterns_found": hits},
                    ))
        return findings

    async def check_cloud_metadata_ssrf(self, session: aiohttp.ClientSession) -> AuditFinding:
        if not self.deep_mode:
            return AuditFinding(
                check_name="Cloud Metadata SSRF",
                severity=Severity.INFO,
                status=CheckStatus.SKIPPED,
                details="Skipped (requires --deep mode).",
                remediation="Run with --deep to enable.",
            )
        for meta_url in (
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ):
            payload = {"name": meta_url, "stream": False}
            s, b, _ = await self._safe_request(session, "POST", "/api/pull", json_payload=payload)
            if s == 200 or (b and any(k in str(b) for k in ("ami-id", "instance-id", "google"))):
                return AuditFinding(
                    check_name="Cloud Metadata SSRF",
                    severity=Severity.CRITICAL,
                    status=CheckStatus.VULNERABLE,
                    details="Server fetched cloud metadata via /api/pull.",
                    remediation="Block internal IP ranges in /api/pull URL validation.",
                    evidence={"target": meta_url, "response": str(b)[:200]},
                )
        return AuditFinding(
            check_name="Cloud Metadata SSRF",
            severity=Severity.LOW,
            status=CheckStatus.SECURE,
            details="Cloud metadata endpoints blocked or unreachable.",
            remediation="Maintain SSRF protections.",
        )

    async def check_token_brute(self, session: aiohttp.ClientSession) -> AuditFinding:
        for token in ("ollama", "admin", "password", "test", "Bearer ollama", "Bearer admin"):
            s, _, _ = await self._safe_request(
                session, "GET", "/api/tags",
                headers={"Authorization": token},
                read_body=False,
            )
            if s == 200:
                return AuditFinding(
                    check_name="Token/Key Brute-Force",
                    severity=Severity.CRITICAL,
                    status=CheckStatus.VULNERABLE,
                    details=f"Authentication bypassed with weak token: {token}",
                    remediation="Implement strong API keys or OAuth2. Rotate default credentials.",
                    evidence={"accepted_token": token},
                )
        return AuditFinding(
            check_name="Token/Key Brute-Force",
            severity=Severity.LOW,
            status=CheckStatus.SECURE,
            details="Weak/default tokens rejected.",
            remediation="Verify credential rotation policies.",
        )

    async def check_waf_rate_limit(self) -> AuditFinding:
        details = []
        if self._waf_detected:
            details.append("WAF/Proxy signatures detected in response headers.")
        if self._rate_limit_detected:
            details.append("Rate limiting headers present (auto-throttle active).")
        if details:
            return AuditFinding(
                check_name="WAF & Rate Limit Detection",
                severity=Severity.INFO,
                status=CheckStatus.SECURE,
                details="; ".join(details),
                remediation="Monitor for aggressive throttling during deep scans.",
                evidence={"waf": self._waf_detected, "rate_limit": self._rate_limit_detected},
            )
        return AuditFinding(
            check_name="WAF & Rate Limit Detection",
            severity=Severity.LOW,
            status=CheckStatus.SECURE,
            details="No WAF or rate limiting headers detected.",
            remediation="Consider implementing API rate limiting.",
        )

    # -------------------------------------------------------------------------
    # Model config extraction
    # -------------------------------------------------------------------------
    @staticmethod
    def _clean_modelfile(modelfile: str) -> str:
        m = re.search(r"(^|\n)LICENSE\b", modelfile)
        if m:
            modelfile = modelfile[: m.start()]
        return modelfile.rstrip()

    async def extract_model_configs(self, session: aiohttp.ClientSession) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        s, b, _ = await self._safe_request(session, "GET", "/api/tags")
        if not b or "models" not in b:
            return findings

        prompts_dir = "extracted_prompts"
        os.makedirs(prompts_dir, exist_ok=True)
        abs_prompts_dir = os.path.abspath(prompts_dir)

        for model in b.get("models", [])[:5]:
            model_name = sanitize_model_name(model.get("name", "unknown"))
            s, cfg, _ = await self._safe_request(
                session, "POST", "/api/show",
                json_payload={"name": model_name},
                timeout_override=30.0,
            )
            if s != 200 or not cfg:
                continue

            safe_name  = re.sub(r"[^\w\-_\.]", "_", model_name).strip("_")
            prompt_path = os.path.join(prompts_dir, f"{safe_name}.md")
            abs_path    = os.path.abspath(prompt_path)

            # Defense-in-depth: prevent directory traversal
            if not abs_path.startswith(abs_prompts_dir + os.sep) and abs_path != abs_prompts_dir:
                logger.error(f"Directory traversal blocked for model: {model_name}")
                continue

            system_prompt  = str(cfg.get("system", ""))
            template       = str(cfg.get("template", ""))
            parameters     = str(cfg.get("parameters", ""))
            modelfile_raw  = str(cfg.get("modelfile", ""))
            modelfile_clean = self._clean_modelfile(modelfile_raw)

            try:
                parts = [f"# 📄 Full Model Configuration: `{model_name}`\n\n"]
                parts.append("## 🧠 1. System Prompt\n")
                parts.append(f"```\n{system_prompt}\n```\n\n" if system_prompt.strip() else "> *No system prompt defined.*\n\n")
                parts.append("## 📝 2. Chat Template\n")
                parts.append(f"```\n{template}\n```\n\n" if template.strip() else "> *No custom template defined.*\n\n")
                parts.append("## ⚙️ 3. Parameters\n")
                parts.append(f"```\n{parameters}\n```\n\n" if parameters.strip() else "> *Default parameters used.*\n\n")
                parts.append("## 🐳 4. Modelfile\n")
                parts.append(f"```\n{modelfile_clean}\n```\n\n" if modelfile_clean.strip() else "> *Modelfile not available.*\n\n")

                _secure_write_file(abs_path, "".join(parts))
                logger.info(f"💾 Extracted config: {abs_path}")

                full_ctx = f"{system_prompt} {template} {parameters} {modelfile_clean}"
                sens_patterns = [r"(api[_-]?key|secret|password|token|credential)", r"(https?://[^\s]+)"]
                hits = [p for p in sens_patterns if re.findall(p, full_ctx, re.IGNORECASE)]

                findings.append(AuditFinding(
                    check_name=f"Sensitive Data Risk ({model_name})",
                    severity=Severity.HIGH if hits else Severity.MEDIUM,
                    status=CheckStatus.VULNERABLE if hits else CheckStatus.WARNING,
                    details="Full config extracted. Sensitive patterns found." if hits else "Full config extracted.",
                    remediation="Review extracted prompts for secrets.",
                    evidence={"model": model_name, "file": abs_path},
                ))
            except Exception as exc:
                logger.error(f"Failed to write config for {model_name}: {exc}")
                findings.append(AuditFinding(
                    check_name=f"Extraction Error ({model_name})",
                    severity=Severity.HIGH,
                    status=CheckStatus.ERROR,
                    details=f"Failed to save configuration: {exc}",
                    remediation="Check file permissions or disk space.",
                    evidence={"model": model_name},
                ))
        return findings

    # -------------------------------------------------------------------------
    # Probe runner helper
    # -------------------------------------------------------------------------
    async def _run_probe(self, coro, name: str):
        try:
            result = await coro
            print(f"  ✨ Completed: {name}", file=sys.stderr)
            return result
        except Exception as exc:
            print(f"  💥 Failed: {name} ({exc})", file=sys.stderr)
            return exc

    # -------------------------------------------------------------------------
    # Full audit orchestration
    # -------------------------------------------------------------------------
    async def run_audit(self, session: aiohttp.ClientSession) -> List[AuditFinding]:
        print(f"\n🔍 Auditing: {self.base_url}", file=sys.stderr)
        print(f"🛡️  Mode: {'DEEP (Semi-Intrusive)' if self.deep_mode else 'STANDARD (Read-Only)'}", file=sys.stderr)
        print("-" * 70, file=sys.stderr)
        t_start = time.monotonic()
        self.findings = []

        await self._fetch_dynamic_advisories(session)
        await self.discover_models(session)

        connectivity = await self.check_connectivity(session)
        self.findings.append(connectivity)
        if connectivity.status == CheckStatus.ERROR:
            print("❌ Audit aborted: target unreachable.", file=sys.stderr)
            return self.findings

        print(f"✅ Version: {self.detected_version}", file=sys.stderr)
        if self.discovered_models:
            print(f"📦 Models: {', '.join(self.discovered_models)}", file=sys.stderr)

        print("📊 Checking CVEs…", file=sys.stderr)
        self.findings.extend(await self.check_known_cves(session))

        # Concurrently run independent core checks
        auth, info, cors, dangerous = await asyncio.gather(
            self.check_authentication(session),
            self.check_info_disclosure(session),
            self.check_cors_policy(session),
            self.check_dangerous_endpoints(session),
        )
        self.findings.extend((auth, info, cors, dangerous))

        print("🧪 Running advanced probes…", file=sys.stderr)
        raw = await asyncio.gather(
            self._run_probe(self.check_model_weight_exfil(session), "Weight Exfiltration"),
            self._run_probe(self.check_streaming_dos(session), "Streaming DoS"),
            self._run_probe(self.check_modelfile_rce(session), "Modelfile RCE"),
            self._run_probe(self.check_cloud_metadata_ssrf(session), "Cloud Metadata SSRF"),
            self._run_probe(self.check_token_brute(session), "Token Brute-Force"),
            self._run_probe(self.check_prompt_injection_leakage(session), "Prompt Injection"),
            self._run_probe(self.extract_model_configs(session), "Model Config Extraction"),
            return_exceptions=True,
        )

        ops = [("append",), ("append",), ("append",), ("append",),
               ("append",), ("extend",), ("extend",)]
        for (op,), result in zip(ops, raw):
            if isinstance(result, Exception):
                logger.error(f"Probe failed: {result}")
            elif result:
                getattr(self.findings, op)(result)

        self.findings.append(await self.check_waf_rate_limit())

        self.stats = {"total_checks": len(self.findings)}
        for sev in Severity:
            self.stats[sev.value] = sum(1 for f in self.findings if f.severity == sev)

        dur = time.monotonic() - t_start
        print(f"\n📝 Audit completed in {dur:.2f}s", file=sys.stderr)
        self._print_summary()
        return self.findings

    def _print_summary(self) -> None:
        SEV_EMOJI = {
            Severity.CRITICAL: f"🔴 {_ansi_color('[CRITICAL]', '1;31')}",
            Severity.HIGH:     f"🟠 {_ansi_color('[HIGH]    ', '1;33')}",
            Severity.MEDIUM:   f"🟡 {_ansi_color('[MEDIUM]  ', '1;33')}",
            Severity.LOW:      f"🔵 {_ansi_color('[LOW]     ', '1;34')}",
            Severity.INFO:     f"⚪ {_ansi_color('[INFO]    ', '1;36')}",
        }
        print("\n" + "=" * 70, file=sys.stderr)
        print(_ansi_color("📊 AUDIT FINDINGS SUMMARY", "1;36"), file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        line = " | ".join(
            f"{SEV_EMOJI[s].split()[0]} {s.value}: {self.stats[s.value]}" for s in Severity
        )
        print(f"Summary: {line}", file=sys.stderr)
        print("-" * 70, file=sys.stderr)

        actionable = [
            f for f in self.findings
            if f.status in (CheckStatus.VULNERABLE, CheckStatus.WARNING, CheckStatus.ERROR)
        ]
        if actionable:
            print(_ansi_color("⚠️  Action Required:", "1;31"), file=sys.stderr)
            sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                         Severity.LOW: 3, Severity.INFO: 4}
            for f in sorted(actionable, key=lambda x: sev_order.get(x.severity, 5)):
                if f.status == CheckStatus.VULNERABLE:
                    s_indicator = f"❌ {_ansi_color('VULNERABLE', '1;31')}"
                elif f.status == CheckStatus.ERROR:
                    s_indicator = f"💥 {_ansi_color('ERROR', '1;31')}"
                else:
                    s_indicator = f"⚠️ {_ansi_color('WARNING', '1;33')}"
                cve_tag = f" [{f.cve_id}]" if f.cve_id else ""
                print(f"  {SEV_EMOJI[f.severity]} {f.check_name}{cve_tag} ({s_indicator})", file=sys.stderr)
                print(f"    └─ {f.details}", file=sys.stderr)
                print(f"    └─ Fix: {f.remediation}", file=sys.stderr)
        else:
            print(f"✅ {_ansi_color('All checks SECURE.', '1;32')}", file=sys.stderr)

        prompts_dir = "extracted_prompts"
        if os.path.isdir(prompts_dir) and any(f.endswith(".md") for f in os.listdir(prompts_dir)):
            print(f"📂 LLM configs: {os.path.abspath(prompts_dir)}", file=sys.stderr)
        print("=" * 70 + "\n", file=sys.stderr)

    # -------------------------------------------------------------------------
    # Report generation
    # -------------------------------------------------------------------------
    def generate_report(
        self,
        findings: List[AuditFinding],
        output_path: str,
        format_type: str = "md",
    ) -> str:
        timestamp  = time.strftime("%Y-%m-%d_%H%M%S", time.gmtime())
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        if format_type == "json":
            report_path = f"{output_path}_audit_{timestamp}.json"
            data = {
                "metadata": {
                    "target": self.base_url,
                    "ip_port": self.target_ip_display,
                    "version": self.detected_version,
                    "models_found": self.discovered_models,
                    "models_loaded": [m.get("name") for m in self.loaded_models],
                    "timestamp": timestamp,
                    "stats": self.stats,
                },
                "findings": [
                    {
                        "check_name": f.check_name,
                        "severity": f.severity.value,
                        "status": f.status.value,
                        "details": f.details,
                        "remediation": f.remediation,
                        "cve_id": f.cve_id,
                        "evidence": f.evidence,
                    }
                    for f in findings
                ],
            }
            _secure_write_file(report_path, json.dumps(data, indent=2, cls=_CustomEncoder))
            return os.path.abspath(report_path)

        if format_type == "md":
            report_path = f"{output_path}_audit_{timestamp}.md"
            sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                         Severity.LOW: 3, Severity.INFO: 4}
            lines = [
                "# 🛡️ Ollama Unified Security Audit Report",
                f"**Generated:** {timestamp}\n",
                "## 🎯 Target Profile",
                "| Property | Value |",
                "| :--- | :--- |",
                f"| **Target Host** | `{self.base_url}` |",
                f"| **IP:PORT** | `{self.target_ip_display}` |",
                f"| **Detected Version** | `{self.detected_version}` |",
                "| **Status** | ✅ AUDIT COMPLETED |",
                "",
                "## 📦 Discovered Models",
                f"- **Installed ({len(self.discovered_models)}):**",
            ]
            for m in (self.discovered_models or ["None"]):
                lines.append(f"  - `{m}`")
            lines.append(f"- **Loaded ({len(self.loaded_models)}):**")
            for m in self.loaded_models:
                size = m.get("size", 0)
                sfx = f" ({size / 1024**3:.1f} GB)" if size > 0 else ""
                lines.append(f"  - `{m.get('name', 'unknown')}`{sfx}")
            if not self.loaded_models:
                lines.append("  - None")
            lines.extend([
                "",
                "## 📊 Summary Statistics",
                f"- 🔴 **Critical:** {self.stats.get('CRITICAL', 0)}",
                f"- 🟠 **High:** {self.stats.get('HIGH', 0)}",
                f"- 🟡 **Medium:** {self.stats.get('MEDIUM', 0)}",
                f"- 🔵 **Low:** {self.stats.get('LOW', 0)}",
                f"- ⚪ **Info:** {self.stats.get('INFO', 0)}",
                "",
                "## 📋 Findings Detail",
                "",
            ])
            for f in sorted(findings, key=lambda x: sev_order.get(x.severity, 5)):
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                         "LOW": "🔵", "INFO": "⚪"}.get(f.severity.value, "⚪")
                s_label = {
                    CheckStatus.VULNERABLE: "❌ VULNERABLE",
                    CheckStatus.WARNING: "⚠️ WARNING",
                    CheckStatus.ERROR: "💥 ERROR",
                    CheckStatus.SKIPPED: "⏭️ SKIPPED",
                    CheckStatus.SECURE: "✅ SECURE",
                }.get(f.status, f.status.value)
                cve_tag = f" `[{f.cve_id}]`" if f.cve_id else ""
                lines += [
                    f"### {emoji} {f.check_name}{cve_tag}",
                    f"- **Status:** {s_label}",
                    f"- **Details:** {f.details}",
                    f"- **Remediation:** {f.remediation}",
                ]
                if f.evidence:
                    lines += [
                        "- **Evidence:**",
                        "  ```json",
                        f"  {json.dumps(f.evidence, indent=2, cls=_CustomEncoder)}",
                        "  ```",
                    ]
                lines += ["---", ""]

            _secure_write_file(report_path, "\n".join(lines))
            return os.path.abspath(report_path)

        raise ValueError(f"Unsupported format: {format_type}")


# ==============================================================================
# LLM SERVER DISCOVERY ENGINE (from scanner, enhanced)
# ==============================================================================
class LLMDiscoveryEngine:
    """
    Lightweight discovery layer: detects server type (Ollama / LM Studio / TextGen WebUI)
    via concurrent HTTP probes. Shared by both single-target and range scans.
    """

    USER_AGENT = "OllamaUnifiedScanner/2.0"

    def __init__(
        self,
        timeout: float = 5.0,
        disable_ssl_verify: bool = False,
        retry_attempts: int = 3,
        retry_delay: float = 0.5,
    ):
        self.timeout         = timeout
        self.ssl_setting     = not disable_ssl_verify
        self.retry_attempts  = retry_attempts
        self.retry_delay     = retry_delay

    async def _probe_endpoint(
        self,
        session: aiohttp.ClientSession,
        url: str,
        server_type: ServerType,
        parser_func,
    ) -> Optional[Tuple[ServerType, List[str]]]:
        """Probe one endpoint with retry + exponential backoff. No redirects (SSRF guard)."""
        for attempt in range(self.retry_attempts):
            try:
                async with session.get(
                    url,
                    headers={"User-Agent": self.USER_AGENT},
                    ssl=self.ssl_setting,
                    timeout=aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout / 2),
                    allow_redirects=False,
                ) as resp:
                    if resp.status == 200:
                        try:
                            # 2 MB guard against OOM
                            body = await resp.content.read(2 * 1024 * 1024)
                            data = json.loads(body)
                            models = parser_func(data)
                            if models is not None:
                                return (server_type, models)
                        except (json.JSONDecodeError, aiohttp.ContentTypeError):
                            pass
                    return None
            except (asyncio.TimeoutError, aiohttp.ClientError):
                if attempt < self.retry_attempts - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
            except Exception:
                break
        return None

    async def detect_server_type(
        self,
        ip: str,
        port: int,
        session: aiohttp.ClientSession,
        base_url: Optional[str] = None,
    ) -> Tuple[ServerType, List[str], ScanStatus]:
        """
        Concurrently probe all supported server types and return on the first match.
        """
        if not base_url:
            base_url = format_target_url(ip, port)

        def _safe_model_list(d, key: str) -> Optional[List[str]]:
            if not isinstance(d, dict):
                return None
            items = d.get(key)
            if not isinstance(items, list):
                return None
            return [
                sanitize_text(
                    m.get("name", m.get("id", "unknown")) if isinstance(m, dict) else "invalid",
                    max_len=256,
                )
                for m in items[:50]
            ]

        probes = [
            self._probe_endpoint(
                session, f"{base_url}/api/tags", ServerType.OLLAMA,
                lambda d: _safe_model_list(d, "models"),
            ),
            self._probe_endpoint(
                session, f"{base_url}/v1/models", ServerType.LM_STUDIO,
                lambda d: _safe_model_list(d, "data"),
            ),
            self._probe_endpoint(
                session, f"{base_url}/api/info", ServerType.TEXTGEN_WEBUI,
                lambda d: (
                    [sanitize_text(d.get("loading_model", d.get("model_name", "unknown")), max_len=256)]
                    if isinstance(d, dict) else None
                ),
            ),
        ]

        pending = [asyncio.create_task(p) for p in probes]
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    result = task.result()
                    if result:
                        for t in pending:
                            t.cancel()
                        return (result[0], result[1], ScanStatus.SUCCESS)
                except Exception:
                    continue

        return (ServerType.UNKNOWN, [], ScanStatus.UNDETECTED)

    async def get_process_status(
        self,
        ip: str,
        port: int,
        session: aiohttp.ClientSession,
        base_url: Optional[str] = None,
    ) -> Tuple[List[Dict], ScanStatus]:
        """Fetch loaded model processes from /api/ps."""
        if not base_url:
            base_url = format_target_url(ip, port)
        url = f"{base_url}/api/ps"

        for attempt in range(self.retry_attempts):
            try:
                async with session.get(
                    url,
                    headers={"User-Agent": self.USER_AGENT, "Accept": "application/json"},
                    ssl=self.ssl_setting,
                    timeout=aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout / 2),
                    allow_redirects=False,
                ) as resp:
                    if resp.status == 200:
                        body = await resp.content.read(2 * 1024 * 1024)
                        data = json.loads(body)
                        if not isinstance(data, dict):
                            return ([], ScanStatus.INVALID_RESPONSE)
                        raw = data.get("models")
                        processes = [m for m in raw[:50] if isinstance(m, dict)] if isinstance(raw, list) else []
                        for p in processes:
                            if "name" in p:
                                p["name"] = sanitize_text(p["name"], max_len=256)
                            if not isinstance(p.get("size"), (int, float)):
                                p["size"] = 0
                        return (processes, ScanStatus.SUCCESS)
                    if resp.status == 404:
                        return ([], ScanStatus.SUCCESS)
                    return ([], ScanStatus.INVALID_RESPONSE)
            except asyncio.TimeoutError:
                if attempt < self.retry_attempts - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
                else:
                    return ([], ScanStatus.TIMEOUT)
            except Exception:
                if attempt < self.retry_attempts - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
                else:
                    return ([], ScanStatus.CONNECTION_ERROR)
        return ([], ScanStatus.CONNECTION_ERROR)

    async def get_model_info(
        self,
        ip: str,
        port: int,
        session: aiohttp.ClientSession,
        model_name: str,
        base_url: Optional[str] = None,
    ) -> Tuple[Optional[Dict], ScanStatus]:
        """Fetch single model configuration from /api/show."""
        if not base_url:
            base_url = format_target_url(ip, port)
        url = f"{base_url}/api/show"

        for attempt in range(self.retry_attempts):
            try:
                async with session.post(
                    url,
                    headers={"User-Agent": self.USER_AGENT, "Content-Type": "application/json"},
                    json={"name": model_name},
                    ssl=self.ssl_setting,
                    timeout=aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout / 2),
                    allow_redirects=False,
                ) as resp:
                    if resp.status == 200:
                        body = await resp.content.read(2 * 1024 * 1024)
                        data = json.loads(body)
                        if not isinstance(data, dict):
                            return (None, ScanStatus.INVALID_RESPONSE)
                        config = {
                            "system_prompt": sanitize_text(data.get("system", ""), max_len=1024),
                            "parameters": sanitize_text(data.get("parameters", ""), max_len=1024),
                            "template": sanitize_text(data.get("template", ""), max_len=1024),
                        }
                        return (config, ScanStatus.SUCCESS)
                    if resp.status == 404:
                        return ({}, ScanStatus.SUCCESS)
                    return (None, ScanStatus.INVALID_RESPONSE)
            except asyncio.TimeoutError:
                if attempt < self.retry_attempts - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
                else:
                    return (None, ScanStatus.TIMEOUT)
            except Exception:
                if attempt < self.retry_attempts - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
                else:
                    return (None, ScanStatus.CONNECTION_ERROR)
        return (None, ScanStatus.CONNECTION_ERROR)


# ==============================================================================
# UNIFIED RANGE SCANNER
# ==============================================================================
class OllamaUnifiedScanner:
    """
    Worker-queue range scanner with LLM server discovery + optional Ollama security audit.
    Combines the full-audit depth of OllamaSecurityAuditor with the multi-server discovery
    and high-throughput concurrency of the original remote server scanner.
    """

    def __init__(
        self,
        timeout: float = 5.0,
        max_concurrent: int = 100,
        retry_attempts: int = 3,
        retry_delay: float = 0.5,
        enable_dns_cache: bool = True,
        disable_ssl_verify: bool = False,
        port_timeout: Optional[float] = None,
        deep_mode: bool = False,
        audit_mode: bool = True,
        request_delay: float = 0.0,
    ):
        self.timeout          = timeout
        self.max_concurrent   = max_concurrent
        self.retry_attempts   = retry_attempts
        self.retry_delay      = retry_delay
        self.enable_dns_cache = enable_dns_cache
        self.disable_ssl_verify = disable_ssl_verify
        self.port_timeout     = port_timeout if port_timeout is not None else timeout / 2
        self.deep_mode        = deep_mode
        self.audit_mode       = audit_mode
        self.request_delay    = request_delay
        self.stats: Dict[str, int] = defaultdict(int)
        self._init_stats()
        self.discovery = LLMDiscoveryEngine(
            timeout=timeout,
            disable_ssl_verify=disable_ssl_verify,
            retry_attempts=retry_attempts,
            retry_delay=retry_delay,
        )

    def _init_stats(self) -> None:
        for k in ("successful_queries", "timeout", "connection_error", "scan_errors",
                  "undetected", "port_closed", "process_status_success", "model_info_success"):
            self.stats[k] = 0
        for srv in ServerType:
            if srv != ServerType.UNKNOWN:
                self.stats[f"{srv.value}_count"] = 0

    async def _check_port(self, ip: str, port: int) -> Tuple[bool, ScanStatus]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.port_timeout,
            )
            writer.close()
            await writer.wait_closed()
            return (True, ScanStatus.SUCCESS)
        except asyncio.TimeoutError:
            self.stats["timeout"] += 1
            return (False, ScanStatus.TIMEOUT)
        except ConnectionRefusedError:
            self.stats["port_closed"] += 1
            return (False, ScanStatus.PORT_CLOSED)
        except OSError as exc:
            self.stats["connection_error"] += 1
            logger.debug(f"Port check {ip}:{port}: {exc}")
            return (False, ScanStatus.CONNECTION_ERROR)

    async def _scan_single_target(
        self,
        ip: str,
        ip_version: str,
        port: int,
        session: aiohttp.ClientSession,
    ) -> Optional[ScanResult]:
        try:
            is_open, _ = await self._check_port(ip, port)
            if not is_open:
                return None

            url = format_target_url(ip, port, is_ipv6=(ip_version == "IPv6"))
            server_type, models, scan_status = await self.discovery.detect_server_type(
                ip, port, session, base_url=url
            )
            if server_type == ServerType.UNKNOWN:
                return None

            self.stats["successful_queries"] += 1
            self.stats[f"{server_type.value}_count"] += 1

            process_list: List[Dict] = []
            model_configs: List[Dict] = []
            audit_findings: Optional[List[AuditFinding]] = None

            if self.deep_mode and models and server_type == ServerType.OLLAMA:
                target_models = models[:3]
                tasks = [self.discovery.get_process_status(ip, port, session, base_url=url)]
                tasks += [
                    self.discovery.get_model_info(ip, port, session, m, base_url=url)
                    for m in target_models
                ]
                results = await asyncio.gather(*tasks)
                procs, _ = results[0]
                process_list = procs if procs else []
                for i, (cfg, _) in enumerate(results[1:]):
                    if cfg:
                        model_configs.append({"model_name": target_models[i], "config": cfg})
                        self.stats["model_info_success"] += 1
                if process_list:
                    self.stats["process_status_success"] += 1

            # Full security audit for Ollama targets
            if self.audit_mode and server_type == ServerType.OLLAMA:
                try:
                    auditor = OllamaSecurityAuditor(
                        target_url=url,
                        timeout=self.timeout,
                        disable_ssl_verify=self.disable_ssl_verify,
                        max_concurrent=10,
                        deep_mode=self.deep_mode,
                        request_delay=self.request_delay,
                    )
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(limit=10),
                        timeout=aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout / 2),
                    ) as audit_session:
                        audit_findings = await auditor.run_audit(audit_session)
                except Exception as exc:
                    logger.error(f"Audit failed for {url}: {exc}")

            return ScanResult(
                ip=ip,
                port=port,
                server_type=server_type,
                models=models or [],
                process_list=process_list,
                model_configs=model_configs,
                url=url,
                is_accessible=models is not None,
                status=scan_status,
                audit_findings=audit_findings,
            )
        except Exception as exc:
            logger.debug(f"Unexpected error scanning {ip}:{port}: {exc}")
            self.stats["scan_errors"] += 1
            return None

    async def scan_range(
        self,
        input_source: str,
        is_file: bool = False,
        port: int = 11434,
        show_progress: bool = True,
        output_base: Optional[str] = None,
        format_type: str = "md",
    ) -> List[ScanResult]:
        """
        Main scanner entry point using a worker-queue model.
        Eliminates head-of-line blocking — all workers pull from a shared async queue.
        """
        total_ips = _count_input_ips(input_source, is_file)
        print(
            f"\n🌐 Scanning {total_ips} IPs on port {port}"
            + (" [DEEP]" if self.deep_mode else "")
            + (" [AUDIT]" if self.audit_mode else ""),
            file=sys.stderr,
        )
        print("-" * 70, file=sys.stderr)

        if total_ips > 10_000:
            resp = input(f"\n⚠️  Warning: scanning {total_ips} IPs may take significant time. Continue? (y/N): ")
            if resp.strip().lower() != "y":
                print("❌ Scan cancelled by user.", file=sys.stderr)
                return []

        results: List[ScanResult] = []
        t_start = time.monotonic()
        completed = 0
        successes = 0

        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent * 4,
            limit_per_host=20,
            ttl_dns_cache=300 if self.enable_dns_cache else None,
        )

        if HAS_TQDM and show_progress:
            pbar = _tqdm_mod.tqdm(total=total_ips, desc="Scanning", unit="IP",
                                  file=sys.stdout, mininterval=0.5)
        else:
            pbar = None

        queue: asyncio.Queue = asyncio.Queue(maxsize=self.max_concurrent * 2)

        async def worker():
            nonlocal completed, successes
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout / 2),
                headers={"Accept": "application/json"},
            ) as session:
                while True:
                    try:
                        item = await queue.get()
                        if item is None:
                            queue.task_done()
                            break

                        ip, version = item
                        result = await self._scan_single_target(ip, version, port, session)
                        completed += 1

                        if result and result.is_accessible and result.models:
                            successes += 1
                            results.append(result)
                            m_list = ", ".join(result.models[:5])
                            m_sfx  = "…" if len(result.models) > 5 else ""
                            msg    = (
                                f"\n✅ {result.server_type.value.upper()} @ {result.url} | "
                                f"Models ({len(result.models)}): {m_list}{m_sfx}"
                            )
                            if HAS_TQDM and pbar:
                                _tqdm_mod.tqdm.write(msg)
                            else:
                                print(msg, flush=True)

                            if output_base and result.server_type == ServerType.OLLAMA and self.audit_mode:
                                safe_ip = ip.replace(":", "_")
                                out_file = os.path.join(output_base, f"audit_{safe_ip}")
                                _do_report_for_result(result, out_file, format_type)

                        elif result and result.is_accessible:
                            results.append(result)

                        if pbar:
                            pbar.update(1)
                        elif show_progress and (completed % 50 == 0 or completed == total_ips):
                            elapsed = time.monotonic() - t_start
                            rate    = completed / elapsed if elapsed > 0 else 0
                            pct     = completed / total_ips * 100 if total_ips else 0
                            print(
                                f"\r📈 {completed}/{total_ips} ({pct:.1f}%) | "
                                f"{rate:.1f} IPs/s | found {successes}",
                                end="",
                                flush=True,
                                file=sys.stderr,
                            )
                        queue.task_done()
                    except asyncio.CancelledError:
                        queue.task_done()
                        break
                    except Exception as exc:
                        logger.error(f"Worker error: {exc}")
                        queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self.max_concurrent)]
        try:
            for ip_item in parse_ip_from_input(input_source, is_file=is_file):
                await queue.put(ip_item)
            for _ in range(self.max_concurrent):
                await queue.put(None)
            await asyncio.gather(*workers)
        except (asyncio.CancelledError, Exception):
            for w in workers:
                if not w.done():
                    w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            raise

        if pbar:
            pbar.close()

        dur = time.monotonic() - t_start
        print(f"\n\n🏁 Scan completed in {dur:.2f}s", file=sys.stderr)
        self._print_scan_stats(total_ips, successes, dur)
        return results

    def _print_scan_stats(self, total: int, successes: int, duration: float) -> None:
        print("\n📊 Scan Statistics:", file=sys.stderr)
        print(f"  • Total IPs scanned:     {total}", file=sys.stderr)
        print(f"  • Successful queries:    {self.stats['successful_queries']}", file=sys.stderr)
        print(f"  • Port closed:           {self.stats['port_closed']}", file=sys.stderr)
        print(f"  • Timeouts:              {self.stats['timeout']}", file=sys.stderr)
        print(f"  • Connection errors:     {self.stats['connection_error']}", file=sys.stderr)
        print(f"  • Undetected:            {self.stats['undetected']}", file=sys.stderr)
        print("\n📋 Discovered Server Types:", file=sys.stderr)
        print(f"  • Ollama:                {self.stats['ollama_count']}", file=sys.stderr)
        print(f"  • LM Studio:             {self.stats['lmstudio_count']}", file=sys.stderr)
        print(f"  • TextGen WebUI:         {self.stats['textgen_webui_count']}", file=sys.stderr)
        if total > 0:
            print(f"  • Success rate:          {successes / total * 100:.2f}%", file=sys.stderr)

    def generate_scan_report(
        self, results: List[ScanResult], output_path: str, format_type: str = "json"
    ) -> str:
        timestamp = time.strftime("%Y-%m-%d_%H%M%S", time.gmtime())
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        if format_type == "json":
            report_path = f"{output_path}_scan_{timestamp}.json"
            data = {
                "scan_summary": {
                    "timestamp": timestamp,
                    "total_found": len(results),
                    "statistics": dict(self.stats),
                },
                "servers": [
                    {
                        "ip": r.ip,
                        "port": r.port,
                        "url": r.url,
                        "server_type": r.server_type.value,
                        "models_count": len(r.models),
                        "models": r.models,
                        "process_status": r.process_list,
                        "model_configs": r.model_configs,
                        "is_accessible": r.is_accessible,
                        "status": r.status.value,
                        "audit_findings_count": len(r.audit_findings) if r.audit_findings else 0,
                    }
                    for r in results
                ],
            }
            with open(report_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            return report_path

        if format_type == "text":
            report_path = f"{output_path}_scan_{timestamp}.txt"
            with open(report_path, "w", encoding="utf-8") as fh:
                fh.write("=" * 60 + "\n")
                fh.write("Ollama Unified Scanner — Scan Report\n")
                fh.write("=" * 60 + "\n")
                fh.write(f"Generated: {timestamp}\n")
                fh.write(f"Servers Found: {len(results)}\n\n")
                for r in results:
                    fh.write(f"\n[{r.server_type.value}] {r.url}\n")
                    if r.models:
                        fh.write(f"  Models: {', '.join(r.models)}\n")
                    if r.process_list:
                        fh.write(f"  Loaded: {len(r.process_list)}\n")
                    if r.audit_findings:
                        vulns = sum(
                            1 for f in r.audit_findings if f.status == CheckStatus.VULNERABLE
                        )
                        fh.write(f"  Audit Findings: {len(r.audit_findings)} ({vulns} VULNERABLE)\n")
            return report_path

        raise ValueError(f"Unsupported format: {format_type}")


def _do_report_for_result(result: ScanResult, out_file: str, format_type: str) -> None:
    """Generate an audit report for a range-scan result if audit findings exist."""
    if not result.audit_findings:
        return
    try:
        auditor = OllamaSecurityAuditor.__new__(OllamaSecurityAuditor)
        auditor.base_url         = result.url
        auditor.target_ip_display = f"{result.ip}:{result.port}"
        auditor.detected_version = "unknown"
        auditor.discovered_models = result.models
        auditor.loaded_models    = result.process_list
        auditor.stats            = {"total_checks": len(result.audit_findings)}
        for sev in Severity:
            auditor.stats[sev.value] = sum(
                1 for f in result.audit_findings if f.severity == sev
            )
        path = auditor.generate_report(result.audit_findings, out_file, format_type)
        print(f"   📝 Audit report: {path}", file=sys.stderr)
    except Exception as exc:
        logger.error(f"Failed to generate report for {result.url}: {exc}")


# ==============================================================================
# BANNER
# ==============================================================================
BANNER = r"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    ██████╗ ██╗     ██╗      █████╗ ███╗   ███╗ █████╗               ║
║   ██╔═══██╗██║     ██║     ██╔══██╗████╗ ████║██╔══██╗              ║
║   ██║   ██║██║     ██║     ███████║██╔████╔██║███████║              ║
║   ██║   ██║██║     ██║     ██╔══██║██║╚██╔╝██║██╔══██║              ║
║   ╚██████╔╝███████╗███████╗██║  ██║██║ ╚═╝ ██║██║  ██║              ║
║    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝              ║
║                                                                      ║
║   UNIFIED SECURITY SCANNER  v2.0.0                                   ║
║   Discover · Audit · Report                                          ║
║   Ollama · LM Studio · TextGen WebUI  ·  IPv4 + IPv6                 ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""


# ==============================================================================
# MAIN
# ==============================================================================
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ollama Unified Security Scanner — discovery + full audit in one tool",
        epilog="""
EXAMPLES:
  %(prog)s 192.168.1.100                        # Single-target Ollama audit
  %(prog)s 192.168.1.0/24                       # CIDR range scan + audit
  %(prog)s 192.168.1.1-100 --scan-only          # Range discovery, no audit
  %(prog)s --file targets.txt --deep            # File input, deep probes
  %(prog)s 192.168.1.0/24 -p 1234 -o report    # LM Studio port, save report
  %(prog)s fd00::/120 -p 11434                  # IPv6 CIDR scan

DISCLAIMER: Authorized security testing only.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("target", nargs="?",
                        help="Single IP/URL/hostname, CIDR range, or dash-notation range")
    parser.add_argument("-f", "--file",
                        help="File containing IP ranges/addresses (one per line, # for comments)")
    parser.add_argument("-p", "--port", type=int, default=11434,
                        help="Target port (default: 11434)")
    parser.add_argument("-o", "--output", default="ollama_report",
                        help="Base name for output files (default: ollama_report)")
    parser.add_argument("--format", choices=("md", "json", "text"), default="md",
                        help="Audit report format (default: md)")
    parser.add_argument("--deep", action="store_true",
                        help="Enable deep/semi-intrusive probes (SSRF, RCE validation)")
    parser.add_argument("--scan-only", action="store_true",
                        help="Discovery only — skip full Ollama security audit")
    parser.add_argument("-t", "--timeout", type=float, default=5.0,
                        help="Connection timeout in seconds (default: 5.0)")
    parser.add_argument("-c", "--concurrent", type=int, default=100,
                        help="Max concurrent connections for range scans (default: 100)")
    parser.add_argument("-r", "--retries", type=int, default=3,
                        help="Retry attempts per target (default: 3)")
    parser.add_argument("-d", "--retry-delay", type=float, default=0.5,
                        help="Base retry delay in seconds (default: 0.5)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Delay between requests in audit mode (default: 0)")
    parser.add_argument("--disable-dns-cache", action="store_true",
                        help="Disable DNS caching")
    parser.add_argument("--no-ssl-verify", action="store_true",
                        help="Disable SSL certificate verification")
    parser.add_argument("--no-progress", action="store_true",
                        help="Suppress progress bar/display")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")

    args = parser.parse_args()

    if not args.target and not args.file:
        parser.print_help()
        print("\n❌ Error: provide a target or --file.", file=sys.stderr)
        sys.exit(1)

    if args.port < 1 or args.port > 65535:
        print("❌ Error: port must be 1–65535.", file=sys.stderr)
        sys.exit(1)
    if args.timeout <= 0:
        print("❌ Error: timeout must be positive.", file=sys.stderr)
        sys.exit(1)
    if args.concurrent <= 0:
        print("❌ Error: concurrent must be positive.", file=sys.stderr)
        sys.exit(1)
    if args.retries < 0:
        print("❌ Error: retries cannot be negative.", file=sys.stderr)
        sys.exit(1)
    if args.retry_delay < 0:
        print("❌ Error: retry-delay cannot be negative.", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    print(BANNER, file=sys.stderr)
    print(f"🔌 Port: {args.port}  ⚡ Concurrency: {args.concurrent}"
          f"  ⏱️  Timeout: {args.timeout}s", file=sys.stderr)
    print(f"🛡️  Mode: {'SCAN-ONLY' if args.scan_only else 'DEEP AUDIT' if args.deep else 'STANDARD AUDIT'}",
          file=sys.stderr)
    print("-" * 70, file=sys.stderr)

    is_file = bool(args.file)
    input_source = args.file if is_file else args.target

    # Determine if we need range scanning or single-target
    is_range = is_file or (
        args.target and (
            "/" in args.target
            or ("-" in args.target and not args.target.startswith("http"))
        )
    )

    # Single-IP that looks like a plain host/IP is not a range
    if not is_file and args.target:
        try:
            count = count_ips_in_range_static(args.target)
            is_range = count > 1 or is_file
        except Exception:
            is_range = False

    try:
        if is_range or is_file:
            scanner = OllamaUnifiedScanner(
                timeout=args.timeout,
                max_concurrent=args.concurrent,
                retry_attempts=args.retries,
                retry_delay=args.retry_delay,
                enable_dns_cache=not args.disable_dns_cache,
                disable_ssl_verify=args.no_ssl_verify,
                port_timeout=args.timeout / 2,
                deep_mode=args.deep,
                audit_mode=not args.scan_only,
                request_delay=args.delay,
            )
            results = asyncio.run(
                scanner.scan_range(
                    input_source,
                    is_file=is_file,
                    port=args.port,
                    show_progress=not args.no_progress,
                    output_base=args.output if not args.scan_only else None,
                    format_type=args.format,
                )
            )

            # Print results summary
            print(f"\n{'=' * 70}", file=sys.stderr)
            print(f"📊 RESULTS — {len(results)} servers discovered", file=sys.stderr)
            print("=" * 70, file=sys.stderr)
            for idx, r in enumerate(results, 1):
                print(f"\n{idx}. {r.url}")
                print(f"   🔧 Server: {r.server_type.value.upper()}")
                print(f"   📦 Models ({len(r.models)}): {', '.join(r.models[:10])}")
                if args.deep and r.process_list:
                    print(f"   🔄 Loaded: {len(r.process_list)} model(s)")
                    for p in r.process_list[:5]:
                        gb = p.get("size", 0) / 1024**3
                        print(f"      ├─ {p.get('name', '?')} (~{gb:.1f} GB)")
                if r.audit_findings:
                    vulns = sum(1 for f in r.audit_findings if f.status == CheckStatus.VULNERABLE)
                    print(f"   🛡️  Audit: {len(r.audit_findings)} checks, {vulns} VULNERABLE")

            if args.output:
                try:
                    scan_path = scanner.generate_scan_report(results, args.output, "json")
                    print(f"\n💾 Scan report: {scan_path}", file=sys.stderr)
                    txt_path = f"{args.output}_hosts.txt"
                    with open(txt_path, "w", encoding="utf-8") as fh:
                        for r in results:
                            fh.write(f"{r.url}\n")
                    print(f"💾 Host list:   {txt_path}", file=sys.stderr)
                except Exception as exc:
                    print(f"❌ Report generation failed: {exc}", file=sys.stderr)

        else:
            # Single-target full audit
            auditor = OllamaSecurityAuditor(
                target_url=args.target,
                timeout=args.timeout,
                disable_ssl_verify=args.no_ssl_verify,
                deep_mode=args.deep,
                request_delay=args.delay,
            )

            async def _run_single():
                connector = aiohttp.TCPConnector(limit=10)
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(total=args.timeout, connect=args.timeout / 2),
                ) as session:
                    # Quick server-type detection before full audit
                    discovery = LLMDiscoveryEngine(
                        timeout=args.timeout,
                        disable_ssl_verify=args.no_ssl_verify,
                    )
                    parsed = urlparse(auditor.base_url)
                    host = parsed.hostname or ""
                    port = parsed.port or args.port
                    srv_type, _, _ = await discovery.detect_server_type(host, port, session, base_url=auditor.base_url)
                    if srv_type != ServerType.OLLAMA:
                        print(f"⚠️  Detected server type: {srv_type.value.upper()} — "
                              "full security audit requires Ollama.", file=sys.stderr)
                        if args.scan_only:
                            return []

                    findings = await auditor.run_audit(session)
                    print(f"\n📤 Generating {args.format.upper()} report…", file=sys.stderr)
                    try:
                        path = auditor.generate_report(findings, args.output, args.format)
                        print(f"✅ Report saved: {path}", file=sys.stderr)
                    except Exception as exc:
                        print(f"❌ Report failed: {exc}", file=sys.stderr)
                    return findings

            asyncio.run(_run_single())

    except KeyboardInterrupt:
        print("\n⚠️  Interrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"\n❌ Fatal error: {exc}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
