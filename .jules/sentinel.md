## 2026-07-28 - Self-DoS & Out of Memory (OOM) via Unbounded Binary Downloads in Scanner Probes
**Vulnerability:** The asynchronous `_safe_request` helper of the security auditing tool unconditionally downloaded and parsed the entire HTTP response body via `await response.json()`. When probing the model weight exfiltration endpoint `/api/blobs/{digest}` of a vulnerable target, this led to a severe Self-DoS / OOM vulnerability on the auditor's own machine since LLM model weights are multi-gigabyte binary blobs.
**Learning:** This existed because the helper lacked a way to specify whether the response body should be read or ignored, and did not check `Content-Type` headers or size limits before calling `response.json()`.
**Prevention:** Always implement a `read_body` option or size limits in core request handlers, and set `read_body=False` for any status-only checks where the response body is not required for processing.

## 2026-07-29 - Self-DoS & Out of Memory (OOM) via Unbounded IP Range Expansion
**Vulnerability:** The static IP range validation function `validate_ip_range_static` fully expanded CIDR subnets and hyphenated IP ranges into in-memory lists of string objects without an upper limit. If a user provided a large target subnet (e.g., /8 or /16) or vast hyphen-separated IP range, it would cause massive memory allocation, leading to an immediate Out-of-Memory (OOM) crash or hanging the application.
**Learning:** This existed because the IP range scanner lacked defensive input size bounds on user-controlled inputs during the range expansion phase.
**Prevention:** Enforce a strict threshold (e.g., `MAX_IP_RANGE_LIMIT = 65536`) on the number of hosts/addresses parsed during expansion, and raise a descriptive error to fail securely before allocating memory.
