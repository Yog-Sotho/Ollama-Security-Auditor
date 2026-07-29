## 2026-07-28 - [Target Audit Concurrency]
**Learning:** Sequential async executions of independent probes (such as WAF detection, weight exfil, streaming DoS, modelfile RCE, metadata SSRF, token brute-forcing, and prompt injection leakage) degrade audit times linearly. Batching them with `asyncio.gather` reduces the overall latency from several seconds to the duration of the longest request.
**Action:** Replace the sequential await/append patterns with `asyncio.gather` for independent probe endpoints in `OllamaSecurityAuditor.run_audit`.

## 2026-07-29 - [External API Query Parallelism and Range Scanner Concurrency Control]
**Learning:** Performing multiple sequential HTTP requests to independent threat intelligence sources (GitHub, NVD, ExploitDB) delays the initialization of targets. Concurrently, failing to acquire semaphores during range scans results in unbounded concurrent socket allocation, leading to "Too many open files" errors and high latency.
**Action:** Always fetch external, non-dependent metadata concurrently using `asyncio.gather(..., return_exceptions=True)`. Additionally, guarantee semaphore acquisition with `async with` inside worker functions like `scan_target`.
