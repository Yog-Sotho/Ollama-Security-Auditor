## 2026-07-28 - [Target Audit Concurrency]
**Learning:** Sequential async executions of independent probes (such as WAF detection, weight exfil, streaming DoS, modelfile RCE, metadata SSRF, token brute-forcing, and prompt injection leakage) degrade audit times linearly. Batching them with `asyncio.gather` reduces the overall latency from several seconds to the duration of the longest request.
**Action:** Replace the sequential await/append patterns with `asyncio.gather` for independent probe endpoints in `OllamaSecurityAuditor.run_audit`.

## 2026-07-29 - [External API Query Parallelism and Range Scanner Concurrency Control]
**Learning:** Performing multiple sequential HTTP requests to independent threat intelligence sources (GitHub, NVD, ExploitDB) delays the initialization of targets. Concurrently, failing to acquire semaphores during range scans results in unbounded concurrent socket allocation, leading to "Too many open files" errors and high latency.
**Action:** Always fetch external, non-dependent metadata concurrently using `asyncio.gather(..., return_exceptions=True)`. Additionally, guarantee semaphore acquisition with `async with` inside worker functions like `scan_target`.

## 2026-07-30 - [Ollama Metadata Caching Limitations]
**Learning:** Caching `/api/ps` in Ollama introduces dynamic stale-state bugs because Ollama automatically loads and unloads models dynamically based on keep-alive parameters and query activity. In contrast, static metadata endpoints such as `/api/version` and `/api/tags` remain completely unchanged during an audit and can be safely cached to avoid duplicate network roundtrips.
**Action:** Exclude active process tracking (`/api/ps`) from metadata cache eligibility; limit single-audit HTTP GET caching strictly to static and semi-static API resources (`/api/version`, `/api/tags`).

## 2026-07-31 - [Threat Intel Global Caching and Semantic Version Tuple Memoization]
**Learning:** Repeatedly fetching external dynamic advisories (from GitHub, NVD, ExploitDB) across multiple auditor instances during range scans results in severe network latency and API rate limiting. Coalescing external requests into a globally shared threat intel cache, protected by a lazy-initialized asyncio.Lock, guarantees dynamic data is only loaded once. Additionally, repeatedly parsing raw version strings into semantic tuples introduces avoidable CPU overhead, which can be entirely mitigated by memoizing version parsing via functools.lru_cache.
**Action:** Implement module-level global caching and an async lock for external advisory fetches, and decorate `_parse_version_tuple` with `@lru_cache`.
