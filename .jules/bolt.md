## 2026-07-31 - [Semantic Version Memoization]
**Learning:** Repetitive parsing of semantic version strings in the vulnerability range checker for numerous static and dynamic CVE rules introduces CPU bottleneck, involving regex compilation, string manipulation, and tuple parsing overhead on every check loop execution. Applying a memoization cache to the parser optimizes comparison latency.
**Action:** Decorate `_parse_version_tuple` with `functools.lru_cache(maxsize=128)` to memoize parsed semantic version tuples.

## 2026-07-28 - [Target Audit Concurrency]
**Learning:** Sequential async executions of independent probes (such as WAF detection, weight exfil, streaming DoS, modelfile RCE, metadata SSRF, token brute-forcing, and prompt injection leakage) degrade audit times linearly. Batching them with `asyncio.gather` reduces the overall latency from several seconds to the duration of the longest request.
**Action:** Replace the sequential await/append patterns with `asyncio.gather` for independent probe endpoints in `OllamaSecurityAuditor.run_audit`.

## 2026-07-29 - [External API Query Parallelism and Range Scanner Concurrency Control]
**Learning:** Performing multiple sequential HTTP requests to independent threat intelligence sources (GitHub, NVD, ExploitDB) delays the initialization of targets. Concurrently, failing to acquire semaphores during range scans results in unbounded concurrent socket allocation, leading to "Too many open files" errors and high latency.
**Action:** Always fetch external, non-dependent metadata concurrently using `asyncio.gather(..., return_exceptions=True)`. Additionally, guarantee semaphore acquisition with `async with` inside worker functions like `scan_target`.

## 2026-07-30 - [Ollama Metadata Caching Limitations]
**Learning:** Caching `/api/ps` in Ollama introduces dynamic stale-state bugs because Ollama automatically loads and unloads models dynamically based on keep-alive parameters and query activity. In contrast, static metadata endpoints such as `/api/version` and `/api/tags` remain completely unchanged during an audit and can be safely cached to avoid duplicate network roundtrips.
**Action:** Exclude active process tracking (`/api/ps`) from metadata cache eligibility; limit single-audit HTTP GET caching strictly to static and semi-static API resources (`/api/version`, `/api/tags`).

## 2026-07-31 - [Global Threat Intelligence Cache and Lock for Multi-Target Range Scans]
**Learning:** Querying external threat intelligence sources (such as GitHub, NVD, and ExploitDB APIs) during multi-target range scans causes redundant network roundtrips, vulnerability to rate-limiting or blocking, and unnecessary scan latency. Reusing these static/slow-to-change records across multiple auditor instances via a thread/coroutine-safe global cache and a lazy-initialized asyncio Lock completely eliminates repetitive external network calls and avoids asyncio event loop context runtime errors.
**Action:** Implement a global advisory cache with a lazy-initialized asyncio Lock that gets evaluated dynamically under the active event loop during initialization, and ensure to return a deep or shallow copy of the cached lists to prevent cross-instance mutation side effects.
