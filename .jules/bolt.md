## 2026-07-28 - [Target Audit Concurrency]
**Learning:** Sequential async executions of independent probes (such as WAF detection, weight exfil, streaming DoS, modelfile RCE, metadata SSRF, token brute-forcing, and prompt injection leakage) degrade audit times linearly. Batching them with `asyncio.gather` reduces the overall latency from several seconds to the duration of the longest request.
**Action:** Replace the sequential await/append patterns with `asyncio.gather` for independent probe endpoints in `OllamaSecurityAuditor.run_audit`.

## 2026-07-29 - [External API Query Parallelism and Range Scanner Concurrency Control]
**Learning:** Performing multiple sequential HTTP requests to independent threat intelligence sources (GitHub, NVD, ExploitDB) delays the initialization of targets. Concurrently, failing to acquire semaphores during range scans results in unbounded concurrent socket allocation, leading to "Too many open files" errors and high latency.
**Action:** Always fetch external, non-dependent metadata concurrently using `asyncio.gather(..., return_exceptions=True)`. Additionally, guarantee semaphore acquisition with `async with` inside worker functions like `scan_target`.

## 2026-07-30 - [Ollama Metadata Caching Limitations]
**Learning:** Caching `/api/ps` in Ollama introduces dynamic stale-state bugs because Ollama automatically loads and unloads models dynamically based on keep-alive parameters and query activity. In contrast, static metadata endpoints such as `/api/version` and `/api/tags` remain completely unchanged during an audit and can be safely cached to avoid duplicate network roundtrips.
**Action:** Exclude active process tracking (`/api/ps`) from metadata cache eligibility; limit single-audit HTTP GET caching strictly to static and semi-static API resources (`/api/version`, `/api/tags`).

## 2026-08-05 - [Global Dynamic Advisory Caching and Semantic Version Tuple Memoization]
**Learning:** In a multi-target or network range scan, querying remote dynamic advisory threat intelligence APIs (GitHub, NVD, ExploitDB) sequentially or even concurrently for every individual host introduces high network overhead and rate limiting risks. Globally caching threat intelligence results via a class-level cache protected by a lazy-initialized async Lock completely eliminates repetitive external network roundtrips. Additionally, since the same semantic versions are parsed and matched repeatedly across CVE registries, memoizing `_parse_version_tuple` via `functools.lru_cache` eliminates redundant string splitting and regular expression parsing, reducing processing time for version checks.
**Action:** Implement a lazy-initialized global Lock (`_global_advisories_lock`) and class-level storage (`_global_advisories_cache`) inside `OllamaSecurityAuditor._fetch_dynamic_advisories`, and decorate `_parse_version_tuple` with `functools.lru_cache(maxsize=128)`.
