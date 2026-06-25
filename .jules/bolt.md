## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-06-25 - Bounding concurrency for Injection Guard
**Learning:** Using unbounded `Promise.all` for parallel operations on potentially large arrays (like `safe1` in the `FORGE` stage) can cause flaky test failures ("Promise resolution is still pending but the event loop has already resolved") when AbortSignals are involved, and risks hitting API rate limits or memory exhaustion in production.
**Action:** Replace `Promise.all` with the codebase's existing `mapLimit` pattern to enforce a bounded concurrency cap (`concurrency`) for all batch API calls or parallel processing steps.
