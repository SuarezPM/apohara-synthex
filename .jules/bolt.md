## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.

## 2026-06-21 - Bounded concurrency for Injection Guard
**Learning:** The Layer 2 Injection Guard execution used unbounded `Promise.all()` which violates the codebase's concurrency limits (using `mapLimit` and `SYNTHEX_CONCURRENCY`). This could exhaust rate limits or capacity for multi-document payloads.
**Action:** Always use `mapLimit` rather than unbounded `Promise.all()` when parallelizing API calls across unbounded inputs to ensure bounded concurrency constraints are maintained.
