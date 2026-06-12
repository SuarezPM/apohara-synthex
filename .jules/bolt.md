## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-06-12 - Bounded Concurrency for External APIs
**Learning:** Using unbounded `Promise.all` for external API calls within a sequential pipeline is a bottleneck or can cause rate limiting if input sizes are large.
**Action:** Use `mapLimit` with the configured `SYNTHEX_CONCURRENCY` to ensure bounded concurrency instead of unbounded `Promise.all` calls, matching the existing architectural pattern.
