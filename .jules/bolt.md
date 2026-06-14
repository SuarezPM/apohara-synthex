## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.

## 2026-06-14 - Bound Injection-Guard Pipeline Concurrency
**Learning:** In `src/pipeline.js` `guardScreenImpl` api calls were called via unbounded `Promise.all`, which may cause rate limit drops for many payload. Bounded limits via `mapLimit` works better.
**Action:** Use bounded concurrency for APIs and check tests under correct node versions (v24 here).
