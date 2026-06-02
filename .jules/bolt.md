## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-06-02 - Bounding injection-guard concurrency
**Learning:** Found an unbounded `Promise.all` in the `injection-guard` step during the `FORGE` stage which processes documents. Bounding it using `mapLimit(..., concurrency, ...)` aligns it with other pipeline steps and protects downstream services from spike loads.
**Action:** Replaced `Promise.all` with `mapLimit` in `src/pipeline.js`.
