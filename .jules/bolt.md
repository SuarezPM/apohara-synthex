## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-05-31 - Bounded concurrency for L2 Hosted Guards
**Learning:** The `runPipeline` function used unbounded `Promise.all` for Layer 2 hosted guards screening (`guardScreenImpl`), which could hit API rate limits or memory constraints when processing many scraped documents simultaneously. While `mapLimit` is used effectively in FETCH and CLASSIFY stages, it was missed in the FORGE stage.
**Action:** Use `mapLimit` with the existing `concurrency` setting instead of `Promise.all` to batch array operations targeting remote services to ensure consistent, stable throughput for large input payloads.
