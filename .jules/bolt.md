## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-05-29 - Bounded concurrency for Injection Guard
**Learning:** The pipeline's Layer-2 injection guard `guardScreenImpl` used an unbounded `Promise.all` on documents. Given that the fetcher could return many documents, an unbounded concurrency here could lead to sudden rate limiting or out-of-memory spikes.
**Action:** Always replace unbounded `Promise.all` processing of documents with `mapLimit` using `SYNTHEX_CONCURRENCY`, matching the pattern used in the FETCH and CLASSIFY stages.
