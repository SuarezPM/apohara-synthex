## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-06-22 - Bounding Promise.all in L2 Guard Screen
**Learning:** Found an unbounded `Promise.all` in `src/pipeline.js` within the injection-guard branch which could lead to API rate limits or memory exhaustion when processing many documents. The app already defined a useful `mapLimit` utility and an injected `concurrency` setting used by the fetch and classify stages. The reviewer incorrectly thought `mapLimit` and `concurrency` were missing.
**Action:** Always prefer bounded concurrency (e.g. `mapLimit`) over unbounded `Promise.all` when making network calls for arrays of items (like documents). Re-using existing local context limits reduces the chance of bringing the pipeline down under load.
