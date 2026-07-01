## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-07-01 - Eliminate O(N²) array lookup in pipeline
**Learning:** In `src/pipeline.js`, extracting L1 REVIEW rows to L3 used a nested array lookup (`safe.find`) inside a loop over reviewed items, causing an O(N²) algorithmic bottleneck for multi-document payloads. This creates unnecessary CPU overhead and can cause event-loop blocking when handling a large influx of documents.
**Action:** When performing cross-references between collections (like matching URL references across arrays), pre-compute an O(1) lookup structure (like a `Map`) to reduce algorithmic complexity to O(N).
