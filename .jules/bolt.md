## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.

## 2026-05-30 - O(N²) array find() in pipeline cross-references
**Learning:** Using `Array.prototype.find()` inside a loop to cross-reference URLs across collections in the pipeline creates an O(N²) algorithmic bottleneck, which can severely increase CPU overhead for large payloads.
**Action:** Pre-compute an O(1) lookup structure like a `Map` before iterating. Be careful to iterate manually and only `.set()` if the key doesn't exist to preserve the first-match semantics of `.find()`.
