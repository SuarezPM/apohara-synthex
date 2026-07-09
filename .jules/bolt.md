## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-05-30 - Array.find in nested loops bottleneck
**Learning:** Using `Array.prototype.find()` inside loops for cross-referencing collections creates an $O(N^2)$ algorithmic bottleneck, adding CPU overhead for large document payloads during pipeline execution.
**Action:** When performing cross-references between collections, pre-compute an $O(1)$ lookup structure like a `Map`. When doing this, manually iterate the array to preserve `Array.prototype.find()` first-match semantics on arrays that might have duplicate keys.
