## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.

## 2024-07-06 - Refactored O(N) Array .find() to Map lookup
**Learning:** Refactoring an O(N) array `.find()` operation inside a loop into an O(1) `Map` lookup can eliminate O(N²) algorithmic bottlenecks. When doing this, be cautious of arrays with duplicate keys: `.find()` returns the first match, so the `Map` must be populated manually with `if (!map.has(obj.key)) map.set(obj.key, obj)` to retain identical semantics.
**Action:** When performing cross-references between collections (like matching URL references across arrays), pre-compute an O(1) lookup structure like a `Map` to avoid O(N²) algorithmic bottlenecks and reduce CPU overhead for large payloads, ensuring duplicate key edge cases are handled correctly.
