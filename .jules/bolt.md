## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.

## 2025-07-08 - O(N^2) cross-reference bottlenecks
**Learning:** Using `Array.prototype.find()` inside a loop causes an O(N²) algorithmic bottleneck, which can be expensive for large arrays.
**Action:** Replace `Array.prototype.find()` inside loops with an O(1) `Map` lookup pre-computed outside the loop. To preserve original `find()` semantics (which returns the first match), explicitly check if the key is absent before setting it (`if (!map.has(key)) map.set(key, val)`).
