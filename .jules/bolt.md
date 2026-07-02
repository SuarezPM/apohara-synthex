## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-05-30 - O(1) Lookups over O(N^2) Array Searches
**Learning:** When correlating large lists of items (like cross-referencing URLs between arrays in `src/pipeline.js`), `Array.find` inside a loop creates an O(N²) algorithmic bottleneck. For data pipelines dealing with many documents, this can severely degrade performance.
**Action:** Always pre-compute an O(1) lookup structure (like a `Map` or a `Set`) when cross-referencing collections to avoid O(N²) overhead.
