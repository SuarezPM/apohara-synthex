## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-07-10 - O(N²) array find with Map lookup in URL cross-referencing
**Learning:** In the pipeline (`src/pipeline.js`), cross-referencing URL collections during L3 escalation checks used `Array.prototype.find()` in a loop over large arrays. This resulted in an O(N²) algorithmic bottleneck and CPU overhead when dealing with numerous documents.
**Action:** When performing cross-references between collections (like matching URL references), pre-compute an O(1) lookup structure like a `Map`. Ensure to iterate the array manually checking for existence (`!map.has()`) before setting to retain the original `.find()` semantics (which returns the first match, avoiding overriding elements when duplicate keys exist).
