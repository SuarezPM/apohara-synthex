## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-06-11 - Bounding concurrency for L2 external guard layer
**Learning:** The pipeline fetches and classifies data with bounded concurrency, but processing the Layer 2 injection guard (L2) with external provider was previously using an unbounded `Promise.all()`. Using unbounded `Promise.all()` is a fast fix but could hit rate limits or cause memory spikes if input sizes are large, which was documented as a learning in this journal on 2026-05-29.
**Action:** Bounded concurrency with `mapLimit` and `concurrency` variables has now been extended to cover the L2 guard (`guardEnabled` block) to ensure multi-target or multi-document payloads are processed safely.
