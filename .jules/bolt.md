## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2024-05-30 - Re-hashing of content in decision payload
**Learning:** The `sha256` hash of a document's content is pre-calculated accurately during the `dedupe` step (stored as `contentHash`), making subsequent hash recalculations in `pipeline.js` when mapping decision objects redundant.
**Action:** When working with pipeline items post-deduplication, prefer `d.contentHash` over recalculating `sha256(String(d.content ?? "")).toString("hex")` to save CPU cycles.
