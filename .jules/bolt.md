## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.

## 2026-06-24 - Rate limiting bounded fetch in pipeline.js
**Learning:** unbounded `Promise.all` in `guardScreenImpl` mapped over `safe1` without constraints. Replaced it with the already existing `mapLimit` and `concurrency` argument for safer chunked concurrent processing, honoring the existing bounds mechanism.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()` and prefer bounded loops where available.
