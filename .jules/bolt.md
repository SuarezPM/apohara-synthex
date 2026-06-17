## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-06-17 - Parallelizing defaultFetch using mapLimit
**Learning:** Sequential `for...of` loops that hit external services (e.g., BrightData URL scraping in `defaultFetch`) introduce high latency. The codebase already provides `mapLimit(items, concurrency, fn)` precisely to bound concurrency while parallelizing operations.
**Action:** When replacing sequential IO with concurrency, use `mapLimit` instead of unbound `Promise.all` to avoid blowing rate limits or spiking memory.
