## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-06-10 - Bounding concurrency for Injection Guard
**Learning:** The pipeline previously fetched `guardScreenImpl` responses sequentially or bounded via `mapLimit` in most places, but the `injection-guard` layer inside FORGE was using unbounded `Promise.all()`. This presented a risk of hitting API rate limits or excessive concurrent requests during bulk ingests.
**Action:** Use `mapLimit` with the existing `concurrency` configuration instead of `Promise.all()` when mapping over potentially large sets of documents that need to hit external APIs/guards, ensuring all processing loops are uniformly rate-limited.
