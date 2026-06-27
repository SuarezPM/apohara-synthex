## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.

## 2026-06-27 - Rate-limited Concurrency Optimization
**Learning:** The `injection-guard` layer used an unbounded `Promise.all()` for its document screening loop, risking rate limit blocks when processing large batches of scraped content.
**Action:** Use the existing `mapLimit()` function instead of `Promise.all()` for operations hitting external APIs, explicitly passing the bound `concurrency` value from the environment to cap the in-flight requests.
