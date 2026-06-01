## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.

## 2026-06-01 - Avoiding unbounded concurrency in AI/ML guard limits
**Learning:** Found an unbounded `Promise.all()` mapping over L2 injection guard processing. Unbounded concurrency when hitting external AI guard API limits is a major bottleneck/risk as it can cause sudden 429 rate limit responses or queue saturation.
**Action:** Replace unbounded concurrency mappings (like `Promise.all`) with bounded concurrency primitives (like `mapLimit`) when making AI/ML calls to adhere to platform rate limits.
