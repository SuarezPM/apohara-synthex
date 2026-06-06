## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-06-06 - Injection Guard Concurrency Bottleneck
**Learning:** The pipeline's Layer 2 (`INJECTION_GUARD`) used an unbounded `Promise.all` which could hit rate limits and capacity constraints for large multi-document payloads, as documented in earlier parallelization analysis.
**Action:** Always replace unbounded `Promise.all` with the existing `mapLimit(items, concurrency, fn)` utility function when processing arrays of external/untrusted payload items in the forge or classification layers.
