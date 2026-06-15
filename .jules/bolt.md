## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-06-15 - Replaced unbounded Promise.all in L2 Injection Guard network calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` for the L2 Injection Guard network calls is a fast fix but could hit rate limits or cause OOM errors if input sizes are large.
**Action:** Replaced the unbounded `Promise.all()` with the existing `mapLimit()` utility to cap concurrent processing. Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
