## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.

## 2026-06-04 - Bounding concurrent execution in guard screening
**Learning:** The pipeline's INJECTION_GUARD stage previously used unbounded Promise.all for evaluating docs, which could cause rate limits or memory exhaustion for large inputs. Replacing it with the existing mapLimit implementation ensures bounded concurrency while reusing existing patterns.
**Action:** Replaced unbounded Promise.all in INJECTION_GUARD loop with mapLimit based on the configured concurrency limit.
