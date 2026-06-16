## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.

## 2026-06-16 - Redundant Regex Evaluation in Grounding
**Learning:** `extractFigures` was called twice in `ground()` for the exact same content when the source document size was under the verification window limit (8000 chars), which applies to the majority of web scrapes. This caused a 100% redundant regex penalty.
**Action:** Always verify if multi-pass logic (like window vs source checks) processes identical inputs in the common case, and reuse the computed structure (e.g. Set) if boundaries match.
