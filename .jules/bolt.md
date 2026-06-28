## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.

## 2026-06-28 - Grounding verification redundancy
**Learning:** The deterministic grounding verifier runs `extractFigures` (which uses a heavy global Regex) twice: once for the seen window and once for the full document. Because many documents are shorter than the window limit (8000 chars), the two strings are often identical, resulting in a 100% redundant parse.
**Action:** When working with slice-based boundary checks, explicitly test if the slice equals the full length to reuse the parsed output and save cycles.
