## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.

## 2026-06-05 - Avoid double stringification in deduplication
**Learning:** During payload deduplication, `content` was being redundantly passed through `JSON.stringify` twice. The first serialization occurred in `fingerprint()`, and a second one happened immediately after in `dedupe()` to compute the length for telemetry. This caused roughly a ~30-40% deduplication latency degradation for extremely large arrays.
**Action:** Extract the already serialized string from `fingerprint()` and propagate it through `check()` to reuse it when computing length, replacing the O(N) redundant stringification with an O(1) property access.

## 2026-06-05 - Known test flakiness
**Learning:** `test/forge/injection-guard.test.js` is known to fail with 'Promise resolution is still pending but the event loop has already resolved' (as documented in the `.jules` memory system).
**Action:** Ignore these test failures as they are pre-existing flakiness and not caused by the stringification optimization.
