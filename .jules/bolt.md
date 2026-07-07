## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.

## 2026-07-07 - Refactoring Array.find() inside loops with Map lookups
**Learning:** Refactoring an O(N) array `.find()` operation into an O(1) `Map` lookup inside a loop is a great performance optimization, but the standard `new Map(array.map(obj => [obj.key, obj]))` retains the *last* match for a given key, whereas `.find()` returns the *first* match.
**Action:** Always verify the semantics of duplicate keys before replacing `.find()` with a Map lookup. If first-match semantics are required, manually iterate the array and only `set()` if the Map doesn't already have the key.
