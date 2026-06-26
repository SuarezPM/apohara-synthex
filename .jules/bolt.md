## 2026-05-29 - Parallelizing API calls
**Learning:** The pipeline fetches and classifies data sequentially, which can be a bottleneck for multi-target or multi-document payloads. Using unbounded `Promise.all()` is a fast fix but could hit rate limits if input sizes are large. Future optimizations should consider chunked concurrent processing.
**Action:** Always check the input size bounds before replacing sequential async loops with unbounded `Promise.all()`.
## 2026-05-31 - Injection Guard API Rate Limits
**Learning:** Found an unbounded `Promise.all()` used for the Layer-2 `injection-guard` AI screening step `guardScreenImpl`. This creates a burst of concurrent API calls when testing large corpuses or large payloads which can hit API rate limits or timeout limits on the endpoint.
**Action:** Applied the codebase's existing `mapLimit` concurrency helper to bound concurrent requests during the `guardEnabled` parallelization phase, respecting the `SYNTHEX_CONCURRENCY` limit.
