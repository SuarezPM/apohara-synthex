# Synthex × brightdata-mcp — Upstream Contribution

**Author:** Pablo M. Suárez (@SuarezPM)
**PR:** https://github.com/brightdata/brightdata-mcp/pull/140 — **OPEN, mergeable** (reacted to by a Bright Data maintainer, `meirk-brd`)
**Branch:** `feat/dedup-layer` · **Diff:** +581 / −36 across 5 files · **Tests:** 37 (3 new files)
**Prior art:** Context_Forge INV-CF-1 / INV-15 — [Zenodo DOI 10.5281/zenodo.20277875](https://doi.org/10.5281/zenodo.20277875)

> *We didn't just use Bright Data — we improved it.* This is a real, open, branding-free
> contribution to the official `brightdata-mcp`, born from building Synthex on top of it.

---

## What it adds

A **deduplication layer** for `scrape_batch` and **field filtering** for `scrape_batch` +
`search_engine_batch`. When an agent batch-scrapes several pages from the same domain, the
shared nav/header/footer was returned N times — wasting tokens. The dedup layer fingerprints
content (SHA-256) and flags duplicates; field filtering returns only the keys the agent asked
for. **Backward compatible** — defaults preserve the original behavior.

## Changes

- **`context_cache.js`** (new): `ContextCache` (SHA-256 content fingerprint dedup), `filterFields`
  (with prototype-pollution guard), `buildBatchMetrics`.
- **`server.js`**: `scrape_batch` gains `deduplicate` / `include_metrics` / `fields` / `format`;
  `search_engine_batch` gains `fields` (applied within `result.organic`).

## Tests (37 new, verifiable with `npm test`)

| File | Tests | Covers |
|---|---|---|
| `test/test_context_cache.js` | 9 | dedup core: same content / different URL flagged, distinct content not flagged, metrics |
| `test/test_dedup_edge_cases.js` | 8 | empty/single-char/boundary/very-long content, null handling |
| `test/test_filter_fields.js` | 20 | field filtering edge cases (nested, numeric, missing, order, special chars) |

*(Upstream `search-utils.test.js` and `server-health.test.js` are unchanged.)*

## Honesty notes

- This dedup is **pure-JS SHA-256, inspired by** Context_Forge's INV-CF-1 invariant (*no content
  block appears twice in batch output*). It does **not** import Context_Forge (which is Python) —
  the idea is ported, not the code.
- A first attempt (**PR #139**) bundled project-specific branding ("ContextForge"/"NEXUS"); it was
  closed. **#140** is the clean, branding-free version that stands on its own.
- **Bug fixed:** the initial fingerprint (`prefix + length`) collided when two pages shared a
  prefix and had equal length but different bodies → switched to full-content SHA-256.

## Files changed

```
context_cache.js
server.js
test/test_context_cache.js
test/test_dedup_edge_cases.js
test/test_filter_fields.js
```
