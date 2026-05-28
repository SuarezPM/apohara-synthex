# Synthex Delta Engine — Kiro Spec

> **Spec format:** Kiro-native (`.kiro/specs/`).
> **Status:** Implementation in progress (v0.6.0 "Watch & Prove").
> **Source PRD:** `.omc/plans/synthex-v0.6.0-watch-prove.md` (R3 consensus).
> **Owner:** Pablo M. Suárez (@SuarezPM) · MIT.

## What Synthex is

Synthex turns Bright Data scrapes into **signed evidence**: every fetch is
classified (4 lenses in parallel via AI/ML API), sealed with HMAC-SHA256 + RFC
3161 timestamp from DigiCert, and exposed as a downloadable PDF Evidence
Report. It ships as an npm package (`@apohara/synthex`) and as an MCP server.

## The gap Delta Engine closes

v0.5.0 processed each URL in isolation. When the same agent scrapes the same
URL again 24h later, Synthex had no way to say "this changed" with
cryptographic proof. Triggerware (partner) detects deltas at the data layer
but does not sign them. changedetection.io diffs URLs without timestamping.
sigstore signs without scraping or diffing. **No open-source tool combines
scrape + diff + HMAC + RFC 3161 + KG in one verifiable chain.**

Delta Engine fills that intersection.

## API contract (v0.6.0)

```js
// src/delta/index.js — exported surface
normalizeContent(html: string): string
  // Strip volatile noise (scripts, styles, csrf, inline timestamps, footer counters).
  // Determinism property: forall stable_html, normalize(html) is byte-equal across runs.

hashSnapshot(content: string): string
  // sha256 hex (64 chars). Pure. Idempotent across runs.

diffSnapshots(prev: Snapshot | null, curr: Snapshot): Diff
  // Returns {added:[], removed:[], changed:[]}.
  // Granularity: chunks of <p>, <li>, <h*> (NOT char-level).
  // Cold start: prev=null returns {added: all chunks, removed: [], changed: []}.

sealDeltaChain({prev_evidence, curr_snapshot, hmacKey, tsaUrl?}): Promise<DeltaEvidence>
  // Reuses src/prove/evidence-report.js buildEvidence(),
  // adds payload field delta_chain (additive, schema v2 stays compatible).
  // previous_tsa_serial: string|null (null marker for cold start).
  // current_tsa_serial: always a string (this run's TSA serial).
```

## delta_chain payload shape (schema v2.1, additive — no breaking change)

```json
{
  "schema_version": 2,
  "contentHash": "<existing>",
  "decisions": [...existing...],
  "tokens_saved": {...existing...},
  "delta_chain": {
    "previous_tsa_serial": "0x...." | null,
    "current_tsa_serial": "0x....",
    "diff_summary": { "added": 4, "removed": 1, "changed": 2 },
    "kg_status": "ingested" | "skipped" | "unreachable",
    "kg_skip_reason": "pii_filter" | "cold_path_disabled" | null
  },
  "seal": { "hmac": "...", "rfc3161Tsa": {...} }
}
```

The `delta_chain` key is **optional**. Reports without delta (single-scrape
mode v0.5.0 behavior) omit it entirely. Verifiers `bin/decode-evidence.js`
auto-detect via `payload.delta_chain` presence.

## HMAC determinism guarantee (T1.6)

`_serializeForHmac()` MUST exclude `HMAC_EXCLUDED_KEYS = [kg_status,
kg_latency_ms, surface_status]` from the canonicalized bytestring. Reason:
two runs over the same URL with different KG availability (run A: Cognee
3.0s OK, run B: Cognee 3.2s timeout) must produce the same `contentHash` —
otherwise the chain reports a fake change.

## Hot path / cold path split

| Layer | Operations | Latency budget |
|---|---|---|
| **Hot** (per scrape, blocking) | normalize → hash → diff → HMAC → TSA roundtrip | < 1500ms p95 e2e (SC-3b), < 200ms p95 deterministic-only (SC-3) |
| **Cold** (async, post-hot) | `cogneeClient.remember(payload)` if `COGNEE_LIVE=1` | best-effort, 3s timeout, `--no-kg` fallback |

Cognee MCP cold start (12-25s for `uv` + MiniMax + lancedb + kuzu) NEVER
blocks the hot path. Operators run `scripts/warmup-cognee.mjs` before demos.

## Anti-claims (PRD principle #1: honest verifiable)

- ❌ "First in world": NEVER. The most we can say is "no open-source
  combination of [scrape + diff + HMAC + RFC 3161 + KG] found in directed
  search at $(date 2026-05-28). See docs/PRIOR_ART.md for reproducible
  queries."
- ❌ "Replaces Triggerware": NEVER. Synthex is the **cryptographic proof
  layer above** Triggerware's delta detection — they complement.
- ❌ "Tamper-proof": prefer "tamper-evident" (chain reveals tampering,
  doesn't prevent it).

## References

- PRD: `.omc/plans/synthex-v0.6.0-watch-prove.md` (consensus reached R3).
- Papers cited: arXiv 2506.13246, 2511.17118, 2505.24478, 2509.03821.
- Sibling code: `apohara-aegis` (78 DJL rules ported in v4 to
  `src/forge/djl.js`).
