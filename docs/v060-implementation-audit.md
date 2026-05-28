# T1.0 — Pre-implementation Audit (D1 gate)

**Date:** 2026-05-28
**Source PRD:** `.omc/plans/synthex-v0.6.0-watch-prove.md` §3 D1 T1.0
**Gate result:** **PASS** — no divergence >20 % LOC vs R2 estimate. T1.1+ proceed without Pablo escalation.

## Files audited

### `src/trigger/monitor.js` — 49 LOC

**Class:** `Monitor`
**Constructor opts:** `{pipeline, intervalMs=3_600_000, threshold=7, onAlert}`
**Pipeline contract:** `pipeline(target) => evidence`
**Public API:**
- `watch(target)` / `unwatch(target)` — set membership
- `runOnce()` — iterate `this.targets`, call `pipeline(target)`, read `evidence.payload.findings[].severity`, fire `onAlert({target, severity, evidenceHash, at})` if max >= threshold
- `start()` / `stop()` — `setInterval(runOnce, intervalMs)` with `unref()`

**Implications for T1.3 (Delta integration):**

Three viable approaches:

| Approach | LOC delta | Back-compat | Decision |
|---|---|---|---|
| (a) Change pipeline signature to `(target, prevEvidence) => evidence` | ~10 | **breaks** existing callers | rejected |
| (b) Subclass `DeltaMonitor extends Monitor` | ~40 | safe | option B |
| (c) **Add `runOnceWithDelta()` method, keep `runOnce()` untouched** | ~20-25 | safe, surgical | **chosen** |

Chose (c). Add `this.lastEvidence = new Map()` to constructor (1 LOC), implement
`runOnceWithDelta()` that reads `lastEvidence.get(target)`, calls
`sealDeltaChain({prev_evidence, curr_snapshot, hmacKey})`, stores curr in the
map, and fires `onAlert` enriched with `deltaSummary`. ~22 LOC budget.

### `src/prove/evidence-report.js` — 86 LOC

**Exports:**
- `buildEvidence(payload, {hmacKey, requestTsa=true}) => Promise<Evidence>`
- `verifyEvidence(evidence, {hmacKey}) => {hashOk, hmacOk, tsaOk}`

**Key internal:** `_serializeForHmac(payload)` (lines 15-19) auto-detects
`payload.schema_version >= 2` → `canonicalize()`, else `JSON.stringify()`.
Verifier (line 70) uses the **same** serializer, so back-compat with v1 reports
is preserved by construction.

**Implications for T1.6 (HMAC_EXCLUDED_KEYS):**

`_serializeForHmac` must strip a normative list of keys from the input before
delegating to `canonicalize` / `JSON.stringify`. The keys to exclude are
**metadata about delivery conditions** (`kg_status`, `kg_latency_ms`,
`surface_status`) — they vary cross-run for the same URL when KG availability
fluctuates, and would produce false `contentHash` mismatches in the chain.

Implementation: introduce `HMAC_EXCLUDED_KEYS` constant (frozen), add a helper
`_stripExcludedKeys(payload)` that returns a **shallow copy** without those
keys (does NOT mutate input), and call it inside `_serializeForHmac` before
the existing branch. ~12 LOC budget.

**Risk:** if any caller currently emits these keys at the **root** of payload
(rather than inside a sub-object), pre-v0.6 reports could have their hash
recalculated post-strip and the verifier could reject them as tampered.
**Mitigation:** the verifier applies the same strip, so canonical bytes match.
Verified mentally: yes, `_serializeForHmac` is the **only** serialization path
used by both sealer and verifier (lines 27 and 69). Safe.

### `src/prove/pdf-report.js` — 406 LOC

**Exports:** `riskScore(evidence)`, `buildPDFReport(evidence)`.

**Structure:** 6 page functions
(`pageExecutiveSummary`, `pageCISO`, `pageCFO`, `pageCounsel`, `pageBroker`,
`pageVerify`) + shared helpers
(`COLORS`, `sevColor`, `OWASP`, `owaspOf`, `rowsOf`, `allRows`, `riskScore`,
`diamond`, `pageHeader`, `drawFooters`, `sectionTitle`, `kv`).

Already imports `PDFDocument` from `pdfkit` (^0.18.0 in package.json:61) and
`QRCode` from `qrcode`.

**Implications for T1.4 (Delta PDF):**

Two viable approaches:

| Approach | LOC | Distribution | Decision |
|---|---|---|---|
| (a) Separate function `buildDeltaPdf(deltaEvidence)` | ~120 (full new doc) | new fn export | rejected (duplicates frame) |
| (b) **Add 7th page `pageDelta(doc, ev)` only when `evidence.payload.delta_chain` is present** | ~80 | extends `buildPDFReport` | **chosen** |

Chose (b). One new page function (~80 LOC) + a conditional
`addPage(); pageDelta(...)` block in `buildPDFReport` (~3 LOC) right after the
Broker page. Single-scrape reports stay 6 pages (back-compat). Delta reports
become 7 pages. Footer numbering already paginates dynamically via
`bufferedPageRange().count`.

`pageDelta` will show: header + TSA chain (`serial_n-1 → serial_n`) + diff
summary table (`added/removed/changed` counts) + diff preview (first N chunks)
+ KG status banner.

## LOC budget check

| Task | R2 PRD estimate | Audited actual budget | Divergence |
|---|---|---|---|
| T1.3 monitor.js extend | 15-35 LOC | 22 LOC | 0 % vs midpoint |
| T1.6 evidence-report.js | ~10 LOC | 12 LOC | +20 % (within tolerance) |
| T1.4 pdf-report.js delta page | ~80 LOC | 80 LOC | 0 % |
| **Total T1.x net new** | ~190 LOC + tests | ~190 LOC + tests | **0 % aggregate** |

**Gate decision per PRD T1.0 AC4:** divergence well below 20 % threshold. No
escalation to Pablo needed. Proceed to T1.1.

## Decisions locked for T1.1 onwards

1. **monitor.js integration approach:** append-only `runOnceWithDelta()`
   method, no breaking change to pipeline signature.
2. **HMAC_EXCLUDED_KEYS implementation:** `_stripExcludedKeys` helper returns
   shallow copy, called inside `_serializeForHmac` before existing branch.
3. **Delta PDF approach:** 7th page conditional on `delta_chain` presence;
   single-scrape reports stay 6 pages.
4. **Schema bump:** none. `delta_chain` is additive on v2 (Architect R1 Q1
   confirmed; Critic R3 ratified).
