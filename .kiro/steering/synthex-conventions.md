# Synthex Repo Conventions — Kiro Steering

> Steering doc for Kiro agents working on `@apohara/synthex`.
> If something here conflicts with the actual code, the code wins; please
> open a PR updating this file.

## Language + runtime

- **JavaScript only.** No TypeScript, no compile step.
- **ESM only** (`"type": "module"` in package.json). No CommonJS imports.
- **Node 24 LTS** (Krypton). `engines.node = ">=24"` in package.json.
- **Zero runtime deps** in the deterministic pre-LLM layer (regex + `node:crypto`).
  LLM-mediated paths use `fetch` (built-in) — no axios, no superagent.

## Test stack

- `node --test` (built-in). No jest, mocha, vitest.
- Tests live in `test/<area>/<thing>.test.js`. Mirror src layout.
- Integration tests use stub HTTP servers (`http.createServer`), NOT
  external services like httpbin (unstable).
- Network tests are opt-in via env (`SYNTHEX_NETWORK_TESTS=1`); never make
  the suite assume network.
- Suite must be < 1s wall clock for the unit + integration block.

## Schema versioning

- Evidence payload has `schema_version` (currently `2`).
- **Append-only**: new fields are additive (optional, default-undefined),
  never break verifiers of older payloads.
- `_serializeForHmac()` auto-detects schema_version and routes to
  `canonicalize()` (v2+, RFC 8785 JCS) or `JSON.stringify()` (v1 legacy).
- Bump only when forcing a root-key change incompatible with v2 readers.
- `HMAC_EXCLUDED_KEYS` is normative: `kg_status`, `kg_latency_ms`,
  `surface_status` are metadata, NOT part of the hashed payload.

## Honest framing (load-bearing)

Synthex's positioning depends on not over-claiming. Forbidden phrases:

- "world's first" / "novel" / "first in world" → use "no combination found
  in directed search".
- "replaces Triggerware/changedetection.io" → use "extends with proof
  layer".
- "tamper-proof" → use "tamper-evident".
- "100% blocking" (for pre-LLM rules) → use measured number with the
  fixture corpus cited.

## Commit style

- Conventional commits prefix: `feat(area):`, `fix(area):`, `chore(...)`,
  `docs(...)`, `test(...)`, `ci(...)`, `release(...)`.
- Body: WHY > WHAT. Reference PRD task IDs (T0.x, T1.x) for v0.6.0 work.
- One commit per task ID; do not bundle unrelated changes.
- Footer must include `Co-Authored-By: Claude Opus 4.7 (1M context)`
  when generated through Claude orchestration.

## Files to leave alone unless asked

- `src/guard.js` — SSRF + rate-limit guard for the public endpoint, NOT
  a pre-pipeline hook. Touching it accidentally breaks production.
- `src/forge/djl.js` — 78 rules ported from `apohara-aegis`. Preserve
  rule IDs (`DJL-PI-001`, etc.) for bidirectional traceability.
- `.github/workflows/release-slsa.yml` — SLSA L3 + npm provenance is wired
  end-to-end; any change risks the supply chain claim.

## Local dev shortcuts

- `npm test` — full suite.
- `npm run bench:djl` — DJL latency benchmark (writes `logs/djl-latency.json`).
- `node bin/decode-evidence.js <evidence.json>` — offline audit-trail verifier.
- `node scripts/warmup-cognee.mjs` — pre-demo Cognee warmup (T0.4).
- `node scripts/bench-tsa-rtt.mjs` — DigiCert RTT baseline (T0.7).
