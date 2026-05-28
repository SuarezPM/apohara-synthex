# Changelog

All notable changes to `@apohara/synthex` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.6.0] — 2026-05-28 · "Watch & Prove"

### Added

- **Delta Evidence Chain** (`src/delta/`): new module that encadena snapshots
  cross-time. `sealDeltaChain({prev_evidence, curr_snapshot, hmacKey})`
  reuses the existing `buildEvidence()` core and adds
  `payload.delta_chain.{previous_tsa_serial, current_tsa_serial,
  diff_summary, kg_status, kg_skip_reason}` to the sealed payload. Additive
  on schema v2 — no schema bump, no breaking change for v0.5.0 reports.
- **Monitor.runOnceWithDelta()** (`src/trigger/monitor.js`): append-only
  method that wraps each pipeline run in a chained evidence + emits alerts
  enriched with `deltaSummary` and TSA serial linkage. Original
  `runOnce()` untouched for back-compat.
- **Delta Evidence PDF** (`src/prove/pdf-report.js`): 7th page conditional
  on `payload.delta_chain` presence — TSA chain anatomy + diff summary +
  KG status banner. Reports without delta stay 6 pages.
- **CLI `decode-evidence --delta-chain`** block: prints the chain
  (previous_tsa_serial → current_tsa_serial) + diff_summary + kg_status
  when the evidence has the field. Back-compat with v0.5.0 reports
  (block omitted when absent).
- **Model tier selector** (`src/classify/tiers.js`): `MODEL_TIERS = {free,
  oss, paid}` + `pickModel({tier, model})`. Tier `free` =
  `nvidia/nemotron-nano-9b-v2` (labeled `free-low-quality` per T0.6
  calibration), `oss` = DeepSeek non-thinking (default), `paid` = DeepSeek
  thinking. `aiml-client.js` accepts `opts.tier`; `api/analyze.js` accepts
  `req.body.tier` from the playground.
- **PII filter bundle** (`src/forge/pii-filter.js`): 25 rules (10 DJL-PII
  reused + 15 PII-EXT for secrets leak: AWS keys, GitHub PAT, Stripe live
  key, JWT, etc.). `shouldSkipKgIngest(text)` gates Cognee ingest on PII.
- **HMAC_EXCLUDED_KEYS** (`src/prove/evidence-report.js`): normative
  constant `[kg_status, kg_latency_ms, surface_status]` excluded from the
  HMAC bytestring so cross-run determinism survives Cognee/Browser
  availability fluctuations.
- **COGNEE_REMOTE_URL guard** (`src/memory/cognee-client.js`):
  `connect()` throws if the env var is set, preventing accidental
  exfiltration of scraped content to a cloud Cognee endpoint.
- **TSA RTT bench** (`scripts/bench-tsa-rtt.mjs`): N-sample measurement of
  DigiCert RFC 3161 round-trip. Baseline 2026-05-28: p95 385 ms (margin 4x
  over SC-3b 1500 ms gate).
- **Nemotron-vs-DeepSeek calibration** (`scripts/calibrate-nemotron.mjs`
  + `test/fixtures/calibration-fixtures.js`): 20 fixtures × 2 tiers
  evaluation; FREE tier labeled `free-low-quality` after 50% Δseverity > 1.5.
- **Stress test harness** (`scripts/stress-test-judges.mjs` +
  `scripts/stress-urls.js`): real-time budget cap, per-surface cost
  estimate, telemetry to `.omc/state/v060-telemetry.jsonl`, output
  `out/stress-*/report.json` + individual evidence JSONs.
- **Live dashboard** (`public/dashboard.html`): vanilla HTML/JS, polls
  telemetry JSONL every 3s, shows 7 KPIs + last-20 table.
- **Playground UI** (`public/playground.html`): URL input + lens dropdown
  + model tier dropdown + 5 pre-loaded examples + Analyze + Watch (60s
  loop) + Download JSON + Copy contentHash.
- **Kiro integration** (`.kiro/specs/delta-engine.md` + `.kiro/steering/
  synthex-conventions.md` + `.kiro/mcp.json`): declares
  `@apohara/synthex` as a Kiro-native MCP server.
- **`npm run lint:slides`**: validator script that every numeric claim in
  `SLIDES.md` has an explicit `[src: path]` citation or adjacent context
  citation.
- **`docs/PRIOR_ART.md`**: reproducible directed-search queries proving
  Synthex's "no open-source combination of these five primitives" claim;
  defensible against post-launch challenge.
- **`docs/v060-stress-report.md`**: full empirical report of the 500-URL
  stress run (99.6% success, $0.75 cost, 9.1 min wall clock).
- **`docs/v060-calibration.md`**: pattern analysis of nemotron over-flagging
  noise.
- **`docs/v060-model-status.md`**: audit confirming DeepSeek is the
  baseline (not deprecated Gemini).
- **`docs/v060-implementation-audit.md`**: T1.0 pre-impl audit gate.
- **`docs/PERFORMANCE.md`**: honest baselines (TSA RTT, suite runtime).
- **`docs/demo-checklist.md`**: T-60/30/15/5/2 cronograma + recovery
  playbook.

### Changed

- **Suite size**: 162 → 262 tests (+100), 152 → 252 pass (+100), 0 fail
  preserved.
- **SLIDES.md**: full rewrite for v0.6.0. Every numeric claim cited.
- **`api/analyze.js`**: accepts `tier` body param + returns `{tier, model}`
  in response. Back-compat 100%.

### Fixed

- **MODEL_TIERS.free model id**: external audit said
  `nvidia/nemotron-3-nano-omni` — empirically does NOT exist in AI/ML API
  (HTTP 404). Switched to `nvidia/nemotron-nano-9b-v2` (verified live in
  `/v1/models`). Commit `00e606a`.

### Security

- `COGNEE_REMOTE_URL` env guard prevents accidental cloud filtration of
  scraped content during stress tests.
- PII filter 25-rule bundle gates KG ingest on secret-leak signals
  (AWS/GCP/Stripe/GitHub/Slack keys, PEM private keys, JWT tokens).

### Performance

- DigiCert TSA RTT p95: 385 ms on CachyOS-PC 2026-05-28 (4× margin over
  SC-3b 1500 ms gate).
- Stress 500 URLs: 99.6% success, $0.0015/URL, 9.1 min wall clock at
  concurrency 8.

### Honest non-claims

- Synthex does NOT claim "first in world" for the 5-primitive composition.
  `docs/PRIOR_ART.md` documents the directed search behind "no open-source
  combination found at 2026-05-28".
- The PDF Risk Score is an internal estimate, NOT a Munich Re rating.
- The 3 pre-LLM layers (28+78+25) are heuristic regex, NOT formal proofs.

---

## [0.5.0] — 2026-05-27

### Added (v0.5)

- Two-layer pre-LLM defense (28 web-injection + 78 DJL = 106 rules).
- `decisions[]` audit trail in payload.
- Canonicalize HMAC (RFC 8785 JCS).
- `tokens_saved` telemetry in payload.
- Node 24 LTS minimum.
- MIT license unified.

---

## [0.4.0] and earlier

See `git log` for full pre-v0.5 history.
