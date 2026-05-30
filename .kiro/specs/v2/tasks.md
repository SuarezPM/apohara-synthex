# Synthex v2.0.0 — Tasks

> **Spec format:** Kiro-native (`.kiro/specs/v2/`).
> **Status:** Planning. Pairs with `requirements.md` (R1–R8) and `design.md`.
> **Source plan:** `docs/internal/V2_PLAN.md §4` (P0→P4, dependency-ordered).
> **Convention:** one checkbox per discrete, verifiable task. `[x]` = already
> shipped + tested (do NOT rebuild). Sequence is LOCKED to the roadmap:
> P0 honesty + seal-surfacing → P1 three-tier defense → P2 enterprise artifacts +
> multi-track + sponsors → P3 stretch → P4 the epic stress test LAST.

---

## P0 — Honesty + seal surfacing (do FIRST) — covers R1, R2

- [ ] **P0.1** Wire C2PA + Rekor sidecars into the Evidence Report so the Rekor +
  C2PA rows are load-bearing in every reproducible build. Files: `api/report.js`,
  `scripts/gen-sample-report.mjs`, a NEW committed hero generator. Verify by
  calling `sealRows`/page fns in-process (NOT grepping the PDF). (R1.1–R1.4)
- [ ] **P0.2** Fix the verify-page commands + emit the sidecar
  `<reportId>.evidence.json`. Files: `src/prove/report/page-verify.js`,
  `bin/synthex.mjs`. Every printed command must run against the emitted files.
  (R1.5) <!-- TODO(verify): add a unifying `verify` verb vs reword to real verbs is a pending decision (V2_PLAN §6 Q4) -->
- [ ] **P0.3** Reconcile stale numbers + caveats across all public surfaces
  (`2/5`→`3/5`; uncaveated "court-verifiable"→0; add C2PA-self-signed +
  multi-TSA-not-eIDAS to the landing honesty list; README off the v1 triad).
  Add a value-consistency check beyond `lint:slides` (which checks presence, not
  value). (R2.1–R2.4, R2.6)
- [ ] **P0.4** Reword HMAC framing in seal headers + `seal.method` to lead
  Ed25519 (HMAC = internal checksum). Regenerate affected fixtures (method is in
  the pre-image); do NOT break the v1 legacy fixture. (R3.1, R3.5)
- [ ] **P0.5** Fix the CAWG ratification date copy to "DIF-ratified 05 Feb 2026
  (v1.0)"; 0 occurrences of "ratified Dec 2025". (R2.5)

## P1 — Three-tier defense core (the moat) — covers R4

- [x] **P1.0** L1 forge REVIEW-only — DONE. Regex never BLOCKs; enforced at the
  pipeline call-site; INV-15 removed from `src/`; counts verified (DJL=78 /
  prefilter=32 / PII=25). Do not regress.
- [x] **P1.1** L2 Featherless Qwen3Guard adapter — DONE (adapter only).
  Moderation-template render + raw POST + tri-level mapping + REVIEW-cap (39/39).
- [ ] **P1.2** Two-axis FP-gate (benign FP + recall on a labeled novel-injection
  corpus). NEW corpus under `test/fixtures/` (ATLAS `AML.T0051`/`.001` +
  `arXiv:2510.11570` "Bag of Tricks"), extend the FP harness to compute recall +
  joint winner selection, add an `npm run fp-gate` / `bench:guard` script.
  BLOCK authority only to a winner bounding FP while maximizing recall, else
  all-REVIEW (stated). (R4.1–R4.3, R4.5)
- [ ] **P1.2a** Probe additional Featherless guards (one cheap call to
  `Llama-Guard-3-8B`, request `AprielGuard-8B`); add only confirmed-live guards
  to the roster. (R4.4)
- [ ] **P1.3** Wire `classifyBatched` as the bulk default (`lens==='all'` → 1
  fetch for 4 lenses), KEEP per-lens `classify()` as the schema-isolation
  fallback. Default `deepseek/deepseek-v4-flash`. (design §3)
- [ ] **P1.4** Nemotron positioning decision: re-add the verified
  `nemotron-3-nano-omni-30b-a3b-reasoning:free` id OR drop the requirement;
  update `HONESTY.md` + `tiers.test.js`. <!-- TODO(verify): pending decision, V2_PLAN §6 Q3 -->
- [ ] **P1.5** Measure L3 benign false-BLOCK (`scripts/measure-l3-falseblock.mjs`
  exists, `AIML_API_KEY` valid); record the number in
  `docs/guard-fp-measurement.md` with a reproduce command. (R4.6)
- [ ] **P1.6** Wire `lint:spotlight` + `node --test` into CI and/or the Kiro
  on-save hook; a PR adding an unwrapped LLM egress must fail the gate.
  (R8.1, design §10)

## P2 — Enterprise artifacts + multi-track + sponsors — covers R3, R5, R6, R8

- [ ] **P2.1** `runPipeline` defaults to the full Ed25519 seal (resolve + pass
  `signingKey`); fix the HMAC-only default in `watch.js` + MCP `tools.js`. Do NOT
  auto-generate an ephemeral key on the default path. (R3.1–R3.4)
- [ ] **P2.2** Seal the Bright Data surface + ids in `decisions[]` (extend
  `payload.sources` beyond `d.url`); replace the `surfaceOf` heuristic in
  `page-data-bom.js` with the sealed fact; remove the "no live surface is sealed"
  note once true. (R5.1, R5.2, R5.4–R5.6)
- [ ] **P2.3** Wire ≥3 Bright Data surfaces into a real run (SERP + Web Scraper
  dataset / discover_new + Scraping Browser), each sealed. Probe the 3 BD
  blockers first (progress path, SERP zone, body shape). (R5.3)
- [ ] **P2.4** Cognee recall on re-scrape + delta→Cognee ingest: call
  `cogneeClient.recall({target,lens})` before re-scrape; set
  `kg_status:'ingested'` after a successful sink; reconcile the cloud client
  (drop `X-Tenant-Id`, `search_type:'TEMPORAL'`); populate `COGNEE_API_URL`.
  (R6.1–R6.6)
- [ ] **P2.5** TriggerWare react loop: live demo + CLI `react`/`watch` verb;
  (stretch) BD discover_new glue. Fix the stale `monitor.js:3-4` comment.
  (design §7) <!-- TODO(verify): createTrigger/poll body field names guessed -->
- [ ] **P2.6** Full seal stack on the Red-Team artifact (`requestTsa:true` +
  c2pa-emit + rekor-anchor) + render REDTEAM rows in the PDF; add a benign-control
  red-team fixture + control-FP test. (design §1)
- [ ] **P2.7** Compliance matrix as a reusable sealed data module
  (NEW `src/prove/compliance-data.js`); use canonical citations (EU AI Act Art
  11/12 "Record-keeping"/13, NIST AI RMF, NYDFS Part 500 2nd Amendment, SR 11-7 /
  OCC 2011-12, OWASP LLM 2025, OWASP Agentic 2026 ASI01–10, MITRE ATLAS v5.6.0
  AML.T0051/.001); add the missing `riskScore` unit test. (design §8)
- [ ] **P2.8** Reverse-flow seal into Aegis (push Ed25519 + Rekor + C2PA up into
  `apohara-aegis`, currently HMAC-chain only). Cross-language; cut before core.
- [ ] **P2.K** Kiro QA team-buddy — author the `.kiro/hooks/*.kiro.hook` files,
  update `.kiro/steering/synthex-conventions.md` (stale HMAC headline + Opus 4.7
  footer), document each hook's catch in the README. **The `.kiro/specs/v2/`
  triplet (this requirements/design/tasks set) is DONE.** Hooks are sequenced
  AFTER the scripts they call exist. (R8.1–R8.6, design §10)
  - [ ] `qa-on-save.kiro.hook` — `when.type:fileEdited`
    `["src/**/*.js","!**/*.test.js"]`, `then.type:shellCommand` (`node --test` +
    `npm audit`, + fp-gate once P1.2 ships).
  - [ ] `report-integrity.kiro.hook` — `when.type:fileEdited` on report source,
    `then.type:shellCommand` (regenerate + fail on stale / overflow / missing
    Ed25519|C2PA|Rekor seal field).
  - [ ] `seal-verify-smoke.kiro.hook` — `when.type:fileEdited` on emitted
    artifacts, `then.type:shellCommand` (3-way + Ed25519).
  - [ ] `pre-commit-qa.kiro.hook` — `when.type:agentStop` (the ONLY honest
    approximation of "on-commit"; NO native git event), `then.type:shellCommand`.

## P3 — Stretch expanders (if time; else documented as v2.1 roadmap)

- [ ] **P3.1** Speechmatics sealed transcript (NEW `src/fetch/speechmatics-client.js`):
  batch `POST /v2/jobs/` → poll → canonicalize + seal `results[]`. Seal
  immediately (7-day retention). <!-- TODO(verify): keep at most one P3 stretch, V2_PLAN §6 Q5 -->
- [ ] **P3.2** Multimodal screening (Scraping Browser screenshot + DOM → vision
  classify to catch CSS-hidden injections). Cut first.
- [ ] **P3.3** SERP signal layer (brand / credential-leak / regulatory monitoring
  as a sealed lens).
- [ ] **P3.4** CAWG org identity on the C2PA card (c2patool
  `--identity-signer-path` / `[cawg_x509_signer]`); keep the self-signed caveat
  until truly CA-rooted.

## P4 — The epic stress test (capstone; LAST) — covers R7

- [ ] **P4.1** Build `scripts/stress/` + `npm run stress` + a SEALED Stress Test
  Report (itself a Synthex evidence artifact — meta-proof). Dimensions, each with
  a reproduce command: scale/throughput; seal integrity % (Ed25519+TSA+Rekor+C2PA)
  + tamper-detection %; two-axis guard FP + recall + per-layer L1/L2/L3 +
  layered-vs-single (`arXiv:2510.11570`); cost/1000 traced to architectural cause;
  latency p50/p95/p99 per stage; determinism. Publish the harness + corpus
  manifest (hashed, versioned, ≥1000 distinct). (R7.1–R7.9)
  <!-- TODO(verify): final scale + sampled-TSA acceptability gated on budget, V2_PLAN §6 Q2 -->

---

## Progress summary

- **Done (do not rebuild):** P1.0 (L1 REVIEW-only), P1.1 (L2 adapter),
  `.kiro/specs/v2/` triplet (this set). STIX 2.1 export, 5-persona Red-Team
  (HMAC+optional-Ed25519 only — full seal still pending in P2.6), and
  `delta_chain` are shipped + tested at the engine level (`V2_PLAN.md §2`).
- **Pending:** all P0 · P1.2 / P1.2a / P1.3 / P1.4 / P1.5 / P1.6 · all P2
  (hooks within P2.K) · all P3 · P4.
