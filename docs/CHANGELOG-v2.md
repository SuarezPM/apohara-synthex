# Changelog — v2.0.0 vs v1.0.0

> Grouped, honest changelog for the v2.0.0 work, organized by theme rather than by date.
> Every entry traces to a real commit in `git log origin/main..HEAD`; the short SHA is cited
> in parentheses. Capabilities that are NOT yet the default, or modules NOT yet wired into the
> pipeline, are marked explicitly. `docs/HONESTY.md` remains the source of truth for
> measured-vs-claimed — nothing here overrides it.
>
> Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
> [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The canonical
> `CHANGELOG.md` covers ≤ 0.6.0; this file is the v2.0.0 supplement, measured against v1.0.0.

---

## [2.0.0] — 2026-05-30 · "Screen it · Seal it"

The headline of v2.0.0 is the **three-tier injection defense moat**: a real, two-axis
(FP **and** recall) open-model selection that found a guard which earns BLOCK authority on its
*measured* false-positive rate — not an asserted one. Around that moat, v2.0.0 makes the seal
real on more code paths, makes the Evidence Report's hero seal reproducible, adds a Red-Team board
page, cuts classify cost, and lands a set of sponsor/track modules (some wired, some additive).

---

### Three-tier defense — the moat: a two-axis FP+recall gate that earns BLOCK

This is the load-bearing change. v1.0.0's L2 gate was **single-axis** (benign FP only) and L2 was
all-REVIEW because the only measured guard (Qwen3Guard) over-flagged. v2.0.0 adds the mandatory
second axis and a real multi-guard selection.

- **Labeled two-axis corpus** — `test/fixtures/guard-recall-corpus/` (647 samples, 45 cells):
  370 executing-injection (→ expected BLOCK) · 132 benign-describing + 108 benign-neutral
  (→ expected ALLOW, the false-positive trap) · 37 borderline (→ expected REVIEW). **Constructed**,
  NOT in-the-wild — adapted from published techniques (OWASP LLM01, OWASP Agentic ASI, MITRE ATLAS
  AML.T0051, and the format-manipulation transforms in "Bag of Tricks", arXiv:2510.11570). Per-file
  SHA-256 in `MANIFEST.json`. (`ff69cfd`)
  - Note: the corpus `README`/`MANIFEST` composition (132/108) is the committed labeling; the
    measurement doc quotes 136/104 from an earlier count. The harness reads the files, so the
    committed corpus is authoritative. `// TODO(verify)` the doc's 136/104 line against the manifest.
- **Two-axis recall+FP harness** — `scripts/measure-guard-recall.mjs` runs the corpus through each
  Featherless-live guard plus the zero-dep L1 heuristic, measuring **recall** (catch rate on labeled
  injections) **and** benign FP (describing vs neutral). Decision rule: BLOCK authority only for a
  guard with benign FP ≤ 20%; winner = qualifying guard with max recall; else all-REVIEW (L3 holds
  BLOCK). Fail-honest: an unparsed/chatted reply counts as NOT-caught, never a fake pass. (`9f0e0cf`)
- **NemoGuard adapter** — `src/forge/nemoguard.js`: a vanilla content-safety prompt (fair vs Qwen's
  official template — no describing-vs-executing exemption baked in), binary safe/unsafe →
  allow/block, spotlight-wrapped. (`9f0e0cf`)
- **Measured result (n=647, 2026-05-30)** — `docs/guard-recall-measurement.md` is the canonical
  record: Qwen3Guard recall 90% / benign FP 35% → **DISQUALIFIED** for BLOCK; NemoGuard
  (`Llama-3.1-Nemotron-Safety-Guard-8B-v3`) recall 66% / benign FP 11% → **QUALIFIES** for BLOCK
  (≤ 20% bar). The multi-guard selection paid off: it found a guard that earns BLOCK on its measured
  FP. `HONESTY.md` §8.A carries the finding with the caveat that NemoGuard is a **measurement** on a
  **constructed** corpus. (`bc55715`, `9f0e0cf`)
- **NemoGuard wired as a Featherless L2 provider** — `screen()` routes by model:
  `SYNTHEX_GUARD_MODEL` = the NemoGuard id selects the content-safety `/chat/completions` adapter;
  the **default stays Qwen3Guard** for back-compat. Fail-open to the heuristic on any error/non-200/
  chatted reply. (`318f874`)
  - **NemoGuard BLOCK is OPT-IN, not the default.** It is gated twice: (1) you must set
    `SYNTHEX_GUARD_MODEL` to the NemoGuard id to select it at all, and (2) any `block` verdict is
    REVIEW-capped unless `SYNTHEX_GUARD_BLOCK_ENABLED` is truthy (`_capVerdict`,
    `src/forge/injection-guard.js`). Conservative because the FP is measured on a CONSTRUCTED corpus;
    the operator opts in. The public "L2 holds BLOCK authority via NemoGuard" claim still waits on
    the production-default wiring (see `guard-recall-measurement.md` follow-up 1).
- **L3 false-BLOCK measurement harness** — `scripts/measure-l3-recall.mjs` runs the L3
  AlignmentCheck reasoner (`deepseek-v4-pro`) over the 647-corpus, reporting recall (BLOCK on
  executing injections), false-BLOCK (BLOCK on benign-describing — the moat number), and REVIEW on
  borderline. Fail-honest: no key → "L3 unavailable", exit non-zero. `--sample`/`--concurrency` bound
  the frontier-model cost; the full run is opt-in. Writes `out/guard-recall/l3-results.json`.
  (`a1fc4e0`) The harness ships; the measured L3 false-BLOCK number over the new corpus is **not yet
  recorded here** — run it to fill in. `// TODO(verify)` the recorded L3 number once run.

### Evidence Report — reproducible hero seal + Red-Team board page

- **Reproducible hero generator** — `scripts/gen-hero-report.mjs` loads the committed hero evidence +
  C2PA sidecar + Rekor anchor and regenerates the hero PDF with the full seal surfaced; it exits
  non-zero if a seal row would be dark. Fixes the v1 known-gap where `buildPDFReport` present-gated
  the Rekor + C2PA rows on `opts.c2paSidecar`/`rekorBundle` but no committed caller passed them, so a
  fresh reproducible build silently dropped both rows and the verify page fell to the "not present"
  branch. `api/report.js` now passes through client-supplied sidecars (rows appear only when the
  artifacts exist). Present-path + honest-absence asserted on `sealRows()` in-process — PDFKit
  subset-CID fonts make grepping the rendered bytes useless. (`c12ca40`)
- **Red-Team Board Briefing page** — `src/prove/report/page-redteam.js` renders the sealed 5-lens
  adversarial red-team (`src/redteam/`) as an Evidence Report page: per-lens risk + one grounded
  concern, the Risk Score BAND and the board VERDICT surfaced as **two distinct axes** (never
  collapsed into one), and the Top-3 board questions. Honest framing: 5 prompts / 1 model, NOT 5
  independent models. Every value is recomputed from the sealed `payload.decisions[]` with the
  byte-identical `src/redteam` aggregate formula. Wired into `pdf-report.js` **present-gated on sealed
  `REDTEAM_*` rows**, so ordinary evidence (including the hero) is unaffected. (`db3aca9`)

### Seal everywhere — Ed25519 on the react/monitor + MCP paths

- **react/monitor + MCP paths seal the real Ed25519 by default** — `runPipeline` already accepted a
  `signingKey`, but `watch.js` + `tools.js` never passed one, so those paths sealed HMAC-only (the
  "real seal in every artifact" thesis failed off the CLI). Both now resolve the persistent signing
  key (`resolveSigningKey()`: env → XDG default) and forward it. (`3d21c4b`)
  - **Honest scope:** `runPipeline`'s **own default is intentionally NOT changed** — leaving it to
    auto-resolve would make test seals depend on whether the dev machine has an XDG key
    (environment-dependent, non-reproducible CI). With no key configured, `resolveSigningKey()`
    returns `null` and the path stays symmetric-only, byte-identical to before. So: the react/monitor
    + MCP paths now seal Ed25519 **when a persistent key is configured**; a keyless CI run is
    unchanged. This is a per-path wiring fix, not a global default flip.

### Classify — batched 4-lens default (pay the input once)

- **`classifyBatched` wired as the `lens="all"` bulk default** — the `lens="all"` path now issues
  ONE structured call per doc for all four lenses (untrusted input paid 1× instead of 4× — the AI/ML
  cost lever) via the already-built-and-tested `classifyBatched`. The per-lens `classify()` stays the
  **schema-isolation fallback**: it is used whenever a per-lens `classifier` is injected (tests/custom)
  so one bad lens still can't corrupt the others, and all existing injected-classifier tests are
  unchanged. The trilens output shape is identical. `batchedClassifier` is injectable; `defaultBatched`
  is used only when nothing is injected. (`8d841ab`)

### Sponsors / modules — compliance data, Speechmatics, SERP, multimodal, Kiro

- **Compliance-data module** — `src/prove/compliance-data.js`: a structured, zero-dep, frozen dataset
  that the Counsel + Model-Attestation report pages (and STIX/audit consumers) can read from instead
  of inline per-page matrices. Citations are CANONICAL/VERBATIM (tests assert literal presence):
  EU AI Act (Reg. (EU) 2024/1689) Art 11 "Technical documentation" / Art 12 "Record-keeping" (NOT
  "logging") / Art 13; NIST AI RMF 1.0 incl. MEASURE 2.5; NYDFS 23 NYCRR Part 500 (2nd Amendment)
  §500.06; SR 11-7 (= OCC Bulletin 2011-12); OWASP LLM 2025 (LLM01/02); OWASP Agentic 2026 (ASI01);
  MITRE ATLAS v5.6.0 (AML.T0051/.001). Every row is a MAPPING, NOT an endorsement; `rag_status` is an
  honest self-assessment with a basis; the ASI01 title is left `// TODO(verify)` rather than
  fabricated. (`53457db`)
  - **Honest scope:** this commit lands the data module + its tests. Wiring the Counsel /
    Model-Attestation pages to consume it (the P2.7 refactor) is **not in this changeset**.
    `// TODO(verify)` the ASI01 entry title.
- **Speechmatics batch ASR client** — `src/fetch/speechmatics-client.js`: built-in fetch + FormData
  (zero new deps), submit → bounded-poll → transcript, finance knobs (domain/diarization/entities/
  operating_point), returns a seal-ready envelope. Fail-safe: recoverable failures return a structured
  error, never throw; a missing key throws at construction. Stub-server tested (no live network in the
  suite); one opt-in live smoke gated behind `SPEECHMATICS_LIVE`. (`f66cdae`)
  - **NOT wired into the router yet** — additive module only.
- **SERP signal lens** — `src/fetch/serp-signal.js`: maps a (brand, signal-kind) pair to a SERP query,
  fetches via an INJECTABLE fetcher (stub in the suite; Bright Data SERP live), returns a seal-ready
  signal envelope. Brand / credential-leak / regulatory / hiring monitoring. Fail-safe; live smoke
  gated behind `SERP_LIVE`. (`db3aca9` → corpus is `db06082`)
  - **NOT yet wired into a lens** — additive module only.
- **Multimodal screen** — `src/fetch/multimodal-screen.js`: given a rendered screenshot + DOM text,
  an injected vision client flags injections hidden by white-on-white / off-screen / alt-text that
  pure text extraction misses. Screenshotter + vision client are injectable (stubbed in the suite —
  no real browser/API); fail-safe (degraded on unavailable). Live smoke behind `MULTIMODAL_LIVE`.
  (`5e640b3`)
  - **NOT wired into the pipeline yet** — the browser client returns text-only today, so the
    screenshot path is injected pending a browser-client `screenshot()` method.
- **Kiro QA hooks** — four committed `.kiro/hooks/*.kiro.hook` using ONLY the confirmed Kiro IDE API
  (`fileEdited` / `agentStop`; `shellCommand` preferred over `askAgent`; **no fabricated on-commit
  event** — `pre-commit-qa` honestly approximates "pre-commit" via `agentStop`). Each references a
  command that EXISTS today (`npm test`, `node --test` + `npm audit`, `gen-hero-report.mjs`,
  `decode-evidence.js`). `.kiro/hooks/README.md` documents what each catches. (`8ee361e`)
- **Kiro v2 spec triplet + QA agent** — `.kiro/specs/v2/{requirements.md (EARS), design.md, tasks.md}`
  as the spec-driven source of truth shared between Kiro and Claude Code; `design.md` leads the seal
  with Ed25519 (HMAC internal-only). (`779d027`) Plus `.kiro/agents/synthex-qa.json`, the headless
  Kiro CLI QA-buddy agent, and `docs/internal/V2_PLAN.md`, the dependency-ordered P0–P4 plan.
  (`5d2d1dd`)
- **npm scripts for reproducibility** — every v2 metric now has a reproduce command:
  `gen:hero` (reproducible hero report), `guard:fp` (single-axis benign FP), `guard:recall` (two-axis
  FP+recall gate), `l3:recall` (L3 false-BLOCK over the 647 corpus). Repo-only measurement tools — NOT
  added to the publish allowlist. (`e62d021`)

### Stress harness scaffold

- The capstone epic stress harness (`scripts/stress/` + `npm run stress` + a sealed Stress Test Report
  with seal-integrity %, tamper-detection %, two-axis FP/recall, per-layer contribution, cost/1000,
  and p50/p95/p99) is **planned (P4.1) but NOT built in this changeset**. What exists toward it: the
  reproducibility scripts above (`gen:hero`, `guard:fp`, `guard:recall`, `l3:recall`), the labeled
  647-sample corpus, and the two-axis harness — the measurement primitives the stress report will
  consume. `docs/internal/V2_PLAN.md` §P4 carries the full scope. `// TODO(verify)` once the harness
  lands.

### Honesty reconciliation (public surfaces)

- **L2 FP reconciled to the canonical 3/5 framing** — the L2 Qwen3Guard benign FP was stale at 2/5 on
  landing / SLIDES / HONESTY §8; the canonical `docs/guard-fp-measurement.md` measures 3/5 (60%),
  observed 2/5–3/5 across runs (hosted inference is non-deterministic). `HONESTY.md` §8.A aligned to
  the canonical value; the terse public surfaces (landing/SLIDES) now lead with the measured RANGE +
  the stable DISQUALIFIED decision rather than a single drifting number. (`d6a5d6e`)
- **"court-verifiable" → "third-party-verifiable"** across residual surfaces (per the 2026-05-29 audit
  finding); added C2PA-self-signed + multi-TSA-not-eIDAS caveats to the landing honesty list; README
  triad reworded to "Screen it · Seal it". (`d6a5d6e`)

---

### What did NOT change (honest non-claims for v2.0.0)

- **The pipeline's default seal is still HMAC-only without a configured key.** Only the react/monitor
  + MCP paths gained the Ed25519 wiring, and only when a persistent key is resolvable; keyless CI is
  byte-identical to v1.0.0. (`3d21c4b`)
- **NemoGuard does not BLOCK by default.** It is opt-in via `SYNTHEX_GUARD_MODEL` and additionally
  REVIEW-capped unless `SYNTHEX_GUARD_BLOCK_ENABLED` is set. The default L2 guard is still Qwen3Guard,
  which remains DISQUALIFIED for BLOCK on its measured 35% FP. (`318f874`, `bc55715`)
- **Speechmatics, SERP signal, and multimodal screen are additive modules, not wired** into the
  pipeline/router. (`f66cdae`, `db06082`, `5e640b3`)
- **The compliance-data module is not yet consumed** by the Counsel / Model-Attestation pages.
  (`53457db`)
- **The recall/FP corpus is constructed, not in-the-wild** — a reproducible labeled benchmark adapted
  from published techniques, not a field study. The 5-page `guard-fp-corpus` remains the in-the-wild
  FP anchor. (`ff69cfd`)
- **The epic stress harness is not built** — scaffolding (corpus + two-axis harness + reproduce
  scripts) only.
- All v1.0.0 honest non-claims carry forward: no "first in world" composition claim; the PDF Risk
  Score is an internal estimate, not a rating; the pre-LLM regex layers are heuristics, not proofs;
  C2PA Content Credentials are self-signed / UNTRUSTED until CA-rooted.
