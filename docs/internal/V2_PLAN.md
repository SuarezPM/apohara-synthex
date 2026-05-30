# Apohara Synthex — v2.0.0 Release Plan

> Single planning document reconciling the master roadmap (`mega_prompt_v2.md`) with structured repo
> reconnaissance + external gate-before-trust probes. Date: 2026-05-30. Source of honesty: `docs/HONESTY.md`.
> Sequence is LOCKED to the roadmap: P0 honesty+seal-surfacing → P1 three-tier defense → P2 enterprise
> artifacts+multi-track+sponsors → P3 stretch → P4 the epic stress test LAST.

---

## 1. STATE MATRIX

Sorted by the phase where the remaining work lands (P0 first). Areas already DONE are pinned to the phase
that would have built them.

| Phase | Area | Status | One-line gap |
|-------|------|--------|--------------|
| P0 | Seal stack core (the real seal) | partial | Engine + tests done (131/131); HMAC still LEADS `seal.method` and several headers call it "base/load-bearing" — reword to internal-only, lead Ed25519. |
| P0 | Enterprise Evidence Report PDF | partial | Seal copy FIXED IN CODE (sealRows leads Ed25519); but NO caller passes `c2paSidecar`/`rekorBundle`, so Rekor+C2PA rows silently vanish on every reproducible build; no committed hero generator; verify-page commands (`synthex verify`, c2patool on JSON sidecar) don't match the real CLI. |
| P0 | Honesty + public claims reconciliation | partial | L2 FP number stale everywhere (`2/5` vs source `3/5`); "court-verifiable" used uncaveated on landing+SLIDES; landing honesty list omits C2PA-self-signed + multi-TSA-not-eIDAS; README still leads v1 triad "Scrape·Classify·Prove". |
| P1 | L2 guard (Featherless Qwen3Guard) + FP-gate | partial | Adapter correct (39/39); FP-gate is SINGLE-AXIS (benign FP only). No recall axis, no labeled novel-injection corpus, no two-axis winner selection, no npm/CI script. |
| P1 | L3 policy reasoner + grounding + Spotlighting | partial | All three real (26/26). Gaps operational: lint+`node --test` not wired into any CI/Kiro hook; L3 benign false-BLOCK measurable but UNMEASURED (no `AIML_API_KEY` at probe time, n=5 corpus). |
| P1 | Classify brain (4 lenses, batched, tiered) | partial | `classifyBatched` built+tested but NOT wired — pipeline still issues 4 per-lens calls. Nemotron "free tier" target CONTRADICTS repo (removed v1.0.0); needs positioning decision (probe found `:free` id live). |
| P1 | L1 forge (regex, REVIEW-only) | done | Met. REVIEW-only enforced at pipeline call-site; INV-15 absent from `src/`; counts verified (DJL=78, prefilter=32, PII=25). Cosmetic: leaf fns still return "BLOCK" label (downgraded upstream). |
| P2 | Pipeline + MCP server + CLI | partial | Full seal stack exists but `runPipeline` is symmetric-only by default (never calls `resolveSigningKey`); watch.js + MCP `tools.js` seal HMAC-only. No standalone `verify` CLI verb. |
| P2 | Bright Data ingest spectrum (each sealed) | partial | 6 real tested clients + router, but NO surface is sealed (`payload.sources = docs.map(d=>d.url)`); surface column in report is URL-regex GUESS. discover_new + Scraping Browser are dead on the default path. |
| P2 | STIX 2.1 + compliance matrix + risk score | partial | STIX export real+wired+tested. Compliance matrix exists only as inline per-page data (no reusable/sealed data module); no riskScore unit test; some RAG statuses hardcoded not evidence-driven. |
| P2 | Sealed Red-Team mode (5-persona) | partial | 5 personas built+sealed (9/9), but seals `requestTsa:false` → HMAC+optional-Ed25519 only (NO TSA/Rekor/C2PA); no PDF rendering of REDTEAM rows; live-target path not wired. Consilium "port" is N/A (no finance personas in sibling; authored fresh). |
| P2 | Cognee memory + delta_chain | partial | delta_chain shipped+consumed by Monitor; CaMeL gate + local/cloud switch real. Headline gap: Cognee RECALL on re-scrape NOT wired (recall() has zero call sites in src); Cognee is write-only; `kg_status` never set to "ingested". |
| P2 | Cross-time delta chain | partial | normalize/hash/diff pure+deterministic; sealed+consumed by Monitor+PDF. Cognee side schema-only; `current_tsa_serial` null in CI (no live TSA); preview truncated at 16KB. |
| P2 | TriggerWare react loop | partial | Loop real+CaMeL-gated (36 pass) but delta source is TriggerWare.ai (real, key valid), NOT BD discover_new; BD adapter never wired into reactor; no CLI verb, no demo scene. |
| P2 | Portable assets from sibling repos | partial | Most port targets ALREADY DONE in JS (personas, spotlight+lint, STIX, compliance matrix). Remaining: reverse-flow seal into Aegis (unstarted), guard two-axis FP+recall gate, AST-lint port (current is regex). |
| P2 | Kiro QA team-buddy (.kiro/) | missing | No `.kiro/specs/v2/`, no `.kiro/hooks/` at all. Today Kiro is a one-shot spec executor. All hooks + v2 spec triplet must be authored. |
| P4 | Epic stress-test harness (capstone) | partial | Throughput harness exists (50/500 runs) but no `scripts/stress/`, no `npm run stress`, no seal-integrity %, no tamper detection, no two-axis FP/recall, no per-layer, no p99, no determinism check, no sealed Stress Report. Prior evidence has only HMAC+TSA (no Ed25519/Rekor/C2PA) → can't even prove the headline. |

**Counts:** done = 1 · partial = 14 · missing = 1.

---

## 2. ALREADY SHIPPED (de-risk — do NOT rebuild)

The seal engine and the honesty infrastructure are genuinely mature. Rebuilding them would burn the budget. What is DONE:

### Seal core — SHIPPED and tested (the moat's foundation)
- **All five seal components implemented AND tested at the engine level**: SHA-256 + Ed25519 (`src/prove/asymmetric.js`) + RFC 3161 TSA with DigiCert anchor + EKU `id-kp-timeStamping` pin (`src/prove/tsa.js`) + Rekor v2 OFFLINE verify with real RFC 6962 Merkle reconstruction + C2SP checkpoint-vs-pinned-key (`src/prove/rekor.js`) + C2PA Content Credentials as COSE_Sign1 with x5chain + EKU `id-kp-documentSigning` (`src/prove/c2pa.js`). **131/131 prove tests pass.**
- **The in-toto subject-digest bug is genuinely fixed**: empirically verified `subjectDigest 835ae008…8feca96 === sha256(SPKI DER)`, NOT `keyId+zeros`. Fixture re-anchored against REAL Rekor v2 (logIndex 4729698). The active check is load-bearing (`src/prove/rekor.js:242-245`).
- **Rekor v2 offline verify reconstructs the Merkle root and checks the checkpoint sig against the TUF-pinned Ed25519 log key** — fixture is a REAL captured Rekor v2 bundle, not mocked. External probe confirmed the pinned key matches the live `log2025-1.rekor.sigstore.dev` shard (HTTP 200, 2026-05-30).
- **L1 forge REVIEW-only is DONE** (the only area marked `done`): regex never BLOCKs a document; enforced at the pipeline call-site; INV-15 fully removed from `src/`. Counts verified (DJL=78 / prefilter=32 / PII=25).

### The Evidence Report P0 "known gap" — PARTIALLY closed (CODE yes, WIRING no)
The roadmap's P0 says "the fields already exist in decisions[] — this is surfacing, not building." Reconciliation:
- **The seal-copy fix is REAL and correct IN CODE**: `src/prove/report/components.js:232-250` `sealRows()` now leads `Ed25519 → RFC3161 TSA → Rekor v2 → C2PA → SHA-256 → HMAC("internal integrity checksum")`. The v0.7 `"HMAC-SHA256 + RFC 3161 TSA"` headline is gone from the renderer. The verify page has the full 3-way verify (`page-verify.js:46-122`). The "does NOT prove" page exists (`page-honest-gap.js`). Per-page disclaimer footer is drawn.
- **BUT the fix is DARK in practice**: NO caller of `buildPDFReport` passes `c2paSidecar`/`rekorBundle` (`api/report.js:27` passes only `{epssMap}`; `scripts/gen-sample-report.mjs:33` and every test call it bare). So on every reproducible build the Rekor+C2PA rows silently vanish and the verify page falls to the "not present" branch. **This is the surviving P0 task: wiring, not building.** Confirmed by running `sealRows` in-process: WITH sidecars it emits the Rekor logIndex + C2PA row; WITHOUT them both vanish.
- **The canonical sample is a REAL injection-catch**: `samples/synthex-hero-evidence.json` has an L3 `ALIGNMENT_CHECK BLOCK` on an active prompt-injection (`globalretail-intel`) plus an `ALLOW` on the OWASP cheat-sheet (describing-vs-executing with benign control). This satisfies the roadmap's "catch thesis" sample requirement.

### Honesty Phase 0 — SHIPPED (the moat)
- `docs/HONESTY.md` (362 lines) is a real source-of-truth: HMAC framed as internal checksum and "never the headline"; C2PA self-signed/untrusted caveated; multi-TSA NOT eIDAS-qualified; L2 DISQUALIFIED for BLOCK; "court-grade" flagged as a removed 2026-05-29 audit finding.
- `npm run lint:slides` passes (every numeric claim cites a `[src:]`); `npm audit` = 0; suite green (547 pass/0 fail per project memory).
- **What is NOT yet reconciled** (P0 work): the stale `2/5` L2 FP number on landing+SLIDES+HONESTY §8; the uncaveated "court-verifiable" on landing+SLIDES; the landing honesty-list omissions; README still leading the v1 triad. The lint checks citation PRESENCE, not value-consistency — so the stale number passed the gate.

### Defense layers + intelligence — built, mostly need wiring not building
- L2 Qwen3Guard Featherless adapter: correct moderation-template render + raw `/completions` POST + tri-level mapping + REVIEW-cap (39/39). The gate-before-trust insight (Featherless serves a generic chat template; must build the prompt explicitly) is already encoded.
- L3 AlignmentCheck (describing-vs-executing, deepseek-v4-pro), grounding verifier (pure-JS), Spotlighting envelope + `lint:spotlight` CI lint: all real (26/26).
- `classifyBatched` single-call path built+tested (1 fetch for 4 lenses) — just not wired into the pipeline.
- STIX 2.1 export real+wired+tested (5/5). Sealed 5-persona Red-Team real+sealed (9/9). delta_chain real+consumed by Monitor (40 assertions green).

---

## 3. GATE-BEFORE-TRUST RESULTS

All ten external surfaces were probed. Headline verdicts + the exact facts and blockers.

### AI/ML API (aimlapi.com) — REACHABLE (HTTP 200, 603 models) — model ids ARE REAL
- **Confirmed live (HTTP 200, env var `AIML_API_KEY`):** `deepseek-v4-flash` and `deepseek-v4-pro` (both bare AND `deepseek/`-prefixed forms resolve; use docs-canonical prefixed form). 1M context, released 2026-04-24. Base: `https://api.aimlapi.com/v1`, chat `/chat/completions`, embeddings `/embeddings`.
- **Embeddings for dedup:** `text-embedding-3-small` (1536d) / `text-embedding-3-large` (3072d) live; multilingual `qwen-text-embedding-v4` live.
- **Nemotron "free tier" nuance (gate-before-trust catch):** the global Free Tier PROGRAM is PAUSED, BUT the per-model variant `nemotron-3-nano-omni-30b-a3b-reasoning:free` IS live at $0/M — **the `:free` suffix is load-bearing, do NOT drop it**. Non-free fallback `nemotron-nano-9b-v2` (128k) live. **All Llama-Guard variants are deprecated/removed on AI/ML** — the L2 guard belongs on Featherless, not here.
- **Blocker:** docs table marks some Nemotron ids "Coming Soon" while they resolve live — pin to ids that returned and re-probe at wire time.

### Featherless (L2 guard) — PARTIAL — Qwen3Guard LIVE, template gotcha CONFIRMED
- **`Qwen/Qwen3Guard-Gen-8B` is LIVE** (3× HTTP 200, `https://api.featherless.ai/v1/chat/completions`, apache-2.0, gated:false). Promo `WEBDATA26`.
- **CRITICAL adapter gotcha (revises stale note):** a naive chat POST does NOT yield the verdict — Featherless serves a GENERIC Qwen3 chat assistant, not the guard's moderation chat-template. `enable_thinking:false` → "I cannot assist with that request." (assistant refusal); thinking-on → output goes to `message.reasoning`, never reaches a `Safety:` line. **The adapter MUST build the full moderation prompt explicitly** (Task + policy + 9 categories + output-format) and parse plain text `Safety: Safe|Unsafe|Controversial` then `Categories:`. Parse regex `r'Safety: (Safe|Unsafe|Controversial)'`. **The repo adapter already does this correctly.**
- **Two-axis FP-gate roster is single-confirmed:** `gpt-oss-safeguard-20b` is NOT on Featherless (CRAWL_NOT_FOUND); `AprielGuard-8B` is absent-but-requestable (>100 downloads); `Llama-Guard-3-8B` has a Featherless page but is un-probed. Do NOT claim a multi-guard methodology until each candidate is probed.

### Bright Data — REACHABLE — Web Unlocker zone LIVE (token valid, HTTP 200)
- One read-only Web Unlocker call returned HTTP 200 with real geo JSON. `BRIGHT_DATA_TOKEN` VALID.
- **Confirmed:** Web Unlocker/SERP/Scraper all POST `https://api.brightdata.com/request` `{zone,url,format}`. Web Scraper async trigger `POST /datasets/v3/trigger?dataset_id=gd_…&type=discover_new&discover_by=…` → `{snapshot_id}`. Scraping Browser is CDP over `wss://…@brd.superproxy.io:9222`. MCP: `@brightdata/mcp`, free tier 5,000 req/mo.
- **$250 promo code is `unlocked`** (Billing → Overview). NOT to be conflated with Featherless `WEBDATA26`.
- **Blockers (probe before P2/P4):** (1) `/datasets/v3/progress/{id}` exact path UNVERIFIED — repo `dataset-client.js` uses it but no primary doc pins it; (2) SERP zone + Browser WSS not independently probed (only Web Unlocker zone proven); (3) repo `dataset-client.scrape()` body shape `{input:[…]}` may need to be a raw array per current docs — a 400 would be silent until tested.

### Speechmatics (P3, 6th prize) — REACHABLE — KEY IS VALID
- **`SPECHMATICS_API_KEY` is VALID** — live read-only `GET https://eu1.asr.api.speechmatics.com/v2/jobs/?limit=1` returned HTTP 200 `{"jobs":[]}`. (Key is 32 chars in `secrets.env`.)
- **Batch is the right API:** POST multipart to `/v2/jobs/` with `config='{"type":"transcription","transcription_config":{...}}'` → poll `/v2/jobs/:id` (running|done|rejected) → GET `/v2/jobs/:id/transcript?format=json`. Auth `Authorization: Bearer`. Finance tuning: `domain:'finance'`, `diarization:'speaker'`, `enable_entities:true`, `operating_point:'enhanced'`. Free tier 480 min/mo. **7-day data retention — seal-and-store immediately.** No blockers.

### TriggerWare — REACHABLE — KEY IS VALID — it is a REAL product
- **What it IS:** TriggerWare.ai by CalQLogic (LA, founded 2017) — a cloud virtual-database / real-time analytics platform ("SQL Over Everything", NL→SQL, MCP server). NOT a webhook-only layer. **Prize:** "Best Use of Automated Workflows" ($300 GC + 5,000 tokens/mo × 12mo).
- **Key VALID:** `GET https://api.triggerware.com/api-keys` with `TRIGGERWARE_API_KEY` returned HTTP 200 + valid JSON array. Auth header `Api-Key:`. Repo `src/trigger/triggerware-client.js` is already correctly wired endpoint-for-endpoint.
- **Model is POLL-based:** triggers are named scheduled queries; poll `POST /triggers/{name}/poll` → `{added:[],deleted:[]}`; schedule is integer seconds. Maps onto the react loop.
- **Stale comment to fix (not a blocker):** `monitor.js:3-4` says "su API no es pública aún" — now FALSE; the API is public, documented at `docs.triggerware.com`, and the key authenticates.

### Cognee — REACHABLE — tenant endpoint false-negative RESOLVED
- **Live (one read-only call, 2026-05-30):** `GET https://api.aws.cognee.ai/api/v1/tenants/current/service-url` with `X-Api-Key` → HTTP 200, resolved the real tenant URL `https://tenant-<uuid>.aws.cognee.ai`. **The prior false-negative is decisively resolved: the programmatic surface is the tenant host, not the platform SPA.**
- **TEMPORAL KG is first-class & current:** `POST /api/v1/search` accepts `search_type:'TEMPORAL'` (+ GRAPH_COMPLETION default, RAG_COMPLETION, etc.). `GET /api/v1/visualize?dataset_id=<uuid>` returns interactive HTML graph (the demo's temporal-graph scene is real, not roadmap).
- **Two repo↔docs mismatches to reconcile before building:** (a) AUTH — repo `CogneeCloudClient` sends+requires `X-Tenant-Id`; docs+live use `X-Api-Key` ONLY (tenant is in the URL host) → drop the spurious `X-Tenant-Id`; (b) INGEST — repo uses `/api/v1/add_text`; docs show `/api/v1/add` (or one-call `/api/v1/remember`) → verify against the tenant's own `/docs` Swagger.
- **Blocker:** `COGNEE_API_URL` + `COGNEE_TENANT_ID` are NOT set in `secrets.env` (only `COGNEE_API_KEY`). Cloud opt-in cannot run until `COGNEE_API_URL` is populated (resolvable from the key). Local MCP path is the default and is built (`~/.cognee/cognee-mcp`); not re-probed this session (heavy cold start 12-25s).

### Kiro — REACHABLE (docs, Feb-May 2026) — hooks API CONFIRMED — NO native on-commit
- **TWO hook systems — do not conflate.** Use **IDE hooks**: individual JSON files `*.kiro.hook` under `.kiro/hooks/`, schema `{enabled, name, description, version, when:{type, patterns[]}, then:{type, prompt|command}}`. (CLI hooks are a different `hooks` object in agent-config — NOT this use case.)
- **`when.type` enum (10):** `fileCreate | fileEdited | fileDelete | promptSubmit | agentStop | preToolUse | postToolUse | preTaskExecution | postTaskExecution | userTriggered`. The canonical JSON value for file-save is **`fileEdited`** (not `fileEdit`). `then.type` is exactly two: `askAgent` (prompt, consumes credits) | `shellCommand` (command, free+deterministic — prefer this for `node --test`/audit/verify).
- **CRITICAL: there is NO native `on-commit`/`gitCommit` event.** on-save → `fileEdited`. The roadmap's "on-commit" must map to `agentStop` (the canonical Kiro pre-commit-scanner example), `userTriggered` (manual), or a real git pre-commit hook OUTSIDE Kiro. **Do NOT invent `onCommit`.**
- **Specs are subdirectories:** `.kiro/specs/<slug>/{requirements.md,design.md,tasks.md}` (EARS format "WHEN … THE SYSTEM SHALL …" in requirements.md). The roadmap's `.kiro/specs/v2/{…}` triplet is VALID. The repo's existing flat `.kiro/specs/*.md` files are NON-canonical and won't drive Kiro's task UI.
- **Blocker:** no live binary probe possible (Kiro is local file conventions, not a network API; not installed here). Confidence rests on kiro.dev docs cross-checked against 3+ real `.kiro.hook` files on GitHub.

### C2PA / CAWG — REACHABLE — one roadmap FACTUAL ERROR found
- **c2patool 0.26.60 INSTALLED** (`/home/thelinconx/.cargo/bin/c2patool`), at/ahead of public head (crates.io 0.26.59). Natively supports CAWG x509 (`--identity-signer-path`, `[cawg_x509_signer]`, `trust` subcommand). No upgrade needed.
- **ROADMAP FACTUAL ERROR (line 38):** the CAWG Organizational Identity Profile was NOT "ratified Dec 2025" — it was **DIF-ratified 05 Feb 2026 (v1.0)**. Profile v1.0 requires C2PA 2.2 OR 2.3 (NOT "or later"), CAWG Identity Assertion 1.2, Metadata Assertion 1.1. **Fix this copy before any slide/HONESTY claim ships.** C2PA spec head is now 2.4 (April 2026).
- Repo `c2pa.js` already emits a structurally spec-shaped `cawg.identity` assertion (`cawg.x509.cose`, EKU `1.3.6.1.5.5.7.3.36`) honestly caveated as self-signed/UNTRUSTED. Posture correct.

### Sigstore Rekor v2 — REACHABLE — offline verify is SHIPPED (not phase-2)
- The offline verifier (`src/prove/rekor.js verifyRekorBundle`) runs fully offline; 13-test suite passes against a REAL bundle (logIndex 4729698). RFC 6962 §2.1.1 reconstruction + C2SP checkpoint key-id formula both match spec. The "shipped vs Reef phase-2" claim is ACCURATE and tested.
- Live shard `log2025-1.rekor.sigstore.dev/api/v2/checkpoint` → HTTP 200 (treeSize 4757363 at probe). Pinned key matches.
- **Two cheap follow-ups (non-blocking):** (1) normalize monitor/HONESTY checkpoint path `/checkpoint` → spec-canonical `/api/v2/checkpoint` (both 200 today); (2) plan additive re-pin when Sigstore turns down the 2025 shard for a 2026 instance — the monitor catches rotation via `'rotated'` exit 2.

### Grounding research citations — REACHABLE — 8/8 REAL, two cosmetic edits
- **All 8 arXiv refs verified real, none fabricated.** Use as-is. Exact ids: `2511.22047` (Qwen3Guard 91.0%→33.8% on novel prompts), `2605.28830` ("larger is not safer"), `2605.00689` (`ML-Bench&Guard` — write the ampersand), `2505.03574` (LlamaFirewall AlignmentCheck), `2512.20293` (AprielGuard), `2403.14720` (Spotlighting, Hines et al.).
- **Two completeness edits:** (a) "Bag of Tricks" has NO id in the roadmap — **add `arXiv:2510.11570`**; (b) `gpt-oss-safeguard` is NOT an arXiv paper — cite the OpenAI blog / HF card (OpenAI, Oct 2025, Apache 2.0).

### Local toolchain + secrets — REACHABLE — GREEN
- node v24.14.1, c2patool 0.26.60, Chromium 148 + Playwright pack, OpenSSL 3.6.2 with `openssl ts`, Rekor offline shipped. **All four seal verifiers present.**
- **All seven sponsor keys present** (names only): `BRIGHT_DATA_TOKEN`, `AIML_API_KEY`, `FEATHERLESS_API_KEY`, `MINIMAX_API_KEY`, `SPEECHMATICS_API_KEY`, `COGNEE_API_KEY`, `TRIGGERWARE_API_KEY`. Plus BD surface zones/ids. `secrets.env` chmod 600, outside repo.

---

## 4. BUILD PLAN P0 → P4

Dependency-ordered. Each task: goal · files · acceptance test · sponsor/track · size (S/M/L) · risk.
Tasks already satisfied are marked **[DONE]**. Honor the roadmap sequence.

### P0 — Honesty + seal surfacing (hours; do FIRST)

**P0.1 — Wire C2PA + Rekor sidecars into the Evidence Report** (the surviving P0 known-gap)
- Goal: make the Rekor+C2PA rows LOAD-BEARING in every reproducible build; the code is correct, only callers omit the sidecars.
- Files: `api/report.js` (pass `c2paSidecar`/`rekorBundle`), `scripts/gen-sample-report.mjs`, a NEW committed hero generator (e.g. `scripts/gen-hero-report.mjs`) that wires evidence + `samples/synthex-hero.c2pa.json` + the rekor anchor.
- Acceptance: running the committed generator produces a PDF where `sealRows` emits the Rekor logIndex (4756641) + C2PA row on page 1 AND the verify page renders all 3 verifications (not the "Not present" branch). A new test asserts the present-path (`buildPDFReport` WITH sidecars → page contains Rekor+C2PA markers).
- Sponsor/track: Security & Compliance (primary). Size: M. Risk: PDFKit subset-CID fonts make string-grep on the PDF return 0 hits — assert by calling `sealRows`/page fns in-process, NOT by grepping the PDF.

**P0.2 — Fix the verify-page commands + emit the sidecar evidence.json**
- Goal: the report instructs commands a judge can actually run.
- Files: `src/prove/report/page-verify.js` (the headline `synthex verify evidence.json` does NOT exist — either add the CLI verb in `bin/synthex.mjs` or change copy to the real `synthex c2pa-verify`/`rekor-verify`); fix the c2patool command (the JSON sidecar is bespoke `synthex-c2pa-sidecar-v1`, only `synthex c2pa-verify` reads it — c2patool interop is proven only on the PNG Evidence Card); fix filenames (`evidence.c2pa.json` vs emitted `<evidence>.c2pa.json`, `synthex-rekor-anchor.json`). Add a sidecar `<reportId>.evidence.json` emitter alongside the PDF.
- Acceptance: every command printed on the verify page runs successfully against the emitted files; sidecar evidence.json with full (non-truncated) values is written by the build path.
- Sponsor/track: Security & Compliance. Size: M. Risk: deciding add-`verify`-verb vs reword — see Open Questions.

**P0.3 — Reconcile stale numbers + caveats across all public surfaces**
- Goal: every public number matches its cited source; no uncaveated court claim.
- Files: `public/index.html` (lines ~675, 750: `2/5`→`3/5`; line 679 + og:description: "court-verifiable"→caveated or "third-party-verifiable"; honesty list ~867-872: ADD C2PA-self-signed + multi-TSA-not-eIDAS), `SLIDES.md` (slides 1/5/13 FP; slides 1/3/6 court claim), `docs/HONESTY.md` §8 (180,185 `2/5`→`3/5`), `README.md` (line 11 v1 triad → "Screen it · Seal it"; line 7 v0.9.0 stale). Canonical source `docs/guard-fp-measurement.md:74` already says `3/5 (60%)`.
- Acceptance: `npm run lint:slides` green AND a NEW value-consistency check (or manual grep) confirms no surface contradicts `guard-fp-measurement.md`; "court-verifiable" uncaveated → 0 occurrences; landing honesty list at parity with HONESTY §1.6/§10.9.
- Sponsor/track: cross-cutting (honesty moat). Size: S. Risk: `lint:slides` checks citation PRESENCE only, not value — a stale number passes the gate; fix the number AND consider a value-consistency lint.

**P0.4 — Reword HMAC framing in seal headers + method label**
- Goal: HMAC "never the headline" (roadmap principle 7).
- Files: `src/prove/evidence-report.js:67-73` `_composeMethod` (HMAC leads `seal.method` — reorder to lead Ed25519 or drop HMAC from the public label), `src/prove/hmac.js:1`, `evidence-report.js:1-2`, `evidence-card.js:4-5` (reword "base/load-bearing seal" → "internal checksum only"). Note `evidence-card.js:84` carries the method string into the card assertion.
- Acceptance: `seal.method` leads with Ed25519 (or omits HMAC from the public label); no header calls HMAC "base/load-bearing"; existing 131 prove tests stay green. Update the stale fixture `test/pdf-report.test.js:19` (`HMAC-SHA256 + RFC 3161 TSA`).
- Sponsor/track: cross-cutting. Size: S. Risk: `seal.method` is canonicalized into the seal pre-image — reordering it changes the bytes signed; regenerate fixtures, do NOT break back-compat tests for the 6-page v1 legacy fixture.

**P0.5 — Fix the CAWG ratification date copy** (roadmap factual error)
- Goal: don't ship a fact a reviewer can falsify.
- Files: anywhere "CAWG … Dec 2025" appears (HONESTY.md, slides). Correct to "DIF-ratified 05 Feb 2026 (v1.0); requires C2PA 2.2/2.3 + Identity Assertion 1.2".
- Acceptance: 0 occurrences of "ratified Dec 2025" for CAWG. Size: S. Risk: none.

### P1 — Three-tier defense core (the moat)

**P1.0 — L1 forge REVIEW-only — [DONE].** Met. No action beyond the cosmetic note (leaf fns return "BLOCK" label, downgraded at the call-site). Don't regress.

**P1.1 — L2 Featherless Qwen3Guard adapter — [DONE] (adapter only).** Adapter correct (39/39), moderation-template render + raw `/completions` POST already shipped. Remaining L2 work is the FP-gate (P1.2).

**P1.2 — Two-axis FP-gate (FP on benign + recall on novel injections)**
- Goal: the roadmap's mandatory SECOND axis. Today the gate is single-axis (benign FP only); BLOCK authority is granted on FP≤20% alone.
- Files: NEW labeled novel-injection corpus under `test/fixtures/` (OWASP/ATLAS-mapped injection packs + a "Bag of Tricks" format-manipulation set), extend `scripts/measure-guard-fp.mjs` (or NEW `scripts/measure-guard-recall.mjs`) to compute recall + joint winner selection, add `npm run fp-gate`/`bench:guard` to `package.json`.
- Acceptance: a reproducible harness reports BOTH benign FP% AND recall% on the labeled set for Qwen3Guard; BLOCK authority granted ONLY to a winner that bounds FP while maximizing recall, else all-REVIEW (stated). Anchor labels on `AML.T0051`/`.001` (indirect injection).
- Sponsor/track: Featherless (open-model selection methodology); Security. Size: L. Risk: only Qwen3Guard is confirmed-live on Featherless — do NOT claim multi-guard until `Llama-Guard-3-8B` is probed (P1.2a); hosted inference is non-deterministic (FP swings 40-60% on n=5) — corpus must be ≥ a real size to make a joint decision stable.

**P1.2a — Probe additional Featherless guards** (S, gate-before-trust): one cheap call each to `Llama-Guard-3-8B` (page-present), request `AprielGuard-8B`. Only add confirmed-live guards to the roster.

**P1.3 — Wire `classifyBatched` as the bulk default**
- Goal: realize the "4 lenses BATCHED into one call" cost win (currently dead — pipeline issues 4 calls/doc).
- Files: `src/pipeline.js:331-339` (switch `lens==='all'` to `classifyBatched`, KEEP per-lens `classify()` as the schema-isolation fallback).
- Acceptance: a test asserts the `lens==='all'` path issues exactly 1 fetch for 4 lenses; per-lens isolation fallback still covered. Default model `deepseek/deepseek-v4-flash` (probe-confirmed live).
- Sponsor/track: AI/ML (intelligence prize). Size: S. Risk: must preserve per-lens fallback or the "one bad lens can't corrupt others" guarantee weakens.

**P1.4 — Nemotron positioning decision** (S; needs Pablo — see Open Questions): repo REMOVED Nemotron in v1.0.0; probe found `nemotron-3-nano-omni-30b-a3b-reasoning:free` live ($0/M, `:free` suffix load-bearing). Either re-add the verified `:free` id OR drop the Nemotron requirement from the v2 target. Update `HONESTY.md:148` + `tiers.test.js` accordingly.

**P1.5 — L3 false-BLOCK measurement** (S): `scripts/measure-l3-falseblock.mjs` exists but is UNMEASURED (`AIML_API_KEY` now confirmed present + key valid). Run it; record the benign false-BLOCK number for the layer with real BLOCK authority. Acceptance: a measured L3 FP number lands in `guard-fp-measurement.md` with a reproduce command. Risk: n=5 corpus is "indicative, not robust" — scale alongside P1.2's corpus.

**P1.6 — Wire lint:spotlight + node --test into CI/Kiro** (S): currently neither is gated. Add to a GitHub Actions workflow AND/OR the Kiro on-save hook (P2.K). Acceptance: a PR that adds an unwrapped LLM egress fails the gate. Risk: the lint is a regex heuristic — a non-fetch SDK transport would be invisible (documented limitation).

### P2 — Enterprise artifacts + multi-track + sponsors

**P2.1 — `runPipeline` defaults to the full Ed25519 seal**
- Goal: fix the symmetric-only default (the highest-impact correctness gap). `runPipeline` never calls `resolveSigningKey`; watch.js + MCP `tools.js` seal HMAC-only.
- Files: `src/pipeline.js` (resolve + pass `signingKey` by default), `src/watch.js:40`, `src/tools.js:39`.
- Acceptance: empirical — `runPipeline` with no explicit key produces `seal.method` leading Ed25519 (resolved from XDG default) when a key is configured; the react/monitor + MCP paths seal with Ed25519. CLI/demo already pass keys.
- Sponsor/track: cross-cutting (every artifact carries the real seal). Size: M. Risk: ephemeral keys break delta_chain continuity (`asymmetric.js:185` refuses ephemeral default) — resolve persistent key, do NOT auto-generate ephemeral in the default path.

**P2.2 — Seal the Bright Data surface + ids in `decisions[]`**
- Goal: the roadmap's "seal which surface + ids" — today NO surface is sealed; the report's "Surface" column is a URL-regex guess.
- Files: `src/pipeline.js:434` (extend `payload.sources` beyond `d.url` to carry surface/zone/datasetId/snapshotId), `decisions[]` rows, `src/prove/report/page-data-bom.js:18-24` (replace `surfaceOf` heuristic with the sealed fact). Remove `surface_status` from `HMAC_EXCLUDED_KEYS` only if it becomes a sealed fact (currently excluded so KG variance doesn't fake a change — be careful).
- Acceptance: a sealed evidence artifact has surface+ids inside the canonical pre-image; the Data-BOM page renders the SEALED surface, not a guess; the honesty note "no live surface is sealed" is removed because it's now true.
- Sponsor/track: Bright Data (judges; the "built on production infrastructure" proof). Size: L. Risk: requires fetchers to return surface metadata; the default path only reaches Web Unlocker + SERP — wire `smartFetcher` + dataset/browser clients into a real run first.

**P2.3 — Bright Data spectrum: wire ≥3 surfaces into a real run**
- Goal: ≥3 surfaces genuinely used + sealed (target full set). Today only Web Unlocker + SERP via `defaultFetch`.
- Files: `src/tools.js`/`bin/synthex.mjs` (pass `smartFetcher`/dataset client instead of bare `runPipeline`), `src/fetch/dataset-client.js` (wire `triggerDiscoverNew`/`collect`), `src/fetch/browser-client.js`.
- Acceptance: a run using SERP + Web Scraper dataset + Scraping Browser (or discover_new) produces sealed evidence tagged with each surface. Probe the 3 BD blockers first (progress path, SERP zone, body shape).
- Sponsor/track: Bright Data. Size: L. Risk: billing — `MAX_INPUTS=2` cap; discover_new dataset may lack the discovery collector (HONESTY §10.6) — fall back to plain async trigger, declare honestly.

**P2.4 — Cognee recall on re-scrape + delta→Cognee ingest**
- Goal: the headline Cognee gap — recall() has zero call sites; Cognee is write-only; `kg_status` never "ingested".
- Files: `src/watch.js`/`src/trigger/monitor.js` (call `cogneeClient.recall({target,lens})` before re-scrape, surface prior sealed evidence), `src/delta/chain.js` (set `kg_status:'ingested'` after a successful `cogneeSink`), unify the watch(sinks) + monitor(delta) paths. Reconcile `CogneeCloudClient` to docs (drop `X-Tenant-Id`, `/api/v1/add`, `search_type:'TEMPORAL'` for the temporal demo). Populate `COGNEE_API_URL` from the key.
- Acceptance: a re-scrape recalls prior sealed evidence from Cognee; the sealed delta reflects `kg_status:'ingested'`; the temporal-graph demo renders via `/api/v1/visualize`.
- Sponsor/track: Cognee (agent-memory prize); Finance/GTM. Size: L. Risk: local MCP cold start 12-25s (warmup script needed for demo); cloud opt-in blocked until `COGNEE_API_URL` set.

**P2.5 — TriggerWare react loop: live demo + BD discover_new glue**
- Goal: make the loop demo-able and (stretch) feed BD discover_new instead of only TriggerWare polling.
- Files: `bin/synthex.mjs` (NEW `react`/`watch` verb — none exists), `demo/demo.js` (a live trigger scene), `src/reactor.js`/`src/watch.js` (optional: adapter mapping BD `collect()` rows → `deriveTarget`). Fix `monitor.js:3-4` stale comment.
- Acceptance: a CLI verb runs the poll→delta→fire→seal→alert loop on a real trigger (key valid); CaMeL gate fires; the trigger name + delta are sealed.
- Sponsor/track: TriggerWare (automated-workflow prize). Size: M. Risk: `createTrigger`/`poll` request body shapes are admittedly guessed — live `createTrigger` may fail on field names; verify before the demo.

**P2.6 — Full seal stack on the Red-Team artifact + render into the report**
- Goal: the sealed Red-Team is HMAC+optional-Ed25519 only (`requestTsa:false`); make it a full-stack sealed artifact + render REDTEAM rows in the PDF.
- Files: `bin/synthex.mjs:491-534` (`requestTsa:true`; call c2pa-emit + rekor-anchor on the output), NEW `src/prove/report/page-redteam.js` (or extend an existing page to render REDTEAM_* rows + Top-3 board questions), add a benign-control red-team fixture + control-FP test.
- Acceptance: the red-team evidence verifies the same 4-way (Ed25519+TSA+Rekor+C2PA); the PDF shows the persona verdict + score band; a benign control does NOT score high.
- Sponsor/track: AI/ML (multi-agent reasoning showcase); Finance track. Size: M. Risk: band vs verdict are on DIFFERENT scales (band ≥80 CRITICAL; verdict ≥70 DO NOT PROCEED) — surface both without implying they're the same axis. Consilium "port" is N/A (personas authored fresh).

**P2.7 — Compliance matrix as a reusable sealed data module**
- Goal: matrix is inline per-page data; make it an exportable structure consumed by the report + (optionally) sealed.
- Files: NEW `src/prove/compliance-data.js` (port the structured Aegis `compliance.py` 6-framework/30+-control dataset to a JS data module), refactor `page-counsel.js`/`page-model-attestation.js` to consume it. Use CONFIRMED citations: EU AI Act Art 11 "Technical documentation", **Art 12 "Record-keeping"** (NOT "logging"), Art 13 "Transparency…"; NIST AI RMF GOVERN/MAP/MEASURE/MANAGE (MEASURE 2.5 anchor); `23 NYCRR Part 500 (Second Amendment, eff. Nov 1, 2023)`; `SR 11-7 = OCC Bulletin 2011-12`; OWASP LLM 2025 ids; **OWASP Top 10 for Agentic Applications 2026** (ASI01-ASI10, NOT 2025); `MITRE ATLAS v5.6.0`, anchor `AML.T0051`/`.001`.
- Acceptance: matrix renders from the data module (no hardcoded RAG status that ignores evidence); a unit test asserts the framework citations match the canonical forms; add the missing riskScore unit test.
- Sponsor/track: Security & Compliance; GC page. Size: M. Risk: roadmap copy says Art 12 "logging" — fix to "Record-keeping" or a fact-check fails.

**P2.8 — Reverse-flow seal into Aegis** (M, ecosystem play): push Synthex's Ed25519+Rekor+C2PA seal UP into `apohara-aegis` (currently HMAC-chain only). Acceptance: an Aegis artifact carries the Synthex seal. Risk: cross-language (Python) — may be a documented roadmap item if time-boxed out. Cut before core.

**P2.K — Kiro QA team-buddy** (the `missing` area)
- Goal: real committed `.kiro/hooks/*.kiro.hook` files + the `.kiro/specs/v2/` triplet. (Section 7 seeds the spec.)
- Files: `.kiro/specs/v2/{requirements.md,design.md,tasks.md}` (subdirectory triplet, EARS), `.kiro/hooks/*.kiro.hook` (4 hooks), update `.kiro/steering/synthex-conventions.md` (stale: leads HMAC headline, cites Opus 4.7), README ("Kiro is our QA team-buddy; here is each hook").
- Hooks (use ONLY confirmed Kiro API):
  - `qa-on-save.kiro.hook` — `when.type:fileEdited` patterns `["src/**/*.js","!**/*.test.js"]`, `then.type:shellCommand` running `node --test` + `npm audit` (+ fp-gate once P1.2 ships).
  - `report-integrity.kiro.hook` — `when.type:fileEdited` on report source, `shellCommand` regenerating the report + failing on stale numbers / table overflow / missing Ed25519|C2PA|Rekor seal field.
  - `seal-verify-smoke.kiro.hook` — `when.type:fileEdited` on emitted artifacts, `shellCommand` running the 3-way (openssl/c2patool/rekor) + Ed25519.
  - `pre-commit-qa.kiro.hook` — `when.type:agentStop` (the ONLY honest approximation of "on-commit"; NO native git event), `shellCommand` re-running the suite before a commit.
- Acceptance: the four hook files are committed, each invokes a REAL command that exists (build P1.2's `fp-gate` + the report/seal scripts first — a hook calling a missing command is dead); README documents exactly what each catches.
- Sponsor/track: Kiro ("Best use of Kiro to speed up development"). Size: M. Risk: hooks are downstream of the scripts they call — sequence them after P0/P1/P2 scripts exist; do NOT claim a `gitCommit` trigger.

### P3 — Stretch expanders (if time; else documented as v2.1 roadmap)

**P3.1 — Speechmatics sealed transcript** (M): batch adapter (key VALID, free tier covers demos) → poll → canonicalize+seal the `results[]` word-timestamp array. Finance; 6th prize. Risk: 7-day retention — seal immediately. NEW `src/fetch/speechmatics-client.js`.
**P3.2 — Multimodal screening** (L): AI/ML + Scraping Browser rendered screenshot + DOM to catch CSS-hidden injections. Browser client returns text only today; needs `page.screenshot()` → vision classify. Stretch; cut first.
**P3.3 — SERP signal layer** (M): brand/credential-leak/regulatory monitoring as a sealed lens. GTM.
**P3.4 — CAWG org identity on the C2PA card** (M): use c2patool `--identity-signer-path`/`[cawg_x509_signer]` to go beyond self-signed. Roadmap, NOT shipped — keep the self-signed caveat until truly CA-rooted.

### P4 — THE EPIC STRESS TEST (capstone; LAST; only after pipeline green + report real)

**P4.1 — Build `scripts/stress/` + `npm run stress`**
- Goal: replace the flat throughput harness with the capstone. The existing harness has no seal-integrity, no tamper, no recall, no per-layer, no p99, no determinism, and its prior evidence has only HMAC+TSA (CANNOT prove the v2 headline).
- Files: NEW `scripts/stress/` (deterministic, versioned, one-command), `package.json` `stress` script, a published corpus manifest (hashed, versioned ≥1000 artifacts), a SEALED Stress Test Report (itself a Synthex evidence artifact — meta-proof), `results.json`.
- Dimensions (each with a reproduce command): (1) scale/throughput; (2) **seal integrity** — % independently verify (Ed25519+TSA+Rekor+C2PA) target 100% + inject K tampered → % detected target 100%; (3) two-axis guard FP + recall + per-layer L1/L2/L3 + layered-vs-single under format-manipulation (cite `2510.11570`); (4) cost $/1000 traced to architectural cause (dedup/layered/batching/O(1) seal); (5) latency p50/p95/p99 per stage; (6) determinism (same input → same content hash → same seal modulo timestamp).
- Acceptance: `npm run stress` reproduces; the report is sealed; 100% seal-verify + 100% tamper-detection reported (or the REAL numbers, honestly, with any gap explained); FP/recall/cost/latency each have a reproduce command; harness + corpus manifest published.
- Sponsor/track: ALL (the proof). Size: L. Risk: prior harness scales by array self-concatenation (duplicates — not a clean ≥1000 distinct corpus); `requestTsa:false` to avoid saturating DigiCert means stress evidence isn't fully sealed — the new harness MUST seal fully or honestly explain a sampled-TSA approach; cost is estimated not BD-billing-actual; needs live credits — gate the scale on the $250/$10/$25 budget (Open Questions).

---

## 5. RISK & GOTCHA REGISTER

**Correctness / wiring**
- **`runPipeline` symmetric-only by default** (CONFIRMED empirically): no `resolveSigningKey` import; no-key → `seal.method='HMAC-SHA256'`, `signature=null`. `watch.js:40` + `tools.js:39` seal HMAC-only. The CLI/demo pass keys; the MCP + react paths do not. → P2.1.
- **Evidence Report P0 fix is DARK**: `sealRows` is correct but NO caller passes `c2paSidecar`/`rekorBundle` → Rekor+C2PA silently vanish on every reproducible build. The fix is wiring, not building. → P0.1.
- **No surface is sealed**: `payload.sources = docs.map(d=>d.url)`; the report's Surface column is a URL-regex GUESS (`page-data-bom.js` self-admits "not a sealed fact"). → P2.2.
- **Cognee recall has zero call sites**: only `MemoryStore.recall` fires on re-scrape; Cognee is write-only; `kg_status` never "ingested". Three remember/recall surfaces share method names — easy to overclaim "Cognee recall works" from green tests that only cover the local store. → P2.4.
- **`seal.method` is in the canonical pre-image**: reordering it (P0.4) changes the signed bytes — regenerate fixtures, do NOT break the 6-page v1 LEGACY back-compat fixture (gen-sample-report runs `sign:false` + `EVIDENCE_SCHEMA_V2=0` on purpose).

**External / probe**
- **Featherless serves a generic chat template** — naive POST returns refusals/reasoning, NOT the `Safety:` verdict. Adapter must build the moderation prompt explicitly (already does). Featherless 503/429 capacity → bounded retry exists; hosted inference is non-deterministic (FP 40-60% on n=5).
- **Cognee tenant-endpoint false-negative RESOLVED**: the surface is `tenant-<uuid>.aws.cognee.ai` (resolve from key via `api.aws.cognee.ai/.../service-url`), NOT the platform SPA. Repo `CogneeCloudClient` sends a spurious `X-Tenant-Id` and uses `/add_text` (docs: `/add`) — reconcile.
- **Kiro has NO native on-commit/gitCommit trigger** — map "on-commit" to `agentStop`/`userTriggered`/external git hook. File-save is `fileEdited` (not `fileEdit`). Hooks calling not-yet-built scripts are dead — sequence after the scripts.
- **BD blockers**: `/datasets/v3/progress/{id}` path UNVERIFIED; SERP zone + Browser WSS un-probed (only Web Unlocker proven); `/scrape` body shape `{input:[…]}` may need to be a raw array (silent 400). Promo `unlocked` (BD) vs `WEBDATA26` (Featherless) — do not conflate.
- **CAWG date is wrong in the roadmap** (Dec 2025 → 05 Feb 2026). C2PA head is 2.4; the profile pins 2.2/2.3.
- **AI/ML Nemotron `:free` suffix is load-bearing**; global Free Tier program is PAUSED; Llama-Guard removed on AI/ML (guard belongs on Featherless).

**Environment / tooling**
- **PDFKit subset-CID fonts**: string-grep on a generated PDF returns 0 hits even for known text — verify content by calling `sealRows`/page fns in-process, NOT by grepping the PDF. (Also: PDFKit `lineBreak:false` + `doc.y` pitfall noted in prior Evidence Report work — table engine measures→grows→paginates; render-test every page.)
- **grep token-corruption in this env**: grep produced false hits/misses in recon (e.g. depth-3 finds missed `packages/backend/scripts/`; a false hit in `spotlight.test.js`). Confirm by Reading files, not trusting grep.
- **`node --test` directory arg footgun**: passing a bare directory (`test/forge/`, `test/redteam/`) reports a spurious `fail 1` / MODULE_NOT_FOUND on Node 24.14.1 — pass a glob (`'test/**/*.test.js'`) or explicit files. cwd resets between bash calls — use absolute paths.
- **`lint:slides` checks citation PRESENCE not value** — the stale `2/5` passed the gate while contradicting its own source. Consider a value-consistency lint.
- **Demo full-seal depends on an EPHEMERAL key** (`demo/demo.js:85`) — breaks delta_chain continuity; acceptable for demo, caveat it. `server.js` declares version `0.1.0` (stale vs package v1.0.0).

---

## 6. OPEN QUESTIONS FOR PABLO (decisions that change sequencing)

1. **Hard deadline + focused build hours?** The roadmap reserves ~500h but the real budget sets the cut line. P3+P2.8 are the first to drop; P4 needs the pipeline green first. Append the deadline to drive the checkpoint cuts.
2. **Stress-test target scale vs budget?** ≥1,000 sealed artifacts is the floor; 10,000 is the stretch. This is gated by BD $250 + AI/ML $10 + Featherless $25. What real scale do you want to fund, and is a sampled-TSA approach (to avoid saturating DigiCert) acceptable for the seal-integrity metric, or must 100% carry a live TSA?
3. **Nemotron: re-add or drop?** The repo deliberately removed it (v1.0.0). The probe found `nemotron-3-nano-omni-30b-a3b-reasoning:free` live ($0/M). Re-add the verified `:free` id for the L3/red-team free path, or update the v2 target to drop the Nemotron requirement? (Affects P1.4 + HONESTY/tests.)
4. **`synthex verify` verb: add it or reword the report?** The verify page's headline `synthex verify evidence.json` does not exist (only `c2pa-verify`/`rekor-verify`). Add a unifying `verify` verb (cleaner judge UX, more build) or reword the report to the real verbs (faster)? (Affects P0.2.)
5. **Which P3 stretch to keep if time-boxed?** Candidates by prize value: Speechmatics (6th prize, key valid, S/M effort) vs Multimodal (highest "wow", L effort, browser-screenshot work) vs SERP signal layer (GTM track). Pick at most one core; rest → v2.1 roadmap.
6. **Track priority?** All three tracks are claimable. Judges are Bright Data → P2.2/P2.3 (seal the spectrum) is the highest sponsor-fit lever. Confirm Security & Compliance stays primary, with Finance (Red-Team) + GTM (SERP/monitoring) as secondary.
7. **Cloud Cognee vs local-only for the demo?** Cloud needs `COGNEE_API_URL` set + the `X-Tenant-Id`/`/add_text` reconcile. Local MCP is the default but has a 12-25s cold start. Which backend carries the demo's temporal-graph scene?

---

## 7. KIRO `.kiro/specs/v2/` SEED

Bullet outlines for the three-file triplet (canonical subdirectory format; EARS in requirements.md). Uses ONLY the confirmed Kiro hooks API from the probe. Do NOT fabricate any `onCommit`/`gitCommit` trigger.

### `requirements.md` (user stories + EARS acceptance criteria)
- **R1 Seal surfacing**: WHEN an Evidence Report is generated with C2PA + Rekor sidecars, THE SYSTEM SHALL render the Ed25519, RFC 3161 TSA, Rekor v2, and C2PA rows on page 1 and all three verifications on the verify page.
- **R2 Honest numbers**: WHEN any public surface (landing/SLIDES/README/HONESTY) states a measured number, THE SYSTEM SHALL match the canonical source file, verified by a value-consistency check.
- **R3 Full default seal**: WHEN `runPipeline` runs with a configured signing key, THE SYSTEM SHALL seal with Ed25519 by default (not HMAC-only) on the CLI, MCP, and react/monitor paths.
- **R4 Two-axis guard gate**: WHEN the L2 guard is evaluated, THE SYSTEM SHALL measure benign FP AND recall on a labeled novel-injection corpus, and SHALL grant BLOCK authority only to a winner bounding FP while maximizing recall, else all-REVIEW (stated).
- **R5 Sealed surfaces**: WHEN content is fetched from a Bright Data surface, THE SYSTEM SHALL seal the surface name + zone/dataset/snapshot ids inside the canonical pre-image and render them (not a URL guess) in the Data-BOM.
- **R6 Cognee recall**: WHEN a monitored target is re-scraped, THE SYSTEM SHALL recall prior sealed evidence from Cognee and SHALL set `kg_status:'ingested'` on the sealed delta after a successful ingest.
- **R7 Stress proof**: WHEN `npm run stress` runs, THE SYSTEM SHALL produce a sealed Stress Test Report with seal-integrity %, tamper-detection %, two-axis FP/recall, per-layer contribution, cost/1000, and latency p50/p95/p99, each with a reproduce command.
- **R8 Kiro QA**: WHEN a source file is saved, THE SYSTEM SHALL run `node --test` + `npm audit` + the FP-gate via a committed Kiro hook and flag any regression.

### `design.md` (architecture, data, sequence)
- Seal stack (SHIPPED): Ed25519 + RFC 3161 TSA (DigiCert) + Rekor v2 offline (RFC 6962 + C2SP) + C2PA (COSE_Sign1 + x5chain). HMAC = internal checksum, never headline.
- Three-tier defense: L1 regex REVIEW-only → L2 Qwen3Guard-Gen-8B on Featherless (moderation-template adapter, plain-text parse, two-axis-gated BLOCK) → L3 AlignmentCheck (deepseek-v4-pro, describing-vs-executing) → grounding verifier (pure-JS) → Spotlighting envelope + lint.
- Intelligence: 4-lens batched classify on deepseek-v4-flash; deepseek-v4-pro spot; embeddings (`text-embedding-3-small`) for semantic dedup; Nemotron `:free` PENDING decision (Q3).
- Ingest spectrum sealed: Web Unlocker + SERP + Web Scraper API (discover_new) + Scraping Browser + Synthex-as-MCP; each surface tagged in `decisions[]`.
- Sponsor mapping: Bright Data = ingest; AI/ML = classify+L3+embeddings+personas; Featherless = L2; Cognee = memory (recall+delta_chain, CaMeL-gated, local default/cloud opt-in, `search_type:'TEMPORAL'`); TriggerWare = react (poll→delta→fire→seal→alert); Kiro = QA hooks.
- Compliance data module: structured EU AI Act Art 11/12("Record-keeping")/13 + NIST AI RMF + NYDFS Part 500 (2nd Amendment) + SR 11-7/OCC 2011-12 + OWASP LLM 2025 + OWASP Agentic 2026 (ASI01-10) + MITRE ATLAS v5.6.0 (AML.T0051/.001).
- Stress harness: deterministic versioned corpus (benign + labeled adversarial), full pipeline at concurrency, sealed report as meta-proof.

### `tasks.md` (discrete trackable tasks — mirrors §4)
- P0: [ ] wire C2PA+Rekor sidecars into report (P0.1) · [ ] fix verify-page commands + emit sidecar evidence.json (P0.2) · [ ] reconcile stale numbers/caveats (P0.3) · [ ] reword HMAC framing + method label (P0.4) · [ ] fix CAWG date (P0.5).
- P1: [x] L1 REVIEW-only (DONE) · [x] L2 adapter (DONE) · [ ] two-axis FP-gate + corpus (P1.2) · [ ] probe extra Featherless guards (P1.2a) · [ ] wire classifyBatched (P1.3) · [ ] Nemotron decision (P1.4) · [ ] measure L3 false-BLOCK (P1.5) · [ ] CI/Kiro lint+test gate (P1.6).
- P2: [ ] runPipeline full-seal default (P2.1) · [ ] seal BD surface+ids (P2.2) · [ ] wire ≥3 BD surfaces (P2.3) · [ ] Cognee recall + delta ingest (P2.4) · [ ] TriggerWare live loop + verb (P2.5) · [ ] full seal + report rows on Red-Team (P2.6) · [ ] compliance data module + citations (P2.7) · [ ] reverse-flow seal to Aegis (P2.8) · [ ] Kiro hooks + v2 spec + README (P2.K).
- P3: [ ] Speechmatics sealed transcript (P3.1) · [ ] multimodal (P3.2) · [ ] SERP signal layer (P3.3) · [ ] CAWG org identity (P3.4).
- P4: [ ] `scripts/stress/` + `npm run stress` + sealed Stress Test Report (P4.1).

### Hooks to author under `.kiro/hooks/` (confirmed API only)
- `qa-on-save.kiro.hook` — `when.type:fileEdited`, patterns `["src/**/*.js","!**/*.test.js"]`, `then.type:shellCommand`.
- `report-integrity.kiro.hook` — `when.type:fileEdited` on report source, `then.type:shellCommand` (regenerate + fail on stale/overflow/missing seal field).
- `seal-verify-smoke.kiro.hook` — `when.type:fileEdited` on emitted artifacts, `then.type:shellCommand` (3-way + Ed25519).
- `pre-commit-qa.kiro.hook` — `when.type:agentStop` (the honest "pre-commit" approximation — NO native git event), `then.type:shellCommand`.
- Update `.kiro/steering/synthex-conventions.md` (stale HMAC-headline + Opus 4.7 footer). Document each hook's catch in README.
