# Synthex v2.0.0 — Design

> **Spec format:** Kiro-native (`.kiro/specs/v2/`).
> **Status:** Planning. Pairs with `requirements.md` (R1–R8) and `tasks.md`.
> **Source plan:** `docs/internal/V2_PLAN.md` (§2 shipped, §3 probes, §4 plan).
> **Honesty source:** `docs/HONESTY.md`. Conventions:
> `.kiro/steering/synthex-conventions.md`.

## Design principle

The seal engine and the defense layers are **already built and tested** at the
engine level (`V2_PLAN.md §2`). v2 design is therefore about *data flow and
default wiring*, not new cryptography. Where a component is shipped, this doc
describes the contract it already honors; where it is dark, this doc describes
the wiring that makes it load-bearing by default.

---

## 1. Seal stack (SHIPPED)

The seal is a layered, independently-verifiable bundle. Each layer is real and
tested at the engine level (131/131 prove tests, `V2_PLAN.md §2`).

| Layer | What it is | Implementation | Trust posture |
|---|---|---|---|
| **Ed25519** | Asymmetric signature over the canonical pre-image; publishable `keyId` | `src/prove/asymmetric.js` | Headline seal |
| **RFC 3161 TSA** | Trusted timestamp; CMS chain + cert-validity + EKU `id-kp-timeStamping` pinned to DigiCert | `src/prove/tsa.js` | Third-party time anchor (NOT eIDAS-qualified) |
| **Rekor v2** | Offline transparency-log verify; RFC 6962 §2.1.1 Merkle reconstruction + C2SP checkpoint vs TUF-pinned log key | `src/prove/rekor.js` | Offline-verifiable inclusion proof |
| **C2PA** | Content Credentials as COSE_Sign1 with x5chain + EKU `id-kp-documentSigning`; CAWG `cawg.identity` assertion (EKU `1.3.6.1.5.5.7.3.36`) | `src/prove/c2pa.js` | **Self-signed / UNTRUSTED** (honestly caveated) |
| **HMAC-SHA256** | Internal integrity checksum | `src/prove/hmac.js` | **Internal only — never the headline** |

**Canonicalization.** The signed bytes are produced by RFC 8785 JCS
(`canonicalize()`) for schema v2+; v1 legacy routes to `JSON.stringify()`.
`seal.method` is part of the pre-image — reordering it to lead Ed25519 (R3.5,
P0.4) changes the signed bytes and requires fixture regeneration without
breaking the v1 legacy back-compat fixture.

**CAWG fact (corrected).** CAWG Organizational Identity Profile is
**DIF-ratified 05 Feb 2026 (v1.0)** and requires C2PA 2.2 OR 2.3 + CAWG Identity
Assertion 1.2 + Metadata Assertion 1.1. (NOT "ratified Dec 2025"; C2PA spec head
is 2.4, April 2026.) `c2patool 0.26.60` is installed and supports CAWG x509
natively. The card stays self-signed/UNTRUSTED until truly CA-rooted (P3.4).

**Seal-surfacing wiring (R1).** `sealRows()` is correct but dark: no caller of
`buildPDFReport` passes `c2paSidecar`/`rekorBundle`, so the Rekor + C2PA rows
silently vanish and the verify page falls to "Not present". The fix is to wire
the sidecars at the callers (`api/report.js`, the sample/hero generators) and
emit a `<reportId>.evidence.json` sidecar with full values.

---

## 2. Three-tier defense + verifiers

Layered screening, deterministic-first. Each layer narrows what the next sees;
only L3 holds real BLOCK authority. L1/L2 are REVIEW-capped.

```
ingest ─▶ L1 forge ─▶ L2 Qwen3Guard ─▶ L3 AlignmentCheck ─▶ grounding ─▶ Spotlighting ─▶ classify ─▶ seal
         (REVIEW)     (REVIEW-capped)   (BLOCK authority)    (drop figs)   (envelope+lint)
```

- **L1 forge — regex, REVIEW-only (DONE).** 78 DJL + 32 prefilter + 25 PII
  rules. Never BLOCKs a document; REVIEW-only is enforced at the pipeline
  call-site (`V2_PLAN.md §2`). Leaf functions still return a "BLOCK" label that
  is downgraded upstream (cosmetic). Pure `node:crypto` + regex, zero deps.
- **L2 Qwen3Guard — Featherless (adapter DONE).** `Qwen/Qwen3Guard-Gen-8B`,
  `https://api.featherless.ai/v1/chat/completions`. **Critical adapter shape:**
  Featherless serves a generic Qwen3 chat assistant, NOT the guard's moderation
  template — a naive POST yields a refusal (`enable_thinking:false`) or text in
  `message.reasoning` (thinking-on), never a `Safety:` line. The adapter MUST
  build the full moderation prompt explicitly (Task + policy + 9 categories +
  output-format) and parse plain text via `Safety: (Safe|Unsafe|Controversial)`
  then `Categories:`. The repo adapter already does this (39/39). BLOCK authority
  is gated on the two-axis FP+recall winner selection (R4); until then, L2 is
  REVIEW-capped.
- **L3 AlignmentCheck — describing-vs-executing.** `deepseek-v4-pro` via AI/ML
  API (`https://api.aimlapi.com/v1/chat/completions`). Distinguishes a document
  *describing* an injection from one *executing* it (the canonical sample BLOCKs
  an active injection while ALLOWing the OWASP cheat-sheet). This is the layer
  with real BLOCK authority, so its benign false-BLOCK rate is measured (R4.6).
- **Grounding verifier — pure-JS.** Drops fabricated figures the model could not
  have grounded in the source.
- **Spotlighting — envelope + lint.** Nonce-tagged Spotlighting envelope
  (Hines et al., `arXiv:2403.14720`) plus `lint:spotlight` CI lint that fails on
  an unwrapped LLM egress. The lint is a regex heuristic — a non-`fetch` SDK
  transport is invisible (documented limitation).

**Two-axis guard gate (R4).** A guard earns BLOCK authority only by bounding
benign FP while maximizing recall on a labeled novel-injection corpus
(ATLAS `AML.T0051`/`.001` + a `arXiv:2510.11570` "Bag of Tricks"
format-manipulation set). Hosted inference is non-deterministic (FP 40–60% at
n=5) so the corpus must be large enough for a stable joint decision; otherwise
the gate falls back to all-REVIEW and says so. Only `Qwen3Guard-Gen-8B` is
confirmed live on Featherless — no multi-guard claim until each candidate is
probed.

---

## 3. Intelligence — batched 4-lens classify

```
docs[] ──▶ classifyBatched(lens='all') ──▶ 1 fetch, 4 lenses ──▶ tiered verdicts
                    │
                    └─(fallback)─▶ classify(lens=X) per-lens isolation
```

- **Batched path.** `classifyBatched` issues exactly **one** `fetch` for all four
  lenses on `deepseek/deepseek-v4-flash` (probe-confirmed live, 1M context,
  released 2026-04-24, base `https://api.aimlapi.com/v1`). It is built and tested
  but not yet wired — the pipeline still issues 4 per-lens calls (R-derived from
  P1.3). Wiring it realizes the cost win.
- **Per-lens fallback (load-bearing).** `classify(lens=X)` per-lens calls stay as
  the schema-isolation fallback so one bad lens cannot corrupt the others.
- **Spot reasoning.** `deepseek-v4-pro` for L3 / deep spot checks.
- **Embeddings.** `text-embedding-3-small` (1536d) for semantic dedup
  (`text-embedding-3-large` 3072d and `qwen-text-embedding-v4` also live).
- **Nemotron `:free`.** `nemotron-3-nano-omni-30b-a3b-reasoning:free` probed
  live at $0/M — **the `:free` suffix is load-bearing**; the global Free Tier
  program is paused. <!-- TODO(verify): re-add the verified :free id vs drop the Nemotron requirement is a pending decision (V2_PLAN §6 Q3) -->
  All Llama-Guard variants are removed on AI/ML — the L2 guard lives on
  Featherless, not here.

---

## 4. Sealed Bright Data spectrum

Each ingest surface is tagged in `decisions[]` and sealed inside the canonical
pre-image (R5). All Web Unlocker / SERP / Scraper calls POST
`https://api.brightdata.com/request` `{zone, url, format}`.

| Surface | Transport | Sealed id(s) |
|---|---|---|
| Web Unlocker | `POST /request` (proven live, HTTP 200) | `zone` |
| SERP | `POST /request` | `zone` <!-- TODO(verify): SERP zone not independently probed --> |
| Web Scraper API (discover_new) | `POST /datasets/v3/trigger?dataset_id=gd_…&type=discover_new&discover_by=…` → `{snapshot_id}` | `dataset_id`, `snapshot_id` |
| Scraping Browser | CDP over `wss://…@brd.superproxy.io:9222` | session id <!-- TODO(verify): Browser WSS not independently probed --> |
| Synthex-as-MCP | `@brightdata/mcp` (free tier 5,000 req/mo) | surface tag |

**Sealing the surface (R5).** Today `payload.sources = docs.map(d => d.url)` and
the Data-BOM "Surface" column is a URL-regex guess. The design extends
`payload.sources` to carry `{surface, zone, datasetId, snapshotId}`, seals those
inside the pre-image, and replaces the `surfaceOf` heuristic in
`page-data-bom.js` with the sealed fact. `surface_status` stays in
`HMAC_EXCLUDED_KEYS` (so KG/surface availability variance does not fake a content
change) unless/until the surface becomes a fully sealed fact, decided
deliberately.

**BD blockers (probe before P2/P4).** `/datasets/v3/progress/{id}` exact path
unverified; SERP zone + Browser WSS un-probed; `/scrape` body shape `{input:[…]}`
may need to be a raw array (silent 400). Billing cap `MAX_INPUTS=2`. Promo code
is `unlocked` (Bright Data) — NOT to be conflated with Featherless `WEBDATA26`.

---

## 5. Sponsor mapping

| Sponsor | Role in the system | Surface |
|---|---|---|
| **Bright Data** | Ingest spectrum (each surface sealed) | Web Unlocker / SERP / Web Scraper / Scraping Browser / MCP |
| **AI/ML API** | Classify (4-lens batched) + L3 AlignmentCheck + embeddings + red-team personas | `deepseek-v4-flash` / `deepseek-v4-pro` / `text-embedding-3-small` |
| **Featherless** | L2 guard | `Qwen/Qwen3Guard-Gen-8B` moderation-template adapter |
| **Cognee** | Memory: recall + delta_chain, CaMeL-gated; local default / cloud opt-in | `search_type:'TEMPORAL'`, `/api/v1/visualize` |
| **TriggerWare** | React loop: poll → delta → fire → seal → alert | `POST /triggers/{name}/poll` → `{added,deleted}` |
| **Kiro** | QA team-buddy | `.kiro/specs/v2/` + `.kiro/hooks/*.kiro.hook` |
| **Speechmatics** (P3) | Sealed finance transcript | batch `POST /v2/jobs/` → poll → seal `results[]` |

---

## 6. Cognee memory + delta chain

```
re-scrape ─▶ cogneeClient.recall({target,lens}) ─▶ surface prior sealed evidence
          ─▶ normalize ─▶ hash ─▶ diff ─▶ seal delta ─▶ cogneeSink ─▶ kg_status:'ingested'
```

- **Recall wiring (R6).** `recall()` has zero call sites today; Cognee is
  write-only and `kg_status` is never `'ingested'`. The design calls recall
  before a re-scrape (in `watch.js` / `monitor.js`) and sets
  `kg_status:'ingested'` on the sealed delta after a successful `cogneeSink`,
  unifying the watch(sinks) and monitor(delta) paths.
- **Cloud client reconcile.** Send `X-Api-Key` only (tenant in the resolved
  tenant-host URL `https://tenant-<uuid>.aws.cognee.ai`, resolved from
  `GET https://api.aws.cognee.ai/api/v1/tenants/current/service-url`); drop the
  spurious `X-Tenant-Id`. <!-- TODO(verify): ingest path /add vs repo /add_text against the tenant's own /docs Swagger -->
- **Delta payload shape.** `delta_chain` is additive (schema v2.1), optional, and
  auto-detected by verifiers via `payload.delta_chain` presence
  (see `.kiro/specs/delta-engine.md`). `kg_status ∈ {ingested, skipped,
  unreachable}` with a `kg_skip_reason`. `HMAC_EXCLUDED_KEYS = [kg_status,
  kg_latency_ms, surface_status]` is normative so KG-availability variance never
  fakes a content change.
- **Hot/cold split.** Recall + remember run on the cold path (best-effort, 3s
  timeout); the deterministic normalize→hash→diff→seal hot path never blocks on
  Cognee. Local MCP cold start is 12–25s — `scripts/warmup-cognee.mjs` runs
  before demos. Cloud opt-in is blocked until `COGNEE_API_URL` is populated.

---

## 7. TriggerWare react loop

```
POST /triggers/{name}/poll ─▶ {added:[],deleted:[]} ─▶ deriveTarget ─▶ delta ─▶ CaMeL gate ─▶ seal ─▶ alert
```

TriggerWare (CalQLogic) is a poll-based virtual-database platform; triggers are
named scheduled queries, schedule is integer seconds, auth header is `Api-Key:`.
The repo client (`src/trigger/triggerware-client.js`) is wired
endpoint-for-endpoint and the key is valid. The trigger name + delta are sealed;
the CaMeL flow gate fires before any react action.
<!-- TODO(verify): createTrigger/poll request body field names are admittedly guessed; verify live before the demo -->
The stale `monitor.js:3-4` comment ("su API no es pública aún") is FALSE — the
API is public and the key authenticates.

---

## 8. Compliance data module

A reusable, exportable data structure (today the matrix is inline per-page),
consumed by the report pages and optionally sealed. Frameworks use only the
canonical citation forms confirmed in `V2_PLAN.md §4 (P2.7)`:

| Framework | Canonical citation |
|---|---|
| EU AI Act | Art 11 "Technical documentation", **Art 12 "Record-keeping"** (NOT "logging"), Art 13 "Transparency…" |
| NIST AI RMF | GOVERN / MAP / MEASURE / MANAGE (anchor MEASURE 2.5) |
| NYDFS | `23 NYCRR Part 500` (Second Amendment, eff. Nov 1, 2023) |
| Model risk | `SR 11-7 = OCC Bulletin 2011-12` |
| OWASP LLM | OWASP LLM 2025 ids |
| OWASP Agentic | **OWASP Top 10 for Agentic Applications 2026** (ASI01–ASI10, NOT 2025) |
| MITRE ATLAS | `v5.6.0`, anchor `AML.T0051` / `AML.T0051.001` |

The module renders the matrix from data (no hardcoded RAG status that ignores
evidence); a unit test asserts the citation forms match the canonical strings,
plus the missing `riskScore` unit test.

---

## 9. Stress harness shape (capstone)

```
versioned corpus (≥1000 distinct: benign + labeled adversarial)
   └─▶ full pipeline @ concurrency
        ├─ seal integrity %  (Ed25519+TSA+Rekor+C2PA verify) ─ target 100%
        ├─ inject K tampered ─▶ tamper-detection % ─ target 100%
        ├─ two-axis guard FP + recall + per-layer L1/L2/L3 + layered-vs-single
        ├─ cost/1000 traced to architectural cause
        ├─ latency p50/p95/p99 per stage
        └─ determinism (same input → same content hash → same seal modulo timestamp)
   └─▶ SEALED Stress Test Report (itself a Synthex evidence artifact — meta-proof)
   └─▶ results.json + published corpus manifest (hashed, versioned)
```

Deterministic, versioned, one-command (`npm run stress`). Each dimension carries
a reproduce command. Prior evidence had only HMAC+TSA, so the new harness must
seal fully (or honestly document a sampled-TSA approach to avoid saturating
DigiCert, R7.9). Cost is estimated unless traced to BD billing-actual; the scale
is budget-gated. This is sequenced LAST, after the pipeline is green and the
report is real.

---

## 10. Kiro QA hooks (design reference — files authored in a later task)

Kiro **IDE hooks** are individual JSON files `*.kiro.hook` under `.kiro/hooks/`,
schema `{enabled, name, description, version, when:{type, patterns[]},
then:{type, prompt|command}}`. Confirmed `when.type` enum (10):
`fileCreate | fileEdited | fileDelete | promptSubmit | agentStop | preToolUse |
postToolUse | preTaskExecution | postTaskExecution | userTriggered`. The
canonical file-save value is **`fileEdited`** (NOT `fileEdit`). `then.type` is
exactly two: `askAgent` (consumes credits) | `shellCommand` (free + deterministic
— preferred for `node --test` / audit / verify).

**CRITICAL:** there is **no native `on-commit` / `gitCommit` event**. The
"pre-commit" hook maps to `agentStop` (the canonical Kiro pre-commit-scanner
pattern), `userTriggered` (manual), or a real git pre-commit hook OUTSIDE Kiro.
Do NOT invent `onCommit`.

Planned hooks (authored later, after the scripts they call exist — see
`tasks.md` P2.K):

| Hook file | `when.type` | `then.type` | Catch |
|---|---|---|---|
| `qa-on-save.kiro.hook` | `fileEdited` (`["src/**/*.js","!**/*.test.js"]`) | `shellCommand` | `node --test` + `npm audit` (+ fp-gate once P1.2 ships) |
| `report-integrity.kiro.hook` | `fileEdited` (report source) | `shellCommand` | regenerate + fail on stale number / table overflow / missing Ed25519\|C2PA\|Rekor seal field |
| `seal-verify-smoke.kiro.hook` | `fileEdited` (emitted artifacts) | `shellCommand` | 3-way (openssl/c2patool/rekor) + Ed25519 |
| `pre-commit-qa.kiro.hook` | `agentStop` (honest "pre-commit" — NO native git event) | `shellCommand` | re-run the suite before a commit |

Hooks are downstream of the scripts they call: a hook invoking a missing command
is dead, so they are sequenced after P0/P1/P2 scripts exist. The steering doc
(`.kiro/steering/synthex-conventions.md`) is stale (leads HMAC headline, cites
Opus 4.7) and is updated in the same task; each hook's catch is documented in the
README.
