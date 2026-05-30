# Synthex v2.0.0 — Requirements

> **Spec format:** Kiro-native (`.kiro/specs/v2/`).
> **Status:** Planning. Source of truth for honesty: `docs/HONESTY.md`.
> **Source plan:** `docs/internal/V2_PLAN.md` (§4 build plan, §7 seed).
> **Owner:** Pablo M. Suárez (@SuarezPM) · MIT.

## What v2 is

v2 turns the already-shipped seal engine and three-tier defense from
*built-but-dark* into *load-bearing-by-default*. The crypto and the defense
layers exist and are tested at the engine level; v2 is mostly **wiring,
surfacing, and honest measurement**, not green-field building. Every
requirement below is derived from a measured gap in `V2_PLAN.md §1` and may be
verified against a named acceptance check.

## Honest framing (load-bearing)

These requirements inherit the forbidden-phrase list from
`.kiro/steering/synthex-conventions.md`: no "world's first", no "tamper-proof"
(use "tamper-evident"), no "replaces Triggerware" (use "extends with proof
layer"). HMAC is an **internal integrity checksum**, never the headline seal.
A capability is only asserted here when a gate-before-trust probe confirmed it
in `V2_PLAN.md §3`; anything unconfirmed carries a `TODO(verify)` and is NOT
stated as fact.

---

## R1 — Seal surfacing

**User story.** As a compliance reviewer, I want every reproducible Evidence
Report build to actually contain the full seal stack, so that the Ed25519,
RFC 3161 TSA, Rekor v2, and C2PA rows I see on screen are not silently dropped
on a clean rebuild.

**Context.** The `sealRows()` renderer is correct in code, but no caller of
`buildPDFReport` passes `c2paSidecar`/`rekorBundle`, so the Rekor + C2PA rows
vanish and the verify page falls to the "Not present" branch
(`V2_PLAN.md §2`, P0.1).

### Acceptance criteria (EARS)

- **R1.1** WHEN an Evidence Report is generated and both a C2PA sidecar and a
  Rekor bundle are supplied, THE SYSTEM SHALL render the Ed25519, RFC 3161 TSA,
  Rekor v2, and C2PA rows on page 1 of the PDF.
- **R1.2** WHEN an Evidence Report is generated with those sidecars, THE SYSTEM
  SHALL render all three independent verifications (Ed25519 / TSA, Rekor v2,
  C2PA) on the verify page, NOT the "Not present" branch.
- **R1.3** WHEN the committed hero generator runs, THE SYSTEM SHALL produce a
  PDF whose `sealRows` output includes the Rekor logIndex and the C2PA row.
- **R1.4** WHEN no C2PA sidecar or Rekor bundle is supplied, THE SYSTEM SHALL
  render the verify page's "Not present" branch for those rows and SHALL NOT
  fabricate a Rekor logIndex or C2PA assertion.
- **R1.5** WHEN the verify page prints a verification command, THE SYSTEM SHALL
  print only commands that exist in `bin/synthex.mjs` (or the real
  `c2patool`/`openssl ts`/rekor verbs) and SHALL emit a sidecar
  `<reportId>.evidence.json` with full, non-truncated values alongside the PDF.
- **R1.6** WHERE the PDF uses subset-CID fonts, THE SYSTEM SHALL be verified by
  calling `sealRows` and page functions in-process, NOT by grepping the
  rendered PDF (string-grep returns 0 hits even for present text).

---

## R2 — Honest numbers

**User story.** As a judge fact-checking the project, I want every public
number to match its cited source file, so that I cannot find a single
contradiction between the landing page, the slides, the README, and
`docs/HONESTY.md`.

**Context.** The L2 false-positive number is stale (`2/5` vs the canonical
`3/5 (60%)` in `docs/guard-fp-measurement.md:74`), "court-verifiable" is used
uncaveated, and the landing honesty list omits the C2PA-self-signed and
multi-TSA-not-eIDAS caveats (`V2_PLAN.md §2`, P0.3).

### Acceptance criteria (EARS)

- **R2.1** WHEN any public surface (landing, SLIDES, README, HONESTY) states a
  measured number, THE SYSTEM SHALL state the value that matches its canonical
  source file, verified by a value-consistency check (not only citation
  presence).
- **R2.2** WHEN the L2 guard false-positive rate is stated on any surface, THE
  SYSTEM SHALL state `3/5 (60%)` consistent with `docs/guard-fp-measurement.md`.
- **R2.3** WHEN a verifiability claim is made for the seal, THE SYSTEM SHALL
  caveat it (e.g. "third-party-verifiable") and SHALL NOT use "court-verifiable"
  uncaveated; the count of uncaveated "court-verifiable" occurrences SHALL be 0.
- **R2.4** WHEN the landing honesty list is rendered, THE SYSTEM SHALL include
  the C2PA-self-signed/untrusted caveat AND the multi-TSA-not-eIDAS-qualified
  caveat, at parity with `docs/HONESTY.md`.
- **R2.5** WHEN the CAWG profile is referenced, THE SYSTEM SHALL state
  "DIF-ratified 05 Feb 2026 (v1.0); requires C2PA 2.2/2.3 + Identity Assertion
  1.2" and SHALL NOT state "ratified Dec 2025"; that phrase SHALL appear 0 times.
- **R2.6** WHEN `npm run lint:slides` runs, THE SYSTEM SHALL pass; IF a number
  contradicts its canonical source, THEN the value-consistency check SHALL fail
  the build even though the citation is present.

---

## R3 — Full default seal

**User story.** As an operator running the pipeline through any entry point,
I want the default seal to be Ed25519 (not HMAC-only), so that the MCP server
and the react/monitor loop produce the same court-grade-caveated seal the CLI
already does.

**Context.** `runPipeline` never calls `resolveSigningKey`; `watch.js` and the
MCP `tools.js` seal HMAC-only. Only the CLI and demo pass keys explicitly
(`V2_PLAN.md §5`, P2.1).

### Acceptance criteria (EARS)

- **R3.1** WHEN `runPipeline` runs with a configured signing key resolvable from
  the XDG default, THE SYSTEM SHALL seal with Ed25519 such that `seal.method`
  leads with Ed25519 (HMAC framed only as the internal checksum).
- **R3.2** WHEN the react/monitor path (`watch.js`) seals an artifact, THE
  SYSTEM SHALL use the resolved Ed25519 signing key, not HMAC-only.
- **R3.3** WHEN the MCP server (`tools.js`) seals an artifact, THE SYSTEM SHALL
  use the resolved Ed25519 signing key, not HMAC-only.
- **R3.4** WHEN no persistent signing key is configured, THE SYSTEM SHALL fall
  back safely to the internal HMAC checksum and SHALL NOT auto-generate an
  ephemeral key on the default path (ephemeral keys break delta_chain
  continuity per `asymmetric.js`).
- **R3.5** WHERE `seal.method` is reordered to lead Ed25519, THE SYSTEM SHALL
  regenerate affected fixtures because `seal.method` is part of the canonical
  pre-image, and SHALL NOT break the v1 legacy back-compat fixture.

---

## R4 — Two-axis guard gate

**User story.** As a security lead, I want the L2 guard's BLOCK authority to be
justified by both a benign false-positive bound AND a recall measurement on a
labeled novel-injection corpus, so that we never grant blocking power to a
guard that silently misses real injections.

**Context.** Today the FP-gate is single-axis (benign FP only); BLOCK authority
is granted on FP ≤ 20% alone, with no recall axis and no labeled corpus
(`V2_PLAN.md §1`, P1.2). Only `Qwen/Qwen3Guard-Gen-8B` is confirmed live on
Featherless; other guards are unprobed.

### Acceptance criteria (EARS)

- **R4.1** WHEN the L2 guard is evaluated, THE SYSTEM SHALL measure benign
  false-positive rate AND recall on a labeled novel-injection corpus, and SHALL
  report both axes with reproduce commands.
- **R4.2** WHEN selecting a guard for BLOCK authority, THE SYSTEM SHALL grant it
  only to a winner that bounds benign FP while maximizing recall; OTHERWISE THE
  SYSTEM SHALL fall back to all-REVIEW and SHALL state that it did so.
- **R4.3** WHEN the labeled corpus is constructed, THE SYSTEM SHALL anchor
  labels on MITRE ATLAS `AML.T0051` / `AML.T0051.001` (indirect prompt
  injection) and include a "Bag of Tricks" (`arXiv:2510.11570`)
  format-manipulation set.
- **R4.4** WHILE only `Qwen/Qwen3Guard-Gen-8B` is confirmed live on Featherless,
  THE SYSTEM SHALL NOT claim a multi-guard methodology; additional guards
  (`Llama-Guard-3-8B`, `AprielGuard-8B`) SHALL be added to the roster only after
  a gate-before-trust probe confirms each is live.
- **R4.5** WHERE hosted inference is non-deterministic (benign FP observed to
  swing 40–60% at n=5), THE SYSTEM SHALL size the corpus large enough to make
  the joint FP/recall decision stable and SHALL state the corpus size.
- **R4.6** WHEN the L3 reasoner (the layer with real BLOCK authority) is
  measured, THE SYSTEM SHALL record its benign false-BLOCK number in
  `docs/guard-fp-measurement.md` with a reproduce command.

---

## R5 — Sealed surfaces

**User story.** As a Bright Data judge, I want the exact ingest surface and its
ids sealed inside the evidence, so that the report's "Surface" column is a
cryptographically sealed fact rather than a URL-regex guess.

**Context.** No surface is sealed: `payload.sources = docs.map(d => d.url)`, and
`page-data-bom.js` self-admits the surface column is "not a sealed fact"
(`V2_PLAN.md §2`, P2.2 / P2.3).

### Acceptance criteria (EARS)

- **R5.1** WHEN content is fetched from a Bright Data surface, THE SYSTEM SHALL
  seal the surface name plus its zone / dataset id / snapshot id inside the
  canonical pre-image of the evidence.
- **R5.2** WHEN the Data-BOM page renders, THE SYSTEM SHALL display the sealed
  surface fact and SHALL NOT derive the surface from a URL-regex heuristic.
- **R5.3** WHEN at least three distinct Bright Data surfaces (e.g. Web Unlocker,
  SERP, Web Scraper dataset / discover_new, Scraping Browser) are used in a run,
  THE SYSTEM SHALL produce sealed evidence tagged with each surface used.
- **R5.4** WHEN the surface fact is sealed, THE SYSTEM SHALL remove the honesty
  note "no live surface is sealed" because it is then true; UNTIL then the note
  SHALL remain.
- **R5.5** IF a fetched surface returns no surface metadata, THEN THE SYSTEM
  SHALL record the surface as unknown rather than guess, and SHALL NOT fabricate
  a zone, dataset id, or snapshot id.
- **R5.6** WHERE `surface_status` is in `HMAC_EXCLUDED_KEYS` to keep KG variance
  from faking a change, THE SYSTEM SHALL keep it excluded UNLESS the surface
  becomes a fully sealed fact, in which case the exclusion SHALL be reconsidered
  deliberately.

---

## R6 — Cognee recall

**User story.** As an agent-memory user, I want a re-scrape to recall prior
sealed evidence from Cognee before fetching again, so that the cross-time chain
is informed by graph memory and the delta records that the knowledge graph was
actually ingested.

**Context.** `recall()` has zero call sites in `src/`; Cognee is write-only and
`kg_status` is never set to `'ingested'`. The cloud client also sends a spurious
`X-Tenant-Id` and uses `/add_text` where docs use `/add` (`V2_PLAN.md §3/§5`,
P2.4).

### Acceptance criteria (EARS)

- **R6.1** WHEN a monitored target is re-scraped, THE SYSTEM SHALL call Cognee
  recall (target + lens) and SHALL surface prior sealed evidence before the
  re-fetch.
- **R6.2** WHEN a Cognee ingest succeeds for a sealed delta, THE SYSTEM SHALL set
  `kg_status: 'ingested'` on that sealed delta.
- **R6.3** WHEN Cognee is unreachable or skipped, THE SYSTEM SHALL set
  `kg_status` to `'unreachable'` or `'skipped'` with a `kg_skip_reason`, SHALL
  NOT block the hot path, and SHALL NOT report a fake content change (per the
  `HMAC_EXCLUDED_KEYS` guarantee).
- **R6.4** WHEN the Cognee cloud client authenticates, THE SYSTEM SHALL send
  `X-Api-Key` only (tenant carried in the resolved tenant-host URL) and SHALL
  NOT send `X-Tenant-Id`. <!-- TODO(verify): confirm /add vs /add_text against the tenant's own /docs Swagger at wire time -->
- **R6.5** WHEN the temporal-graph demo runs against the cloud tenant, THE SYSTEM
  SHALL use `search_type: 'TEMPORAL'` and render the graph via
  `GET /api/v1/visualize`.
- **R6.6** WHERE the local Cognee MCP path is the default, THE SYSTEM SHALL keep
  it as default and SHALL run `scripts/warmup-cognee.mjs` before a demo to
  absorb the 12–25s cold start; cloud opt-in SHALL remain blocked until
  `COGNEE_API_URL` is populated.

---

## R7 — Stress proof (capstone)

**User story.** As any sponsor judge, I want one reproducible command that
stress-tests the whole pipeline and emits a sealed Stress Test Report, so that
the headline numbers (seal integrity, tamper detection, guard FP/recall, cost,
latency) are themselves proven by a Synthex evidence artifact.

**Context.** The existing throughput harness has no seal-integrity, no tamper
injection, no recall, no per-layer split, no p99, no determinism check, and its
prior evidence carries only HMAC+TSA — so it cannot prove the v2 headline
(`V2_PLAN.md §1`, P4.1). This requirement is the capstone and is sequenced LAST.

### Acceptance criteria (EARS)

- **R7.1** WHEN `npm run stress` runs, THE SYSTEM SHALL execute the full pipeline
  at concurrency over a deterministic, versioned, hashed corpus of ≥1000
  distinct artifacts and SHALL write a `results.json`.
- **R7.2** WHEN the stress run completes, THE SYSTEM SHALL report the percentage
  of artifacts that independently verify across Ed25519 + RFC 3161 TSA + Rekor v2
  + C2PA, targeting 100%, and SHALL report the real number with any gap
  explained honestly.
- **R7.3** WHEN K tampered artifacts are injected, THE SYSTEM SHALL report the
  tamper-detection percentage, targeting 100%.
- **R7.4** WHEN the stress run completes, THE SYSTEM SHALL report two-axis guard
  FP and recall, per-layer L1/L2/L3 contribution, and layered-vs-single
  performance under format-manipulation (citing `arXiv:2510.11570`).
- **R7.5** WHEN the stress run completes, THE SYSTEM SHALL report cost per 1000
  artifacts traced to architectural cause (dedup / layering / batching / O(1)
  seal) and SHALL state which figures are estimated vs billing-actual.
- **R7.6** WHEN the stress run completes, THE SYSTEM SHALL report latency p50 /
  p95 / p99 per pipeline stage.
- **R7.7** WHEN the stress run completes, THE SYSTEM SHALL report a determinism
  check (same input → same content hash → same seal modulo timestamp).
- **R7.8** WHEN the Stress Test Report is emitted, THE SYSTEM SHALL seal it as a
  Synthex evidence artifact (meta-proof) and SHALL publish the harness plus the
  corpus manifest; each reported dimension SHALL carry a reproduce command.
- **R7.9** IF a live TSA cannot carry 100% of artifacts without saturating
  DigiCert, THEN THE SYSTEM SHALL either seal fully or honestly document a
  sampled-TSA approach for the seal-integrity metric. <!-- TODO(verify): final scale + sampled-TSA acceptability is gated on the BD/AIML/Featherless budget (V2_PLAN §6 Q2) -->

---

## R8 — Kiro QA

**User story.** As a developer using Kiro as the QA team-buddy, I want a saved
source file to automatically run the test suite, the audit, and the FP-gate via
committed Kiro hooks, so that a regression is flagged at save time without me
remembering to run anything.

**Context.** `.kiro/specs/v2/` and `.kiro/hooks/` did not exist; Kiro was a
one-shot spec executor (`V2_PLAN.md §1`, P2.K). Kiro hooks are individual
`*.kiro.hook` JSON files; there is **no native on-commit/gitCommit event** — the
"pre-commit" hook maps to `agentStop` / `userTriggered` / an external git hook.

### Acceptance criteria (EARS)

- **R8.1** WHEN a source file under `src/**/*.js` (excluding `*.test.js`) is
  saved, THE SYSTEM SHALL run `node --test` plus `npm audit` via a committed
  `fileEdited` Kiro hook and SHALL flag any regression. <!-- the FP-gate step is added once P1.2 ships its script -->
- **R8.2** WHEN report source is saved, THE SYSTEM SHALL regenerate the report
  via a `fileEdited` hook and SHALL fail on a stale number, a table overflow, or
  a missing Ed25519 / C2PA / Rekor seal field.
- **R8.3** WHEN an emitted evidence artifact is saved, THE SYSTEM SHALL run the
  three-way verification (openssl ts / c2patool / rekor) plus Ed25519 via a
  `fileEdited` hook.
- **R8.4** WHEN the agent stops (the honest approximation of "pre-commit", since
  Kiro has no native git event), THE SYSTEM SHALL re-run the suite via an
  `agentStop` hook before a commit, and SHALL NOT claim a `gitCommit` trigger.
- **R8.5** WHERE a hook invokes a shell command, THE SYSTEM SHALL prefer
  `then.type: shellCommand` (free + deterministic) over `askAgent` (consumes
  credits) for `node --test` / audit / verify steps.
- **R8.6** WHEN any hook is committed, THE SYSTEM SHALL ensure the command it
  invokes already exists (a hook calling a not-yet-built script is dead), so
  hooks SHALL be sequenced after the scripts they depend on.
