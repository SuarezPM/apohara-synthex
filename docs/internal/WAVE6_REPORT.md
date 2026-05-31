# Wave 6 — Pre-Push Audit Report

> Synthesis of Wave 6 adversarial review (6/6 stress dimensions accepted).
> Scope: the 11 Wave-6 commits staged on `main` (branch is 18 ahead of `origin/main`;
> HEAD `8d841ab`). Findings deduped and ranked by severity. Every "real" finding below
> was re-verified against the working tree (== HEAD) at report time.

## 1. Verdict

**FIX-FIRST.** 4 HIGH findings are confirmed real, three of them are honesty/integrity
defects on the project's declared single sources of truth (HONESTY.md canon, the public
slide deck, the compliance "source of truth" module) and the most visible production seal
path. None is a functional break, but together they violate the project's own honesty rule
("never add a capability claim without a gate-before-trust probe"). Land the 3 must-fix
HIGH items (and ideally the cheap NemoGuard/seal hardening) before pushing; the MEDIUM/LOW
set can ship as a fast-follow.

## 2. Stress dimensions — 6/6 accepted

| Dimension | Status | Notes |
|---|---|---|
| Cost | accepted | `scripts/stress/dimensions/cost.mjs` |
| Determinism | accepted | exposes the non-reproducible hero-PDF finding (M-2) |
| Guard efficacy | accepted | exposes the FP-denominator finding (H-1); `guard-efficacy.mjs` |
| Latency | accepted | `latency.mjs` |
| Seal integrity | accepted | corroborates the serverless HMAC-only finding (H-2) |
| Tamper detection | accepted | `tamper-detection.mjs` |

All six harnesses present under `scripts/stress/dimensions/` with mirrored `test/stress/*.test.js`.

## 3. Confirmed findings (ranked)

### HIGH

**H-1 — Fail-honest rule applied to recall but NOT to FP; unparsed benign replies fabricate BLOCK qualification.**
`scripts/stress/dimensions/guard-efficacy.mjs` `score()`. Unparsed benign replies (`v==null`)
are counted as clean ALLOWs in the FP denominator, so a guard that fails to parse on benign
content is rewarded with `fp→0` and `qualifies:true`, becoming eligible for BLOCK authority
(lines 226-230). Verified: `flagged(null)===false`; an all-unparsed-benign guard yields `fp=0,
qualifies:true`. The harness invariant (lines 15, 250) and the line-174 unparsed total only
cover catches, never the FP denominator.
**Fix:** compute fp over `benign.filter(r => r.v != null)`; surface `unparsed_benign` /
`unparsed_injection` as separate counts (replace the line-174 single total); gate
winner-qualification on a minimum parsed-benign coverage; add caveat that fp is valid only
when `unparsed_benign==0`. (Couples with L-1 below.)

**H-2 — Serverless live API still seals HMAC-only; the P2.1 "seal everywhere" fix skipped the most visible production path.**
Re-verified: `api/analyze.js:36` builds `{ lens, fetcher, hmacKey, requestTsa }` and
`api/stream.js:49` the SSE equivalent — **neither passes `signingKey` nor calls
`resolveSigningKey()`**. `buildEvidence` (`evidence-report.js:92`) gates Ed25519 on
`signingKey ? … : null`, so `synthex.apohara.dev` live mode seals **HMAC+TSA only** even when
`SYNTHEX_SIGNING_KEY` is set. Demo mode masks it (`demo.js:85` auto-generates an ephemeral
keypair). P2.1 (`3d21c4b`) wired only `watch.js:45` / `tools.js:42` / `bin/synthex.mjs`.
**Fix:** import `resolveSigningKey` in both `api/analyze.js` and `api/stream.js` and thread
`signingKey: resolveSigningKey()` into the live-mode opts.

**H-3 — ASI01 ships an INVENTED control title — "Agentic AI Threat (anchor)" instead of canonical "Agent Goal Hijack".**
Re-verified at `src/prove/compliance-data.js:229`. Directly contradicts the module's own
lines 14-16 canonical/verbatim promise; this module is the declared single source of truth
for the Counsel/Attestation pages. High-not-critical because it has no production consumers
yet (only its own test imports it) and the test does not assert the title verbatim.
**Fix:** set `title: "ASI01 — Agent Goal Hijack"` (confirmed verbatim across the official
2025-12-09 OWASP GenAI announcement and corroborating sources); remove the obsolete
`TODO(verify)` at line 233; add a test asserting the title contains "Agent Goal Hijack".

**H-4 — Public files (index.html, SLIDES.md) still claim "L3 = the ONLY BLOCK authority" — contradicted by HONESTY §8.A (NemoGuard QUALIFIES for BLOCK).**
Re-verified verbatim (working tree == HEAD): `public/index.html:675` and `:750`; `SLIDES.md:11`
and `:22` ("the **only** layer that holds real BLOCK authority"). `HONESTY.md:187` says
NemoGuard "QUALIFIES for BLOCK (the ≤ 20% bar)" and NemoGuard is now actually wired (P1.2,
`318f874`). The word "only" is false per the project's own canon. NOTE: the finding mislisted
README.md — README has **zero** such hits; loci are `index.html` + `SLIDES.md` only. The
`lint:slides` gate does NOT catch this (it checks numeric citation, not semantic consistency),
so this honesty regression slips the automated gate.
**Fix:** reword to "L3 + NemoGuard hold BLOCK authority" (NemoGuard is wired), or
"the only WIRED BLOCK authority today; NemoGuard earns it on measurement (§8.A)".

### MEDIUM

**M-1 — NemoGuard parser does not strip `<think>` blocks (asymmetric with the Qwen parser) — can over-block or fake a clean pass.**
Re-verified: `src/forge/nemoguard.js` has no reasoning-block removal, while
`injection-guard.js:148-149` strips `<think>…</think>` before matching (`parseQwen3Guard…`).
Probe A (`<think>… unsafe? No …</think>\n{"User Safety":"safe"}`) → NemoGuard returns
`verdict:'block'` (over-block); Probe B (`<think>… safe …</think>\n{"User Safety":"unsafe",…}`)
→ `verdict:'allow'` (the honesty-relevant fake clean pass). `scripts/measure-guard-recall.mjs:134`
reuses this parser, so measured FP/recall in `docs/guard-recall-measurement.md` are corrupted
by any reasoning preamble. Bounded: the `_FMT` prompt asks for one-line JSON and `<think>` is
unlikely in practice but not forbidden.
**Fix:** in `parseNemoGuardCompletion` strip `<think>…</think>` (or parse only the trailing
JSON / take the last match) before matching, mirroring `injection-guard.js:148-149`.

**M-2 — "Reproducibly regenerate" claim is false — the hero PDF is nondeterministic (live CreationDate + random /ID each run).**
Independently reproduced: 3 clean `node scripts/gen-hero-report.mjs` runs → 3 distinct
SHA-256s, none matching the committed hash. Root cause `src/prove/pdf-report.js:80-83` —
PDFDocument constructed with only `info:{Title,Author}`; no `CreationDate`/`ModDate`/`/ID`
pinned. The seal rows ARE genuinely load-bearing (in-process exit-1 gates at lines 26-29 and
43-46 fire; all four rows surface). Precise honesty/wording defect: the header says
"Reproducibly regenerate" yet `npm run gen:hero` always produces a diff.
**Fix (either):** (a) pin `doc.info.CreationDate`/`ModDate` to a fixed date and a deterministic
`/ID` derived from `evidence.contentHash`; or (b) soften the comment to "regenerate from the
committed sidecars" and drop the "Reproducibly"/byte-reproducible implication.

**M-3 — resolveSigningKey `SYNTHEX_SIGNING_KEY_FILE` branch throws uncaught on a missing/unreadable file.**
Re-verified: `asymmetric.js:190-193` explicit-path branch does `readFileSync(...)` with NO
try/catch, asymmetric to the XDG-default branch at 199-203 which catches and returns null.
On operator misconfig (typo/perms/deleted file) it throws ENOENT through `watch.js:45`,
`tools.js:42`, `bin/synthex.mjs:260`/`:520`, crashing the seal path with a raw fs stack trace
instead of the documented null→symmetric-only fallback. (Minor report nit: line 520 is a CLI
red-team report builder, not an "api report builder" — number and behavior accurate.)
**Fix:** wrap branch 2 in the same try/catch (return null) for consistency, or — if
fail-loud-on-explicit-bad-path is intended — document it in `docs/HONESTY.md §1.4`.

**M-4 — benign_describing vs benign_neutral split is keyed off `cell.subtype`, contradicting the corpus's own per-sample design; numbers do not reconcile with MANIFEST/README.**
In `score()` benign samples bucket by cell subtype; the 22 ALLOW samples living inside
injection/executing cells all fall to the `else=benDesc` branch. Harness yields
describing=136/neutral=104 while MANIFEST/README publish 132/108 (README lines 105-107 require
the split to come from the per-sample technique field). Top-line `fp(240)` and winner-selection
are unaffected — only `fp_describing`/`fp_neutral` (lines 178-179, printed 193) are mis-bucketed.
**Fix:** bucket by the per-sample FP-trap kind (parse `FP-trap: neutral`/`describing` from
`s.technique`, propagated through `loadCorpus`), not by `cell.subtype`.

**M-5 — NIST MEASURE 2.5 requirement/basis inject "robustness", a concept that is NOT in MEASURE 2.5.**
Re-verified `compliance-data.js:120` ("…validity and reliability (robustness)…") and the
basis at line 126 ("Robustness against injection"). Canonical MEASURE 2.5 is about validity,
reliability, and documented generalizability limits; robustness/resilience map to MEASURE
2.6/2.7. Medium because the requirement field is a designed paraphrase (a mischaracterization,
not a verbatim-citation drift).
**Fix:** drop the "(robustness)" parenthetical at :120; reword the basis at :126 away from
"Robustness against injection"; if injection evidence is the intended mapping, frame it as
validity/reliability evidence or add a separate MEASURE 2.7 (security and resilience) row.

### LOW

**L-1 — Winner-selection treats `fp===0` from an all-unparsed guard as qualifying; tie-break / "no valid FP" edge not surfaced.**
`qualifies` predicate (line 221) and winner pick (226-230): a sole live guard with `fp=0` and
`recall=0`/`null` is returned as `winners[0]` (sort uses `(recall??0)`; the local L1 baseline
is filtered at line 219 so there's no incumbent comparison). Low because the degenerate `fp=0`
is only reachable via the H-1 unparsed mechanism — **fix H-1 and L-1 together.**
**Fix:** `qualifies = fp!=null && fp<=FP_THRESHOLD && recall!=null && recall > incumbentRecall`
plus a minimum parsed-benign coverage requirement.

**L-2 — NemoGuard Categories regex is independent of the safety verdict — a verdict/category mismatch can be sealed.**
`nemoguard.js:64` scans the whole raw string independently of the User Safety match (line 61);
probe B yields `{safety:'safe',categories:['S1']}`. Downstream impact is cosmetic today —
`injection-guard.js:468` hardcodes `label = verdict==='block' ? 'unsafe' : null` and ignores
parsed categories; `measure-guard-recall.mjs` ignores `p.categories` too. The trap is latent
in the exported public function.
**Fix:** tie category extraction to the same JSON object/region as the safety match, or zero
categories when `safety==='safe'`.

**L-3 — Model-id routing is exact string equality — a mis-cased/whitespace `SYNTHEX_GUARD_MODEL` silently degrades NemoGuard → Qwen → heuristic.**
The strict `===` at `injection-guard.js:311` fails on a trailing space / uppercased id, falls
to `_screenFeatherless`, then degrades to `source:'heuristic'` with no warning. Outcome is
fail-safe (never a wrong BLOCK) but silent: operator believes a BLOCK-authority guard is live
while only the zero-dep heuristic runs.
**Fix:** trim/normalize the id before comparison (`model.trim()`), or route by a provider+family
check instead of strict `===`.

**L-4 — NemoGuard categories self-contradiction is latent only.** (See L-2; nothing
self-contradictory is sealed today.)

**L-5 — NYDFS section cited as "500.06" — canonical is "500.6".**
`compliance-data.js:149`: change `"23 NYCRR 500.06 — Audit trail"` to `"23 NYCRR 500.6 —
Audit trail"`. Regulator numbering is uniformly "§ 500.6" / "500.6", never zero-padded. The
control title, Second-Amendment citation, and Nov 1 2023 effective date are all correct.

**L-6 — HONESTY.md §8.D ("L3 is the only layer that holds real BLOCK authority") contradicts §8.A without an until-wired caveat.**
`HONESTY.md:236` flat statement; `:187` says NemoGuard QUALIFIES. Reconcilable under the
qualifies-but-not-yet-wired reading the doc uses elsewhere, but a reader hitting §8.D alone
sees a contradiction. Note: the §8.A "not yet wired" basis is itself now stale (NemoGuard is
wired), so the cross-reference should reflect post-wiring reality.
**Fix:** add to §8.D "(the only WIRED block authority at D5; NemoGuard qualifies on measurement
— §8.A)" and update for the wired reality.

**L-7 — Count-attribution mismatch: recall doc 136/104 vs MANIFEST totals 132/108 vs per-cell sums 114/104.**
Three-way mismatch verified: `guard-recall-measurement.md:14-15` (136/104); MANIFEST totals
block (132/108/370/37); summing MANIFEST `files[]` per-cell (114/104/401/28). Grand total 647
holds everywhere but EVERY sub-breakdown disagrees, and the MANIFEST totals block is internally
inconsistent with its own `files[]` array. No headline metric affected (recall/FP computed at
runtime from the corpus).
**Fix:** reconcile MANIFEST totals with `files[]` per-cell sums (or document why subtype
attribution is re-derived at load), then align the doc's 136/104 to whichever is canonical.
(Couples with M-4 — same root: cell-level vs per-sample subtype.)

**L-8 — describing/neutral FP-split inconsistent between MANIFEST/README (132/108) and the live harness (136/104).**
Same root cause as M-4/L-7 (`measure-guard-recall.mjs:62`, `measure-l3-recall.mjs:68` read
cell-level subtype only). Confirmed +4/-4 delta. injection=370 and borderline=37 identical under
both methods; benign total=240 identical, so overall FP rate and the 20%-FP BLOCK-authority
gate are unaffected. Refinement: harness 136/104 AGREES with `guard-recall-measurement.md:14`
while disagreeing with MANIFEST/README — the repo's own docs are internally inconsistent.
**Fix:** make both harnesses read `s.subtype ?? cell.subtype`, OR reconcile the recall doc to
the corpus README/MANIFEST.

**L-9 — buildEnvelope emits a double space on empty-string content.**
`src/fetch/speechmatics-client.js:221`: input `["a","","b"]` → `"a  b"`. Unreachable from real
Speechmatics Batch v2 output (never emits empty `alternatives[].content`).
**Fix:** broaden the skip guard to also drop `content === ""` (or guard the separator on
`content.length`).

**L-10 — buildEnvelope keeps a leading space-dot when the first result is punctuation.**
Punctuation-first result → `". Hi"`. Title phrasing imprecise (no leading space; string just
starts with `.`). Cosmetic; does not affect `words[]` or sealing; real ASR transcripts begin
with a word.
**Fix:** skip a punctuation result while text is empty.

**L-11 — Unresolved `TODO(verify)` in shipped ASI01 control.** Present at
`compliance-data.js:233`. True observation but NOT a defect — the surrounding comments honestly
scope what is asserted and `rag_status='amber'`. Housekeeping only; resolves naturally when
H-3 is fixed.

### Confirmed NON-findings (no action)

- Guard numbers (2/5–3/5 vs 35%/11%) are internally consistent across the two framings (5-page
  in-the-wild corpus vs 647-sample constructed corpus); the docs cross-validate them. No action.

## 4. Severity counts

- Critical: 0
- High: 4 (H-1 … H-4)
- Medium: 5 (M-1 … M-5)
- Low: 11 (L-1 … L-11)
- Confirmed non-findings: 1

## 5. Must-fix-before-push (the 3 HIGH honesty/integrity blockers)

1. **H-4** — strip "the ONLY BLOCK authority" from `public/index.html:675,750` and
   `SLIDES.md:11,22` (public-facing false claim; slips `lint:slides`).
2. **H-3** — replace the invented "Agentic AI Threat (anchor)" ASI01 title with "Agent Goal
   Hijack" at `compliance-data.js:229` (fabricated control name in the declared source of truth).
3. **H-2** — thread `resolveSigningKey()` into `api/analyze.js:36` and `api/stream.js:49`
   (the live prod endpoint seals HMAC-only; Ed25519 silently dropped).

H-1 (FP-denominator) is a measurement-integrity HIGH but lives in `scripts/stress/`, not on a
shipped/public path — fix it (with L-1) immediately after, before quoting any guard FP number
in the deck.
