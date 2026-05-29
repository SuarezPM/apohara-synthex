# Guard false-positive measurement — real benign security corpus

> **Why this file exists.** The 2026-05-29 external audit flagged that Synthex's
> FORGE defense layers were only ever measured for *coverage* on synthetic
> attack corpora — never for *false positives* on real benign content. "The
> guard's FP number doesn't exist until you measure it on real scraped content,
> not synthetic." This file is that measurement.

## Method

- **Corpus** (`test/fixtures/guard-fp-corpus/`, captured 2026-05-29): five real
  pages that are the adversarial *benign* case — security writing that
  *discusses* prompt injection / SQLi / XSS but is informational, not an attack:
  | # | Page | Source |
  |---|------|--------|
  | 01 | "Prompt injection attacks against GPT-3" | simonwillison.net |
  | 02 | SQL Injection Prevention Cheat Sheet | cheatsheetseries.owasp.org |
  | 03 | Cross-Site Scripting Prevention Cheat Sheet | cheatsheetseries.owasp.org |
  | 04 | SQL injection (Web Security Academy) | portswigger.net |
  | 05 | CVE-2021-44228 (Log4Shell) | nvd.nist.gov |
- **Definition.** Every page is benign by construction, so **every `REVIEW` or
  `BLOCK` verdict is a false positive.**
- **Layers measured independently** (`scripts/measure-guard-fp.mjs`):
  - `prefilter.classify` — Layer-1 regex, 32 rules (runs in every pipeline)
  - `djl.evaluate` — Layer-1 regex, 78 rules (runs in every pipeline)
  - `injection-guard.heuristicScreen` — Layer-2 zero-dep fallback. The hosted
    Prompt-Guard model would FP *differently*; this measures the deterministic
    path that runs when `SYNTHEX_GUARD_URL` is unset.
- **Pipeline-level measurement** (`scripts/measure-pipeline-fp.mjs`, v1.0.0): the
  isolated-module numbers above don't tell you what the **pipeline actually does**
  with that signal. After the v1.0.0 FP fix (D5), L1 regex is **REVIEW-only on
  ingest** — a `BLOCK`-grade hit (sev ≥ 8) no longer drops the scraped doc, it
  marks it `REVIEW` and keeps it (severity stays a sealed signal in
  `decisions[]`). This script runs the full FORGE → CLASSIFY path over the corpus
  and reports how many benign docs are **dropped by L1 regex** (must be **0**).
- **Reproduce:** `node scripts/measure-guard-fp.mjs` (isolated layers) and
  `node scripts/measure-pipeline-fp.mjs` (pipeline-level drop count).

## Result (2026-05-29, n=5)

| Layer | FP rate | Pages flagged |
|-------|---------|---------------|
| prefilter (32 regex) | **60%** (3/5) | prompt-injection, xss, sqli |
| djl (78 regex) | **80%** (4/5) | SQLI/XSS/PII/HARM rules |
| injection-guard (heuristic) | **20%** (1/5) | one medium-confidence hit |
| **union (any layer)** | **80%** (4/5) | — |

Per page:

| Page | prefilter | djl | guard(heuristic) |
|------|-----------|-----|------------------|
| 01 prompt-injection blog | BLOCK | BLOCK | REVIEW |
| 02 SQLi **prevention** cheat sheet | ALLOW | ALLOW | ALLOW |
| 03 XSS prevention cheat sheet | REVIEW | BLOCK | ALLOW |
| 04 PortSwigger SQLi | BLOCK | BLOCK | ALLOW |
| 05 CVE-2021-44228 | ALLOW | REVIEW (PII rules) | ALLOW |

## Pipeline-level result (v1.0.0, after the D5 FP fix — n=5)

The isolated-module table above is the *raw signal*. What the **pipeline** does
with it changed in v1.0.0: L1 regex (DJL + prefilter) is now **REVIEW-only on
ingest**, so a `BLOCK`-grade hit no longer drops the doc.

| Metric (`node scripts/measure-pipeline-fp.mjs`) | Pre-fix | v1.0.0 |
|---|---|---|
| Benign docs **dropped by L1 regex** | 3/5 (60%) | **0/5** |
| Benign docs surfaced as **REVIEW by L1** (kept) | — | 3/5 |
| Benign docs **classified** (reach the LLM) | 2/5 | **5/5** |

`dropped_by_regex: 0` is the load-bearing number: no benign security page is
silently dropped anymore. The three pages that previously hit a hard BLOCK
(01 prompt-injection blog, 03 XSS cheat sheet, 04 PortSwigger) are now `REVIEW`'d
and classified, with their `BLOCK`-grade severity sealed in `payload.decisions[]`
for audit. The downstream action/persistence sinks (webhook, Cognee) still honor
that REVIEW via the widened CaMeL gate (`src/sinks.js`, A1).

## What this means (honest reading)

- **The raw FP rate on security content is high — 80% union.** This is the
  expected domain-mismatch failure: the regex layers fire on the *vocabulary and
  example payloads* of security writing. Pages that show example attack strings
  (PortSwigger, the XSS cheat sheet) trip the rules; the SQLi *prevention* cheat
  sheet, which teaches parameterized queries without raw payloads, passes clean.
- **`REVIEW` is the designed mitigation, and as of v1.0.0 it is the ONLY thing L1
  regex does on ingest.** Pre-v1.0.0, `BLOCK` (severity ≥ 8) *dropped* the
  document from the pipeline — three of five benign pages hit that. The D5 fix
  demotes L1 `BLOCK` to `REVIEW` on ingest: the doc is kept and classified, the
  severity is sealed as a signal, and **no benign content is dropped by regex
  anymore** (pipeline `dropped_by_regex: 0`). BLOCK authority on ingest now
  belongs only to a qualified Layer-2 (Phase 1, gated on its own measured FP) and
  L3 AlignmentCheck. If you point Synthex at security blogs, CVE databases, or
  pentest writeups, the content is surfaced for review, not silently dropped.
- The CVE page tripped **PII** rules (DJL-PII-*), not injection rules — long
  reference lists and identifiers in advisories look like PII to the regex.

## Mitigations / next steps

1. **Operators scraping security domains** should run with the Layer-2
   Prompt-Guard model (`SYNTHEX_GUARD_URL`) — it scored 20% FP on the heuristic
   path and the model is calibrated for REVIEW-by-default, so fewer hard BLOCKs.
2. **Rule recalibration — SHIPPED in v1.0.0 (D5):** L1 regex (DJL + prefilter) no
   longer drops a scraped doc on a `BLOCK`-grade hit; it demotes to `REVIEW` on
   ingest, so example payloads in security documentation surface instead of
   dropping. Verified by `scripts/measure-pipeline-fp.mjs` → `dropped_by_regex: 0`.
   A finer-grained per-rule-class / per-domain knob remains a future refinement.
3. The number is now **measured, not asserted.** Re-run on a larger corpus to
   tighten the estimate (n=5 is a floor, not a precise rate).

## Caveats

- n=5 is small — this establishes the *order of magnitude* (high), not a precise
  percentage. Expand `test/fixtures/guard-fp-corpus/` to refine.
- Corpus text was captured as cleaned markdown (Exa), close to but not identical
  to Bright Data's extraction. The vocabulary that trips the rules is present in
  any reasonable text extraction.
