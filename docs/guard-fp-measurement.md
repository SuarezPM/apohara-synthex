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
- **Reproduce:** `node scripts/measure-guard-fp.mjs`

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

## What this means (honest reading)

- **The FP rate on security content is high — 80% union.** This is the expected
  domain-mismatch failure: the regex layers fire on the *vocabulary and example
  payloads* of security writing. Pages that show example attack strings
  (PortSwigger, the XSS cheat sheet) trip the rules; the SQLi *prevention* cheat
  sheet, which teaches parameterized queries without raw payloads, passes clean.
- **`REVIEW` is the designed mitigation and it works** — a `REVIEW` verdict
  surfaces the doc for a human/agent decision instead of dropping it. But
  **`BLOCK` (severity ≥ 8) drops the document from the pipeline.** Three of five
  benign pages hit BLOCK on at least one layer. **If you point Synthex at
  security blogs, CVE databases, or pentest writeups, expect legitimate content
  to be blocked.** That is a real limitation, not a tuning afterthought.
- The CVE page tripped **PII** rules (DJL-PII-*), not injection rules — long
  reference lists and identifiers in advisories look like PII to the regex.

## Mitigations / next steps

1. **Operators scraping security domains** should run with the Layer-2
   Prompt-Guard model (`SYNTHEX_GUARD_URL`) — it scored 20% FP on the heuristic
   path and the model is calibrated for REVIEW-by-default, so fewer hard BLOCKs.
2. **Rule recalibration (v0.9+ knob):** demote the BLOCK→REVIEW threshold for
   specific rule classes when a "technical/security domain" hint is set, so
   example payloads in documentation surface instead of dropping. Not shipped
   yet — flagged here so the claim stays honest.
3. The number is now **measured, not asserted.** Re-run on a larger corpus to
   tighten the estimate (n=5 is a floor, not a precise rate).

## Caveats

- n=5 is small — this establishes the *order of magnitude* (high), not a precise
  percentage. Expand `test/fixtures/guard-fp-corpus/` to refine.
- Corpus text was captured as cleaned markdown (Exa), close to but not identical
  to Bright Data's extraction. The vocabulary that trips the rules is present in
  any reasonable text extraction.
