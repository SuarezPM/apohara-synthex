# T0.6 — Nemotron vs DeepSeek Calibration

**Date:** 2026-05-28
**Source PRD:** `.omc/plans/synthex-v0.6.0-watch-prove.md` §3 D0 T0.6
**Result JSON:** `out/nemotron-vs-deepseek-calibration.json`

## Setup

- **Fixtures:** 20 (5 per lens × 4 lenses: gtm, finance, security, supply-chain).
  Each fixture has a real-world-style web scrape excerpt + the expected lens.
- **Models compared:**
  - `tier=oss` → `deepseek/deepseek-non-thinking-v3.2-exp` (default v0.5+)
  - `tier=free` → `nvidia/nemotron-nano-9b-v2` (the actual FREE model id on
    AI/ML API; the "nvidia/nemotron-3-nano-omni" cited in external audit was
    HTTP 404 / Model Not Found — see commit 00e606a).
- **Decision rule (PRD T0.6 AC3):** if `abs(oss.severity - free.severity) > 1.5`
  on more than 30 % of fixtures, label tier=free as `free-low-quality` in the
  playground UI.

## Result

| Metric | Value |
|---|---|
| Fixtures completed | 20 / 20 |
| Failures (HTTP / parse) | 0 |
| Δ > 1.5 count | **10 / 20** |
| Fail rate | **50 %** |
| Threshold | 30 % |
| **Gate** | **FREE_LOW_QUALITY** |
| Label | `free-low-quality` |

## Pattern

Nemotron-Nano 9B **over-flags noise** consistently. The worst deltas are not on
high-stakes content (security advisories, vendor bankruptcies — both models
agree there) but on benign / promotional / minor-event content where Nemotron
gives 3-5 and DeepSeek gives 0-2.

| Fixture | OSS | FREE | Δ | Diagnosis |
|---|---|---|---|---|
| fin-03 earnings-beat | 1 | 9 | 8 | Interpretation gap (already-discounted vs high-impact financial signal) |
| sc-05 noise-vendor-newsletter | 0 | 3 | 3 | Noise over-rated |
| sc-04 weather-disruption-mild | 2 | 5 | 3 | Noise over-rated |
| fin-05 noise-press-release | 0 | 3 | 3 | Noise over-rated |
| fin-02 regulatory-filing-mild | 4 | 7 | 3 | Noise over-rated |
| sec-05 noise-marketing | 2 | 4 | 2 | Noise over-rated |
| sec-04 low-severity-disclosure | 2 | 4 | 2 | Noise over-rated |
| gtm-05 noise-blog-post | 1 | 3 | 2 | Noise over-rated |
| gtm-04 market-move-quiet | 6 | 8 | 2 | Defensible (Wayback signal) |
| gtm-03 product-launch-incremental | 2 | 4 | 2 | Noise over-rated |

In contrast, on hard signals (sec-01 CVE, sec-02 leaked creds, sec-03 supply
typosquat, fin-01 bankruptcy, sc-01 fire) both models converge with Δ ≤ 1.

## Decision (T0.6 AC3 applied)

- Playground UI **MUST** show `free-low-quality` label when user selects
  tier=free.
- README + SLIDES **MUST NOT** present FREE tier as production-grade. Honest
  framing: "Test cost-free with calibrated awareness it over-flags noise; use
  tier=oss or tier=paid for production decisions."
- DEFAULT_TIER remains `oss` (tiers.js:13) — the playground default is
  high-quality, FREE is opt-in.

## Reproducibility

```
node scripts/calibrate-nemotron.mjs
```

(Requires `AIML_API_KEY` in env; ~$0.05-$0.10 AI/ML cost for 40 requests;
~3-5 min wall clock.)

Re-run before any future model swap to keep the gate honest.

## Caveats (honesty)

- Sample size N=20 is **diagnostic, not statistically rigorous**. Sufficient to
  gate the UI label, NOT sufficient to publish "Nemotron is 50% worse than
  DeepSeek" as a universal claim.
- Severity is JSON-only here; signal/summary quality not scored. A model can
  agree on severity but produce weaker signals — that warrants a separate eval
  if FREE tier is ever promoted in v0.7+.
- All fixtures are English-language. Multilingual content was out of scope.
