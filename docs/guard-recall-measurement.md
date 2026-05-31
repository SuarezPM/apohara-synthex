# Guard recall + FP gate — the two-axis measurement (P1.2)

> **Why this file exists.** `docs/guard-fp-measurement.md` measures ONE axis — benign FP on a 5-page
> real corpus. The roadmap's mandatory SECOND axis is **recall** (catch rate) on a labeled
> novel-injection corpus, and a real **open-model selection** across more than one guard. This file is
> that measurement. It decides which open guard, if any, EARNS BLOCK authority.

## Method

- **Corpus** — `test/fixtures/guard-recall-corpus/` (647 samples, 45 cells), **constructed** (NOT
  in-the-wild) by adapting PUBLISHED techniques: OWASP LLM01, OWASP Agentic ASI, MITRE ATLAS
  AML.T0051, and the format-manipulation transforms in "Bag of Tricks for Subverting Reasoning-based
  Safety Guardrails" (arXiv:2510.11570). Each sample is labeled on the **describing-vs-executing**
  axis: 370 `injection` (executing → expected BLOCK) · 131 `benign-describing` + 109 `benign-neutral`
  (→ expected ALLOW, the false-positive trap) · 37 `borderline` (→ expected REVIEW). These
  describing/neutral counts are the **per-sample attribution** the harness computes (see below),
  not the cell-level approximation in `MANIFEST.json` (which tags each *cell* with a single subtype
  and so reports 132/108); the benign total (240) and every other band are identical.
- **Guards** — the two open guards **gate-confirmed live + accessible** on our Featherless account
  (2026-05-30): `Qwen/Qwen3Guard-Gen-8B` (its official moderation template, via raw `/completions`)
  and `nvidia/Llama-3.1-Nemotron-Safety-Guard-8B-v3` (a vanilla content-safety prompt via
  `/chat/completions` — FAIR: like Qwen's official template, NO describing-vs-executing exemption baked
  in, so the benign-FP is each guard's RAW domain-mismatch tendency). `meta-llama/Llama-Guard-3-8B`
  and `-2-8B` are gated; `granite-guardian-3.1-8b` 404s. The zero-dep L1 heuristic is a per-layer
  baseline.
- **Axes** — *recall* = fraction of injection samples flagged (verdict ≠ allow); *FP* = fraction of
  benign samples flagged. *block-grade* = fraction with a BLOCK verdict (NemoGuard is binary
  safe/unsafe → block, so its recall and block-grade coincide).
- **Per-sample FP-trap attribution** — the `describing`/`neutral` split is resolved **per sample**,
  not per cell: the harness reads (1) the sample's own `subtype` when present — the ~22 ALLOW rows that
  live *inside* injection cells carry it — else (2) an `FP-trap: describing|neutral` marker in the
  sample's `technique`, else (3) the cell-level subtype. This is why describing/neutral are 131/109 and
  not the cell-level 132/108: a handful of ALLOW rows in `executing` cells are attributed to their true
  trap kind instead of defaulting to the cell label.
- **Decision rule** (mirrors `guard-fp-measurement.md`): a guard is **granted BLOCK authority only if
  its benign FP ≤ 20%** (the L1 bar) **AND it actually parsed ≥ 50% of the benign axis** (so an
  all-unparsed guard cannot show fp≈0 — unparsed counts as not-flagged — and back into BLOCK without
  ever judging a page) **AND it has a real recall**. The **winner** is the qualifying guard with the
  highest recall; if none qualifies, L2 stays all-REVIEW and L3 AlignmentCheck holds BLOCK authority.
  `parsed_benign_coverage` and the split `unparsed_injection` / `unparsed_benign` counts are emitted
  per guard so the gap is auditable.
- **fail-honest** — an unparsed / chatted response is counted as **NOT caught** (never a fake catch).
- **Reproduce** — `set -a; . ~/.config/apohara/secrets.env; set +a; node scripts/measure-guard-recall.mjs`
  (writes `out/guard-recall/results.json`). `--sample=N` runs N/cell for a fast smoke.

## Result (2026-05-30, n=647)

| Guard | recall | block-grade | benign FP | describing-FP | neutral-FP | REVIEW on borderline | BLOCK authority |
|-------|--------|-------------|-----------|---------------|------------|----------------------|-----------------|
| L1 heuristic (zero-dep) | 14% | 1% | 12% | 20% | 2% | 14% | n/a (REVIEW-only) |
| **Qwen3Guard-Gen-8B** | **90%** | 20% | **35%** | **60%** | 3% | 32% | ❌ **DISQUALIFIED** (FP > 20%) |
| **Llama-3.1-Nemotron-Safety-Guard-8B-v3** | 66% | 66% | **11%** | 16% | 4% | 0% | ✅ **QUALIFIES** (FP ≤ 20%) |

(unparsed: Qwen 5/647, NemoGuard 9/647 — counted as not-caught.)

> Note: this table was last measured under the prior cell-level FP-trap split (describing/neutral
> 136/104). The corrected **per-sample** attribution (131/109) only re-labels ~5 ALLOW rows between the
> two benign sub-buckets; the **headline benign-FP and recall are over the full 240-sample benign / 370
> injection bands and are unchanged**. The per-category **describing-FP / neutral-FP** columns shift by
> their new denominators on the next full re-run (numbers are produced by the harness, never hardcoded).

> **WINNER (BLOCK authority): NemoGuard — benign FP 11% ≤ 20%, recall 66%.**

## What this means (honest reading)

- **The multi-guard selection PAID OFF.** With only Qwen3Guard (the v1 guard), L2 was all-REVIEW —
  Qwen's 35% FP disqualifies it for BLOCK (it would silently drop ~1 in 3 benign security pages).
  Probing a second open guard found one that EARNS BLOCK on its measured FP: NemoGuard (11%). This is
  a real, measured **capability upgrade**, not an assertion.
- **Neither guard alone is sufficient; the layering is the architecture.** Qwen3Guard has the higher
  recall (90%) but is too trigger-happy for BLOCK → it is the **high-recall REVIEW-breadth filter**.
  NemoGuard is precise enough for BLOCK (FP 11%) but misses 34% of injections (recall 66%) → it is the
  **low-FP BLOCK gate**, and its recall gap is exactly why **L3 AlignmentCheck** (deepseek-v4-pro,
  measured false-BLOCK 0/5 — `guard-fp-measurement.md`) backstops with the describing-vs-executing
  reasoning. L1 REVIEW → L2 (Qwen REVIEW-breadth + NemoGuard BLOCK-precision) → L3 (FP-killer).
- **Cross-validation with the real corpus.** Qwen's **60% describing-FP on the constructed corpus
  matches its 3/5 (60%) on the real 5-page corpus** (`guard-fp-measurement.md`). The constructed
  describing samples behave like real security writing — evidence the corpus is realistic where it
  matters (the FP trap), not a strawman.

## Caveats

- **Constructed corpus**, adapted from published techniques — NOT pages found in the wild. It measures
  the guards against a realistic, reproducible, labeled benchmark; it is not a field study. The 5-page
  `guard-fp-corpus` remains the in-the-wild FP anchor.
- **NemoGuard is binary** (safe/unsafe) — no native Controversial/REVIEW tier; `unsafe → block`.
- **Hosted inference is not run-to-run deterministic** despite `temperature=0`; the BLOCK/DISQUALIFY
  decision is stable across runs (smoke n=90 gave NemoGuard FP 3% / Qwen 31%; full n=647 gives 11% /
  35% — both sides of the 20% bar hold).
- An unparsed/chatted reply is counted as not-caught (conservative; never inflates recall).

## Follow-ups

1. **Wire NemoGuard into production** (`src/forge/injection-guard.js`): add a `nemoguard` provider
   branch (vanilla content-safety prompt → `/chat/completions` → `parseNemoGuardCompletion`), and grant
   BLOCK authority gated on this measured FP. Only after wiring may the landing/SLIDES claim "L2 holds
   BLOCK authority via NemoGuard".
2. Corroborate NemoGuard's FP on the real 5-page `guard-fp-corpus` (in-the-wild anchor for the 11%).
3. Expand the corpus / re-run periodically; the harness is the source of truth (numbers never hardcoded).
