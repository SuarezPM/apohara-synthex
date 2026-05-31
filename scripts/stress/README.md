# The Epic Stress Test — harness

> **Status: harness skeleton — full run pending pipeline-green.**
> This directory is the *structure* for the capstone proof (V2_PLAN P4.1,
> mega_prompt `<the_epic_stress_test>`). The six dimensions are wired into a real
> flow but each is an explicit **stub** that returns
> `{ status: "NOT_IMPLEMENTED", dimension }`. The actual run waits until the
> pipeline core is green (P0 → P2 done) and the Evidence Report is real — the
> stress test runs **LAST** because it is the proof, and the proof needs the
> thing it proves to exist first.

## Honesty contract (the moat)

A stub **never emits a metric**. It returns `NOT_IMPLEMENTED` and a human note on
what implementing it entails — never a number. No value this skeleton prints is a
measurement. When a dimension is implemented it MUST: measure (never assert),
report every failure/timeout/as-measured FP, and carry its own reproduce command.
Cherry-picking or fabricating any stress number betrays the entire thesis and is
forbidden (`docs/HONESTY.md` is the source of truth).

The skeleton makes **zero live external calls**. Any dimension that needs a live
service (e.g. Featherless for the L2 guard) is gated behind the opt-in `--live`
flag and is OFF by default, exactly like the rest of the suite
(`SYNTHEX_NETWORK_TESTS` discipline). The unit suite must never depend on network.

## Files

| File | Purpose |
|------|---------|
| `run.mjs` | One-command harness skeleton. Loads the corpus, runs the six dimension stubs in a real flow, assembles `results.json`, prints a summary. |
| `corpus-manifest.schema.json` | Versioned corpus-manifest shape (hashed, ≥1000 artifacts, benign + labeled-adversarial subsets). The corpus generator (TODO) emits a `corpus.json` validated against this. |
| `README.md` | This file. |

## The six dimensions (V2_PLAN P4.1)

Each is a clearly-marked stub in `run.mjs`; each will report with its own
reproduce command when made real.

1. **scale / throughput** — total sealed artifacts, throughput (URLs/min), peak concurrency.
2. **seal integrity** (the killer metric) — % that independently verify across
   Ed25519 + RFC 3161 TSA + Rekor v2 + C2PA (target 100%); inject K tampered →
   % detected (target 100%, 0 false-accepts). Uses the SHIPPED verifiers
   (`verifyEvidence`, `verifyRekorBundle`, `verifyC2paManifest`, `verifyTimestamp`).
3. **guard efficacy** (honest two-axis) — FP% on benign + recall% on labeled
   injections + describing-vs-executing precision + per-layer L1/L2/L3 + the
   layered-vs-single robustness delta under format-manipulation
   (cite Bag-of-Tricks `arXiv:2510.11570`). Reuses `scripts/measure-guard-recall.mjs` logic.
4. **cost efficiency by design** — total $ and $/1000 traced to its architectural
   cause (dedup → fewer calls; layered → reasoning only on the REVIEW band;
   batched classify → ~half cost; O(1) seal). LLM cost is measured; **BD cost is
   estimated per-surface, not billing-actual** (the billing API lags ~30s).
5. **latency** — p50/p95/p99 per stage (fetch/screen/classify/seal) + end-to-end.
6. **determinism** — same input → same content hash → same seal modulo timestamp.

## Running the skeleton (does not measure anything yet)

```bash
# from apohara-synthex/
node scripts/stress/run.mjs --manifest=scripts/stress/corpus.json --limit=100
```

Flags: `--manifest=PATH`, `--limit=N` (cap loaded artifacts), `--out=DIR`,
`--dimensions=seal_integrity,latency` (subset), `--live` (opt-in live external
calls; OFF by default). Writes `out/stress-YYYY-MM-DD/results.json` with
`harness_status: "SKELETON"` and every dimension `NOT_IMPLEMENTED`.

> The `corpus.json` itself is **not yet generated** — building the ≥1000-artifact
> hashed corpus (benign real pages + labeled adversarial packs) is part of the
> full P4.1 run, not this skeleton. Until then, point `--manifest` at a manifest
> that validates against `corpus-manifest.schema.json`.

## The honest reproduce command (full run — pending pipeline-green)

When the dimensions are real, the capstone reproduces in one command:

```bash
# harness skeleton — full run pending pipeline-green
set -a; . ~/.config/apohara/secrets.env; set +a   # only needed for --live dimensions
node scripts/stress/run.mjs --manifest=scripts/stress/corpus.json --live
```

The integrator wires an `npm run stress` alias into `package.json` separately
(this skeleton does not add it). The full run produces:

- a machine-readable `results.json` (the shape `run.mjs` already assembles),
- a **sealed Stress Test Report** — itself a Synthex evidence artifact (meta-proof),
- the headline numbers for the landing + demo, **each with its reproduce command**.

## What is intentionally NOT here yet

- The corpus generator + the committed `corpus.json` (≥1000 hashed artifacts).
- A standalone `validate-manifest.mjs` (full JSON-schema check of `corpus.json`
  against `corpus-manifest.schema.json`).
- Real bodies for the six dimensions.
- The `npm run stress` script (integrator wires it).

These land with the real P4.1 run, after the pipeline core is green.
