// ============================================================================
// STRESS DIMENSION (4) — COST EFFICIENCY BY DESIGN.
//
// Pure, injectable cost formula for the capstone stress test (V2_PLAN P4.1,
// dimension `cost_efficiency`). NO live run, NO network, NO clock, NO secrets.
// Everything it reports is computed from numbers the harness MEASURES and passes
// in; this module invents no pricing and fabricates no metric.
//
// HONESTY (the moat): the only dollar figures here are the ones the caller hands
// us (`bdSpend`, `aimlSpend`, `featherlessFlat`). Bright Data spend is ESTIMATED
// per-surface upstream (the billing API lags ~30s — see scripts/stress-test-judges.mjs),
// so any consumer MUST keep the `estimated` provenance flag and never relabel it
// "BD-billing-actual". The four efficiency numbers under `traced` are each tied to
// a named architectural cause and are derived ONLY from saved-work counts the
// caller measured (dedup'd calls, batched-away calls) — they are attributions of
// real, measured savings, not projections.
//
// Pure formula. No mutation. Fail-safe: invalid input throws loudly rather than
// silently producing a wrong number.
// ============================================================================

// Per-LLM-call dollar cost is whatever the measured aimlSpend divided by the
// measured call count works out to — we do NOT hardcode a token price here. The
// `traced` savings are expressed as the dollars the ARCHITECTURE avoided, derived
// from that same measured average call cost. This keeps the tracing honest: a
// saving is "calls we provably did not make × what a call actually cost us".

const isFiniteNonNeg = (n) => typeof n === "number" && Number.isFinite(n) && n >= 0;

function requireNonNeg(name, value) {
  if (!isFiniteNonNeg(value)) {
    throw new TypeError(`cost: ${name} must be a finite number >= 0 (got ${value})`);
  }
  return value;
}

function round(n, dp = 4) {
  // Deterministic fixed-decimal rounding for stable, content-addressable output.
  const f = 10 ** dp;
  return Math.round((n + Number.EPSILON) * f) / f;
}

/**
 * Compute total spend and $/1000 sealed artifacts, with each efficiency number
 * traced to its architectural cause.
 *
 * @param {object} input
 * @param {number} input.bdSpend           Bright Data spend (USD). ESTIMATED per-surface, not billing-actual.
 * @param {number} input.aimlSpend         AI/ML API spend (USD) — measured from token/call telemetry.
 * @param {number} input.featherlessFlat   Featherless cost (USD) for the run window — a FLAT subscription, amortized (not per-call).
 * @param {number} input.llmCalls          LLM calls actually issued (measured). Used to derive average call cost.
 * @param {number} input.tokens            LLM tokens actually consumed (measured). Reported for transparency.
 * @param {number} input.dedupCallsSaved   LLM calls NOT issued because (semantic) dedup collapsed duplicate docs.
 * @param {number} input.batchCallsSaved   LLM calls NOT issued because 4-lens classify was batched into 1.
 * @param {number} input.artifacts         Sealed artifacts produced (the denominator for $/1000). Must be > 0.
 * @returns {{
 *   totalUsd:number, per1000Usd:number, artifacts:number,
 *   inputs:{bdSpend:number,aimlSpend:number,featherlessFlat:number,llmCalls:number,tokens:number},
 *   provenance:{bdSpend:'estimated-per-surface',aimlSpend:'measured',featherlessFlat:'flat-subscription-amortized'},
 *   avgCallUsd:number,
 *   traced:{ dedup:object, batched:object, layered:object, sealO1:object }
 * }}
 */
export function costPer1000(input) {
  if (input === null || typeof input !== "object") {
    throw new TypeError("cost: costPer1000 expects an input object");
  }
  const bdSpend = requireNonNeg("bdSpend", input.bdSpend);
  const aimlSpend = requireNonNeg("aimlSpend", input.aimlSpend);
  const featherlessFlat = requireNonNeg("featherlessFlat", input.featherlessFlat);
  const llmCalls = requireNonNeg("llmCalls", input.llmCalls);
  const tokens = requireNonNeg("tokens", input.tokens);
  const dedupCallsSaved = requireNonNeg("dedupCallsSaved", input.dedupCallsSaved);
  const batchCallsSaved = requireNonNeg("batchCallsSaved", input.batchCallsSaved);
  const artifacts = requireNonNeg("artifacts", input.artifacts);

  if (artifacts <= 0) {
    throw new RangeError("cost: artifacts must be > 0 (it is the $/1000 denominator)");
  }

  const totalUsd = round(bdSpend + aimlSpend + featherlessFlat);
  const per1000Usd = round((totalUsd / artifacts) * 1000);

  // Average measured cost of an LLM call we DID make. The savings attributions
  // are "calls avoided × this real average". If we made zero calls there is no
  // measured per-call cost to multiply by, so attributed savings are 0 (honest:
  // we cannot claim a dollar saving without a measured cost basis).
  const avgCallUsd = llmCalls > 0 ? round(aimlSpend / llmCalls, 6) : 0;

  const savedUsd = (calls) => round(avgCallUsd * calls, 4);

  // Each entry names its architectural cause and the measured quantity that
  // drives it. `savedUsd` is the dollar figure attributable to that cause.
  const traced = {
    // dedup → fewer LLM calls: (semantic) dedup collapses duplicate scraped docs
    // so the classifier never re-reasons over the same content.
    dedup: {
      cause: "semantic-dedup",
      detail: "duplicate scraped docs collapsed before classify → calls never issued",
      source: "src/forge/dedup-semantic.js + src/forge/dedup.js",
      callsSaved: dedupCallsSaved,
      usdSaved: savedUsd(dedupCallsSaved),
    },
    // batched → 4 lenses in 1 call: classifyBatched issues one fetch for all four
    // lenses instead of four per-lens calls (~3 of every 4 calls avoided).
    batched: {
      cause: "batched-classify",
      detail: "4 lenses issued as 1 LLM call instead of 4 (per-lens calls avoided)",
      source: "src/classify/aiml-client.js#classifyBatched",
      callsSaved: batchCallsSaved,
      usdSaved: savedUsd(batchCallsSaved),
    },
    // layered → reasoning spent only on the REVIEW band: cheap deterministic L1
    // (regex) and the volume L2 filter gate the expensive L3 reasoner, so the
    // costly model only runs on the fraction that L1/L2 surfaced. This is a
    // STRUCTURAL property of the pipeline, reported qualitatively — we do NOT
    // fabricate a dollar figure for it because the caller does not measure the
    // counterfactual "L3 on every doc" spend here.
    layered: {
      cause: "layered-defense-on-REVIEW-band",
      detail: "deterministic L1 + volume L2 gate the expensive L3 reasoner → L3 runs only on the surfaced band, not every doc",
      source: "src/forge/injection-guard.js (L1/L2) → src/classify/alignment-check.js (L3)",
      structural: true,
    },
    // sealO1 → O(1) sealing cost per artifact: HMAC + Ed25519 + (sampled) TSA +
    // Rekor anchoring are constant-work-per-artifact and carry NO per-token LLM
    // cost — the seal does not scale with document size or with classify spend.
    sealO1: {
      cause: "O(1)-seal",
      detail: "seal is constant work per artifact (HMAC+Ed25519+TSA+Rekor), independent of doc size — no LLM/token cost",
      source: "src/prove/evidence-report.js",
      structural: true,
      llmCost: 0,
    },
  };

  return Object.freeze({
    totalUsd,
    per1000Usd,
    artifacts,
    inputs: Object.freeze({ bdSpend, aimlSpend, featherlessFlat, llmCalls, tokens }),
    provenance: Object.freeze({
      bdSpend: "estimated-per-surface",
      aimlSpend: "measured",
      featherlessFlat: "flat-subscription-amortized",
    }),
    avgCallUsd,
    traced: Object.freeze({
      dedup: Object.freeze(traced.dedup),
      batched: Object.freeze(traced.batched),
      layered: Object.freeze(traced.layered),
      sealO1: Object.freeze(traced.sealO1),
    }),
  });
}

// ── harness dimension runner ─────────────────────────────────────────────────
// Matches the run.mjs dimension contract: an async fn that returns a status
// object. INJECTABLE — the caller supplies the measured aggregate via
// ctx.costInput (so this stays a pure formula with zero live work). When the
// real P4.1 run wires telemetry in, it passes the measured aggregate here.
//
// Honesty: if ctx.costInput is absent we return NOT_IMPLEMENTED (never a number),
// exactly like the skeleton stub it replaces. We only emit status:"OK" with a
// metric when we were GIVEN measured inputs to compute from.

export async function dimCostEfficiency(corpus, ctx = {}) {
  const detail =
    `would compute $/1000 over ${corpus?.loaded ?? "?"} artifacts ` +
    `(LLM cost measured; BD cost ESTIMATED per-surface, not billing-actual) traced to architectural cause`;

  const measured = ctx.costInput;
  if (measured === undefined || measured === null) {
    // No measured aggregate supplied → stay a stub. NEVER invent a number.
    return {
      status: "NOT_IMPLEMENTED",
      dimension: "cost_efficiency",
      detail,
      reproduce: null,
    };
  }

  let cost;
  try {
    cost = costPer1000(measured);
  } catch (e) {
    // Fail-safe: a bad aggregate is surfaced, not faked into a metric.
    return {
      status: "ERROR",
      dimension: "cost_efficiency",
      error: e.message,
      detail,
    };
  }

  return {
    status: "OK",
    dimension: "cost_efficiency",
    detail,
    metric: cost,
    note: "BD spend is estimated per-surface, not BD-billing-actual (billing API lags ~30s).",
    reproduce:
      "node scripts/stress/run.mjs --manifest=scripts/stress/corpus.json --live  # cost aggregated from run telemetry",
  };
}

export default { costPer1000, dimCostEfficiency };
