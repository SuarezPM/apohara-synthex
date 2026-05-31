// ============================================================================
// STRESS DIMENSION (4) — cost efficiency. Fixture-tested, ZERO network.
//
// Verifies the pure cost arithmetic AND the architectural tracing of
// scripts/stress/dimensions/cost.mjs. No live run, no clock, no secrets.
// ============================================================================
import { test } from "node:test";
import assert from "node:assert/strict";
import { costPer1000, dimCostEfficiency } from "../../scripts/stress/dimensions/cost.mjs";

// A deterministic measured-aggregate fixture. Numbers are illustrative INPUTS the
// harness would MEASURE — the test asserts the formula transforms them correctly,
// it does not assert any real-world price.
const FIXTURE = Object.freeze({
  bdSpend: 1.5, // estimated per-surface (e.g. 1000 unlocker calls @ ~0.0015)
  aimlSpend: 2.0, // measured from token/call telemetry
  featherlessFlat: 25.0, // flat subscription for the run window
  llmCalls: 1000, // measured calls actually issued
  tokens: 500_000, // measured tokens
  dedupCallsSaved: 200, // calls dedup collapsed
  batchCallsSaved: 3000, // calls saved by 4-lens→1 batching
  artifacts: 1000, // sealed artifacts (the $/1000 denominator)
});

test("costPer1000 — total spend is the sum of the three measured sources", () => {
  const r = costPer1000(FIXTURE);
  // 1.5 + 2.0 + 25.0
  assert.equal(r.totalUsd, 28.5);
});

test("costPer1000 — per1000Usd = (total / artifacts) * 1000", () => {
  const r = costPer1000(FIXTURE);
  // (28.5 / 1000) * 1000 = 28.5
  assert.equal(r.per1000Usd, 28.5);

  // half the artifacts → double the $/1000 for the same spend
  const half = costPer1000({ ...FIXTURE, artifacts: 500 });
  assert.equal(half.per1000Usd, 57.0);
});

test("costPer1000 — avgCallUsd = aimlSpend / llmCalls (measured per-call basis)", () => {
  const r = costPer1000(FIXTURE);
  // 2.0 / 1000 = 0.002
  assert.equal(r.avgCallUsd, 0.002);
});

test("traced.dedup — usd saved = avgCallUsd * dedupCallsSaved, tied to its cause", () => {
  const r = costPer1000(FIXTURE);
  assert.equal(r.traced.dedup.cause, "semantic-dedup");
  assert.equal(r.traced.dedup.callsSaved, 200);
  // 0.002 * 200 = 0.4
  assert.equal(r.traced.dedup.usdSaved, 0.4);
});

test("traced.batched — usd saved = avgCallUsd * batchCallsSaved, tied to its cause", () => {
  const r = costPer1000(FIXTURE);
  assert.equal(r.traced.batched.cause, "batched-classify");
  assert.equal(r.traced.batched.callsSaved, 3000);
  // 0.002 * 3000 = 6.0
  assert.equal(r.traced.batched.usdSaved, 6.0);
});

test("traced.layered + traced.sealO1 — structural causes, no fabricated dollar figure", () => {
  const r = costPer1000(FIXTURE);
  assert.equal(r.traced.layered.cause, "layered-defense-on-REVIEW-band");
  assert.equal(r.traced.layered.structural, true);
  assert.ok(!("usdSaved" in r.traced.layered), "layered must NOT invent a dollar saving");

  assert.equal(r.traced.sealO1.cause, "O(1)-seal");
  assert.equal(r.traced.sealO1.structural, true);
  assert.equal(r.traced.sealO1.llmCost, 0);
});

test("provenance — BD estimated, AIML measured, Featherless flat/amortized (honesty labels)", () => {
  const r = costPer1000(FIXTURE);
  assert.equal(r.provenance.bdSpend, "estimated-per-surface");
  assert.equal(r.provenance.aimlSpend, "measured");
  assert.equal(r.provenance.featherlessFlat, "flat-subscription-amortized");
});

test("zero LLM calls → no measured per-call basis → attributed savings are 0 (no fabrication)", () => {
  const r = costPer1000({
    ...FIXTURE,
    aimlSpend: 0,
    llmCalls: 0,
    dedupCallsSaved: 500,
    batchCallsSaved: 500,
  });
  assert.equal(r.avgCallUsd, 0);
  assert.equal(r.traced.dedup.usdSaved, 0);
  assert.equal(r.traced.batched.usdSaved, 0);
});

test("result is immutable (frozen) — pure formula, no mutation leaks", () => {
  const r = costPer1000(FIXTURE);
  assert.ok(Object.isFrozen(r));
  assert.ok(Object.isFrozen(r.traced));
  assert.ok(Object.isFrozen(r.traced.dedup));
  assert.ok(Object.isFrozen(r.inputs));
  assert.throws(() => {
    "use strict";
    r.totalUsd = 0;
  }, TypeError);
});

test("determinism — same input → byte-identical result", () => {
  const a = costPer1000(FIXTURE);
  const b = costPer1000({ ...FIXTURE });
  assert.deepEqual(a, b);
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});

test("fail-safe — invalid / negative / zero-denominator inputs throw, never return junk", () => {
  assert.throws(() => costPer1000(null), TypeError);
  assert.throws(() => costPer1000({ ...FIXTURE, bdSpend: -1 }), TypeError);
  assert.throws(() => costPer1000({ ...FIXTURE, aimlSpend: "free" }), TypeError);
  assert.throws(() => costPer1000({ ...FIXTURE, llmCalls: NaN }), TypeError);
  assert.throws(() => costPer1000({ ...FIXTURE, artifacts: 0 }), RangeError);
  assert.throws(() => costPer1000({ ...FIXTURE, artifacts: -10 }), TypeError);
});

// ── harness dimension runner contract ────────────────────────────────────────

test("dimCostEfficiency — no measured input → NOT_IMPLEMENTED, NEVER a metric", async () => {
  const res = await dimCostEfficiency({ loaded: 1000 }, {});
  assert.equal(res.status, "NOT_IMPLEMENTED");
  assert.equal(res.dimension, "cost_efficiency");
  assert.equal(res.reproduce, null);
  assert.ok(!("metric" in res), "a stub must not carry a metric");
});

test("dimCostEfficiency — with measured input → OK + metric + reproduce command", async () => {
  const res = await dimCostEfficiency({ loaded: 1000 }, { costInput: FIXTURE });
  assert.equal(res.status, "OK");
  assert.equal(res.dimension, "cost_efficiency");
  assert.equal(res.metric.per1000Usd, 28.5);
  assert.equal(res.metric.traced.batched.usdSaved, 6.0);
  assert.match(res.reproduce, /scripts\/stress\/run\.mjs/);
  assert.match(res.note, /estimated per-surface/);
});

test("dimCostEfficiency — bad measured input → ERROR (surfaced), never a faked metric", async () => {
  const res = await dimCostEfficiency(
    { loaded: 1000 },
    { costInput: { ...FIXTURE, artifacts: 0 } },
  );
  assert.equal(res.status, "ERROR");
  assert.ok(!("metric" in res));
  assert.match(res.error, /artifacts/);
});
