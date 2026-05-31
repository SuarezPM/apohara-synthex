// Tests for the LATENCY stress dimension — 100% offline, pure math, no network,
// no clock. Every percentile is verified against a hand-computed nearest-rank
// expectation over a KNOWN distribution, so a regression in the math fails loud.
import { test } from "node:test";
import assert from "node:assert/strict";
import { nearestRank, summarize, percentiles } from "../../scripts/stress/dimensions/latency.mjs";

// Known distribution: values 1..100. With nearest-rank, rank = ceil(p/100 * 100),
// so p50→rank 50→value 50, p95→rank 95→value 95, p99→rank 99→value 99.
const oneToHundred = Array.from({ length: 100 }, (_, i) => i + 1);

test("nearestRank: known 1..100 distribution → exact ranks", () => {
  assert.equal(nearestRank(oneToHundred, 50), 50);
  assert.equal(nearestRank(oneToHundred, 95), 95);
  assert.equal(nearestRank(oneToHundred, 99), 99);
  assert.equal(nearestRank(oneToHundred, 100), 100); // rank 100 → last
});

test("nearestRank: edges — p0 maps to first element, empty → null", () => {
  // ceil(0) = 0 → clamped to rank 1 → first element.
  assert.equal(nearestRank(oneToHundred, 0), 1);
  assert.equal(nearestRank([], 50), null);
  assert.equal(nearestRank([42], 50), 42);
  assert.equal(nearestRank([42], 99), 42);
});

test("nearestRank: small n hits the ceil boundary correctly", () => {
  // n=10, values 10,20,...,100. p95 → ceil(9.5)=10 → value 100. p50 → ceil(5)=5 → value 50.
  const tens = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
  assert.equal(nearestRank(tens, 50), 50);
  assert.equal(nearestRank(tens, 95), 100);
  assert.equal(nearestRank(tens, 99), 100);
});

test("summarize: sorts unsorted input and reports n", () => {
  const shuffled = [3, 1, 2, 5, 4]; // sorted: 1,2,3,4,5
  // n=5: p50→ceil(2.5)=3→value 3; p95→ceil(4.75)=5→value 5; p99→ceil(4.95)=5→value 5.
  assert.deepEqual(summarize(shuffled), { p50: 3, p95: 5, p99: 5, n: 5 });
});

test("summarize: drops non-finite samples and counts only valid ones", () => {
  const dirty = [10, NaN, 20, undefined, 30, Infinity, "40", null];
  // Only 10,20,30 survive. n=3: p50→ceil(1.5)=2→20; p95→ceil(2.85)=3→30; p99→30.
  assert.deepEqual(summarize(dirty), { p50: 20, p95: 30, p99: 30, n: 3 });
});

test("summarize: empty / non-array input → all null, n=0", () => {
  assert.deepEqual(summarize([]), { p50: null, p95: null, p99: null, n: 0 });
  assert.deepEqual(summarize(null), { p50: null, p95: null, p99: null, n: 0 });
  assert.deepEqual(summarize("nope"), { p50: null, p95: null, p99: null, n: 0 });
});

test("percentiles: 100 runs of evidence.timings shape → per-stage + e2e exact", () => {
  // Each stage gets the 1..100 distribution; e2e per run = sum of the four stages.
  // For run i (1-based), stage values are all i, so e2e_i = 4*i → distribution 4,8,...,400.
  const timingsList = oneToHundred.map((i) => ({ FETCH: i, FORGE: i, CLASSIFY: i, PROVE: i }));
  const out = percentiles(timingsList);

  for (const stage of ["fetch", "forge", "classify", "prove"]) {
    assert.deepEqual(out.perStage[stage], { p50: 50, p95: 95, p99: 99, n: 100 }, `stage ${stage}`);
  }
  // e2e values 4..400 step 4. p50→rank 50→4*50=200; p95→rank 95→380; p99→rank 99→396.
  assert.deepEqual(out.e2e, { p50: 200, p95: 380, p99: 396, n: 100 });
});

test("percentiles: lowercase output keys map from uppercase timing keys", () => {
  const out = percentiles([{ FETCH: 5, FORGE: 10, CLASSIFY: 15, PROVE: 20 }]);
  assert.equal(out.perStage.fetch.p50, 5);
  assert.equal(out.perStage.forge.p50, 10);
  assert.equal(out.perStage.classify.p50, 15);
  assert.equal(out.perStage.prove.p50, 20);
  // Single run, all stages present → e2e = 5+10+15+20 = 50.
  assert.deepEqual(out.e2e, { p50: 50, p95: 50, p99: 50, n: 1 });
});

test("percentiles: a run missing a stage is excluded from e2e but kept per-stage", () => {
  const timingsList = [
    { FETCH: 1, FORGE: 2, CLASSIFY: 3, PROVE: 4 }, // complete → e2e 10
    { FETCH: 5, FORGE: 6, CLASSIFY: 7 }, // missing PROVE → no e2e total
  ];
  const out = percentiles(timingsList);
  // FETCH samples: [1,5] → both counted. PROVE samples: [4] → only the complete run.
  assert.equal(out.perStage.fetch.n, 2);
  assert.equal(out.perStage.prove.n, 1);
  assert.equal(out.perStage.classify.n, 2);
  // Only the complete run forms an honest e2e total.
  assert.deepEqual(out.e2e, { p50: 10, p95: 10, p99: 10, n: 1 });
});

test("percentiles: empty / non-array input → all-null skeleton, no throw", () => {
  const empty = percentiles([]);
  for (const stage of ["fetch", "forge", "classify", "prove"]) {
    assert.deepEqual(empty.perStage[stage], { p50: null, p95: null, p99: null, n: 0 });
  }
  assert.deepEqual(empty.e2e, { p50: null, p95: null, p99: null, n: 0 });
  // Non-array input must not throw either.
  assert.deepEqual(percentiles(null).e2e, { p50: null, p95: null, p99: null, n: 0 });
  assert.deepEqual(percentiles(undefined).e2e, { p50: null, p95: null, p99: null, n: 0 });
});

test("percentiles: garbage run entries are skipped without throwing", () => {
  // null/number/string entries are not objects → treated as empty runs (all stages missing).
  const out = percentiles([null, 42, "x", { FETCH: 9, FORGE: 9, CLASSIFY: 9, PROVE: 9 }]);
  assert.equal(out.perStage.fetch.n, 1);
  assert.deepEqual(out.e2e, { p50: 36, p95: 36, p99: 36, n: 1 });
});
