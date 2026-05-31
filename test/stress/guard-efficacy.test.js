// Tests for the GUARD EFFICACY stress dimension reshaper. PURE function, zero
// network, fixture-driven. Verifies the reshape mirrors the two-axis decision
// rule (FP ≤ threshold earns BLOCK authority; max recall wins) and stays honest
// (null FP disqualifies; ties yield no winner; input never mutated).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  summarizeGuardEfficacy,
  DEFAULT_FP_THRESHOLD,
} from "../../scripts/stress/dimensions/guard-efficacy.mjs";

// Fixture mirroring out/guard-recall/results.json (real measured shape, numbers
// adapted to a clean decision: nemoguard qualifies for BLOCK, qwen3guard does not).
const FIXTURE = Object.freeze({
  fp_threshold: 0.2,
  samples: 647,
  guards: {
    "heuristic-l1": {
      id: "heuristic-zero-dep (L1 fallback)",
      tiers: ["allow", "review", "block"],
      n: 647,
      unparsed_benign: 0,
      unparsed_injection: 0,
      recall: 0.135,
      block_recall: 0.005,
      fp: 0.12,
      fp_describing: 0.198,
      fp_neutral: 0.019,
    },
    qwen3guard: {
      id: "Qwen/Qwen3Guard-Gen-8B",
      tiers: ["allow", "review", "block"],
      n: 647,
      unparsed_benign: 0,
      unparsed_injection: 5,
      recall: 0.897,
      block_recall: 0.202,
      fp: 0.354, // > 0.2 → DISQUALIFIED from BLOCK
      fp_describing: 0.602,
      fp_neutral: 0.028,
    },
    nemoguard: {
      id: "nvidia/Llama-3.1-Nemotron-Safety-Guard-8B-v3",
      tiers: ["allow", "block"],
      n: 647,
      unparsed_benign: 0, // every benign sample parsed → fp is a valid measurement
      unparsed_injection: 9,
      recall: 0.656,
      block_recall: 0.656,
      fp: 0.108, // ≤ 0.2 AND fp valid → qualifies, only qualifier → winner
      fp_describing: 0.161,
      fp_neutral: 0.038,
    },
  },
  decision: { block_authority: "nemoguard", fp: 0.108, recall: 0.656 },
});

test("guard-efficacy: per-guard recall + FP projected from the source", () => {
  const out = summarizeGuardEfficacy(FIXTURE);
  assert.equal(out.guards.length, 3);
  const byName = Object.fromEntries(out.guards.map((g) => [g.name, g]));
  assert.equal(byName.nemoguard.recall, 0.656);
  assert.equal(byName.nemoguard.fp, 0.108);
  assert.equal(byName.qwen3guard.recall, 0.897);
  assert.equal(byName["heuristic-l1"].fp, 0.12);
});

test("guard-efficacy: layers — heuristic-l1 is L1, hosted guards are L2", () => {
  const out = summarizeGuardEfficacy(FIXTURE);
  const byName = Object.fromEntries(out.guards.map((g) => [g.name, g]));
  assert.equal(byName["heuristic-l1"].layer, "L1");
  assert.equal(byName.qwen3guard.layer, "L2");
  assert.equal(byName.nemoguard.layer, "L2");
});

test("guard-efficacy: L1 is never BLOCK-eligible; L2 eligibility follows FP bar", () => {
  const out = summarizeGuardEfficacy(FIXTURE);
  const byName = Object.fromEntries(out.guards.map((g) => [g.name, g]));
  assert.equal(byName["heuristic-l1"].block_eligible, false); // baseline, never BLOCK
  assert.equal(byName.nemoguard.block_eligible, true); // FP 0.108 ≤ 0.2
  assert.equal(byName.qwen3guard.block_eligible, false); // FP 0.354 > 0.2
});

test("guard-efficacy: winner mirrors the source decision (nemoguard)", () => {
  const out = summarizeGuardEfficacy(FIXTURE);
  assert.equal(out.winner.name, FIXTURE.decision.block_authority);
  assert.equal(out.winner.name, "nemoguard");
  assert.equal(out.winner.fp, 0.108);
  assert.equal(out.winner.recall, 0.656);
  assert.equal(out.winner.fp_threshold, 0.2);
});

test("guard-efficacy: winner = highest-recall qualifying guard, not highest recall overall", () => {
  // qwen has higher recall (0.897) but FP 0.354 > bar → must NOT win.
  const out = summarizeGuardEfficacy(FIXTURE);
  assert.notEqual(out.winner.name, "qwen3guard");
  assert.equal(out.winner.name, "nemoguard");
});

test("guard-efficacy: perLayer reports L1 baseline, best L2, and the honest delta", () => {
  const out = summarizeGuardEfficacy(FIXTURE);
  assert.equal(out.perLayer.L1.name, "heuristic-l1");
  assert.equal(out.perLayer.L1.recall, 0.135);
  assert.deepEqual(out.perLayer.L2.candidates, ["qwen3guard", "nemoguard"]);
  assert.equal(out.perLayer.L2.best, "qwen3guard"); // highest L2 recall (0.897)
  assert.equal(out.perLayer.L2.best_recall, 0.897);
  // delta = best L2 recall (0.897) − L1 recall (0.135) = 0.762
  assert.equal(out.perLayer.layered_vs_l1_recall_delta, 0.762);
});

test("guard-efficacy: no qualifying L2 guard → no winner, honest fallback reason", () => {
  const allHighFP = {
    fp_threshold: 0.2,
    guards: {
      "heuristic-l1": { id: "l1", tiers: ["allow", "review", "block"], recall: 0.1, fp: 0.1 },
      qwen3guard: { id: "q", tiers: ["allow", "review", "block"], recall: 0.9, fp: 0.5 },
      nemoguard: { id: "n", tiers: ["allow", "block"], recall: 0.6, fp: 0.4 },
    },
  };
  const out = summarizeGuardEfficacy(allHighFP);
  assert.equal(out.winner.name, null);
  assert.match(out.winner.reason, /L3 AlignmentCheck holds BLOCK authority/);
});

test("guard-efficacy: null FP disqualifies — never silently treated as passing", () => {
  const nullFP = {
    fp_threshold: 0.2,
    guards: {
      "heuristic-l1": { id: "l1", tiers: ["allow", "review", "block"], recall: 0.1, fp: 0.1 },
      nemoguard: { id: "n", tiers: ["allow", "block"], recall: 0.6, fp: null },
    },
  };
  const out = summarizeGuardEfficacy(nullFP);
  const nemo = out.guards.find((g) => g.name === "nemoguard");
  assert.equal(nemo.block_eligible, false);
  assert.equal(out.winner.name, null);
});

test("guard-efficacy: all-unparsed-benign guard does NOT qualify (fp not fabricated-clean)", () => {
  // H-1 regression: a guard whose every benign reply went UNPARSED would, under the
  // buggy denominator, read fp→0 and qualify for BLOCK on a fabricated-clean FP. The
  // fail-honest rule must apply to FP too: unparsed_benign>0 invalidates fp.
  const allUnparsedBenign = {
    fp_threshold: 0.2,
    guards: {
      "heuristic-l1": { id: "l1", tiers: ["allow", "review", "block"], recall: 0.1, fp: 0.1, unparsed_benign: 0 },
      ghostguard: {
        id: "g",
        tiers: ["allow", "block"],
        recall: 0.9,
        fp: 0, // looks perfect — but every benign sample was unparsed (non-measurement)
        unparsed_benign: 120,
        unparsed_injection: 3,
      },
    },
  };
  const out = summarizeGuardEfficacy(allUnparsedBenign);
  const ghost = out.guards.find((g) => g.name === "ghostguard");
  assert.equal(ghost.fp_valid, false); // fp is NOT a valid measurement
  assert.equal(ghost.block_eligible, false); // therefore not BLOCK-eligible
  assert.equal(ghost.unparsed_benign, 120); // separate count surfaced
  assert.equal(ghost.unparsed_injection, 3); // injection drops surfaced separately
  assert.equal(out.winner.name, null); // no fabricated BLOCK qualification
  assert.match(out.winner.reason, /L3 AlignmentCheck holds BLOCK authority/);
});

test("guard-efficacy: a qualifying winner carries the fp-validity caveat + unparsed counts", () => {
  const out = summarizeGuardEfficacy(FIXTURE);
  assert.equal(out.winner.name, "nemoguard");
  assert.match(out.winner.caveat, /unparsed_benign==0/);
  const byName = Object.fromEntries(out.guards.map((g) => [g.name, g]));
  // separate counts replace the single 'unparsed' total
  assert.equal(byName.nemoguard.unparsed_benign, 0);
  assert.equal(byName.nemoguard.unparsed_injection, 9);
  assert.equal(byName.qwen3guard.unparsed_injection, 5);
  assert.equal(byName.nemoguard.fp_valid, true);
  // legacy single 'unparsed' field must NOT leak through
  assert.ok(!("unparsed" in byName.nemoguard));
});

test("guard-efficacy: exact tie on recall among qualifiers yields no arbitrary winner", () => {
  const tie = {
    fp_threshold: 0.2,
    guards: {
      "heuristic-l1": { id: "l1", tiers: ["allow", "review", "block"], recall: 0.1, fp: 0.1, unparsed_benign: 0 },
      guardA: { id: "a", tiers: ["allow", "block"], recall: 0.7, fp: 0.1, unparsed_benign: 0 },
      guardB: { id: "b", tiers: ["allow", "block"], recall: 0.7, fp: 0.15, unparsed_benign: 0 },
    },
  };
  const out = summarizeGuardEfficacy(tie);
  assert.equal(out.winner.name, null);
  assert.match(out.winner.reason, /tie on recall/);
});

test("guard-efficacy: fp_threshold defaults to documented bar when payload omits it", () => {
  const noThreshold = {
    guards: {
      "heuristic-l1": { id: "l1", tiers: ["allow", "review", "block"], recall: 0.1, fp: 0.1, unparsed_benign: 0 },
      nemoguard: { id: "n", tiers: ["allow", "block"], recall: 0.6, fp: 0.108, unparsed_benign: 0 },
    },
  };
  const out = summarizeGuardEfficacy(noThreshold);
  assert.equal(out.winner.fp_threshold, DEFAULT_FP_THRESHOLD);
  assert.equal(out.winner.name, "nemoguard");
});

test("guard-efficacy: injectable l1Keys + fpThreshold override the defaults", () => {
  // Re-classify qwen3guard as L1 and raise the bar so it would qualify if L2.
  const out = summarizeGuardEfficacy(FIXTURE, { l1Keys: ["qwen3guard"], fpThreshold: 0.4 });
  const byName = Object.fromEntries(out.guards.map((g) => [g.name, g]));
  assert.equal(byName.qwen3guard.layer, "L1");
  assert.equal(byName.qwen3guard.block_eligible, false); // L1 never eligible
  assert.equal(byName["heuristic-l1"].layer, "L2"); // no longer in l1Keys
  // With bar 0.4: heuristic-l1 (now L2, fp 0.12) and nemoguard (fp 0.108) qualify;
  // nemoguard recall 0.656 > heuristic-l1 0.135 → nemoguard wins.
  assert.equal(out.winner.name, "nemoguard");
});

test("guard-efficacy: pure — does not mutate the input results", () => {
  const snapshot = JSON.parse(JSON.stringify(FIXTURE));
  summarizeGuardEfficacy(FIXTURE);
  assert.deepEqual(FIXTURE, snapshot);
});

test("guard-efficacy: returns frozen structures (no downstream mutation)", () => {
  const out = summarizeGuardEfficacy(FIXTURE);
  assert.ok(Object.isFrozen(out));
  assert.ok(Object.isFrozen(out.guards));
  assert.ok(Object.isFrozen(out.guards[0]));
  assert.ok(Object.isFrozen(out.perLayer));
});

test("guard-efficacy: rejects a payload with no guards object", () => {
  assert.throws(() => summarizeGuardEfficacy({}), /results\.guards object is required/);
  assert.throws(() => summarizeGuardEfficacy(null), /results\.guards object is required/);
});
