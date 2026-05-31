// Stress dimension (6) — DETERMINISM unit tests. Fixtures only, ZERO network.
// Drives checkDeterminism with deterministic + non-deterministic STUB runners
// to prove the measurement is honest: identical content collapses to one
// contentHash; volatile fields (sealedAt / TSA genTime+serial+token) are ignored;
// a genuinely non-deterministic runner is reported as such, never hidden.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  checkDeterminism,
  runDeterminismDimension,
  VOLATILE_FIELDS,
} from "../../scripts/stress/dimensions/determinism.mjs";

// ── stub sealers (no live run) ────────────────────────────────────────────────

// Deterministic sealer: same input → same contentHash + same stable seal block,
// but a FRESH volatile timestamp/TSA every call (exactly the shipped behaviour).
function deterministicSealer(input) {
  const contentHash = `hash-${JSON.stringify(input)}`;
  let tsaSerial = 0;
  return {
    contentHash,
    seal: {
      hmacSha256: `hmac-${contentHash}`,
      method: "HMAC-SHA256 + RFC 3161 TSA",
      rfc3161Tsa: {
        standard: "RFC 3161",
        authority: "digicert",
        // volatile: must NOT affect the determinism verdict
        genTime: new Date().toISOString(),
        serial: `${Date.now()}-${tsaSerial++}-${Math.random()}`,
        token: `tok-${Math.random()}`,
      },
    },
    sealedAt: new Date().toISOString(), // volatile
  };
}

// Non-deterministic sealer: same input yields a DIFFERENT contentHash each call.
// This is the failure mode the dimension must catch, not mask.
function nonDeterministicSealer(input) {
  return {
    contentHash: `hash-${JSON.stringify(input)}-${Math.random()}`,
    seal: { hmacSha256: "x", method: "HMAC-SHA256" },
    sealedAt: new Date().toISOString(),
  };
}

// Sealer whose content is stable but whose SEAL pre-image drifts (e.g. method
// string flips between runs). contentHash matches but seal does not.
let sealDriftToggle = false;
function sealDriftSealer(input) {
  sealDriftToggle = !sealDriftToggle;
  return {
    contentHash: `hash-${JSON.stringify(input)}`,
    seal: { hmacSha256: sealDriftToggle ? "a" : "b", method: "HMAC-SHA256" },
    sealedAt: new Date().toISOString(),
  };
}

// ── checkDeterminism: the contract ────────────────────────────────────────────

test("checkDeterminism · identical content → one contentHash → deterministic across n runs", () => {
  const r = checkDeterminism({ url: "https://x.test", content: "hello" }, deterministicSealer, 5);
  assert.equal(r.runs, 5);
  assert.equal(r.uniqueContentHashes, 1, "identical content must yield exactly one contentHash");
  assert.equal(r.deterministic, true);
});

test("checkDeterminism · volatile fields (sealedAt/TSA genTime+serial+token) are IGNORED", () => {
  // deterministicSealer mints a fresh timestamp + TSA serial + token every call;
  // determinism must still be true because those fields are volatile.
  const r = checkDeterminism({ id: 1 }, deterministicSealer, 10);
  assert.equal(r.deterministic, true);
  assert.equal(r.uniqueSealPreImages, 1, "seal pre-image must collapse to one once volatile fields are stripped");
});

test("checkDeterminism · returns the exact contract shape {runs, uniqueContentHashes, deterministic}", () => {
  const r = checkDeterminism({ a: 1 }, deterministicSealer, 3);
  assert.equal(typeof r.runs, "number");
  assert.equal(typeof r.uniqueContentHashes, "number");
  assert.equal(typeof r.deterministic, "boolean");
  // honest extras (no fabricated metrics) — transparent evidence, not claims
  assert.ok(Array.isArray(r.contentHashes));
  assert.equal(typeof r.uniqueSealPreImages, "number");
  assert.equal(typeof r.nullRuns, "number");
});

test("checkDeterminism · non-deterministic runner is reported, NOT masked", () => {
  const r = checkDeterminism({ url: "https://x.test" }, nonDeterministicSealer, 4);
  assert.equal(r.uniqueContentHashes, 4, "each run drifts → four distinct hashes");
  assert.equal(r.deterministic, false);
});

test("checkDeterminism · stable contentHash but drifting seal pre-image → NOT deterministic", () => {
  sealDriftToggle = false;
  const r = checkDeterminism({ k: "v" }, sealDriftSealer, 4);
  assert.equal(r.uniqueContentHashes, 1, "content is stable");
  assert.ok(r.uniqueSealPreImages > 1, "seal pre-image drifts");
  assert.equal(r.deterministic, false, "seal drift must fail determinism even with stable content");
});

test("checkDeterminism · a run with no usable contentHash poisons determinism (fail-safe)", () => {
  const flaky = (input) => ({ contentHash: undefined, seal: {} });
  const r = checkDeterminism({ x: 1 }, flaky, 3);
  assert.equal(r.nullRuns, 3);
  assert.equal(r.deterministic, false);
});

test("checkDeterminism · n is clamped to >=1 and runFn must be a function", () => {
  const r0 = checkDeterminism({ a: 1 }, deterministicSealer, 0);
  assert.equal(r0.runs, 1, "n<1 clamps to 1");
  const rNeg = checkDeterminism({ a: 1 }, deterministicSealer, -5);
  assert.equal(rNeg.runs, 1);
  assert.throws(() => checkDeterminism({}, "not-a-fn", 2), TypeError);
});

test("checkDeterminism · does not mutate the injected input", () => {
  const input = Object.freeze({ url: "https://x.test", nested: Object.freeze({ a: 1 }) });
  // a frozen input would throw on mutation — proves no write path touches it
  assert.doesNotThrow(() => checkDeterminism(input, deterministicSealer, 3));
});

test("checkDeterminism · seal-object key order does not affect the verdict", () => {
  // two runs return the same seal with keys in different insertion order
  let flip = false;
  const reorderingSealer = (input) => {
    flip = !flip;
    const seal = flip
      ? { hmacSha256: "h", method: "HMAC-SHA256" }
      : { method: "HMAC-SHA256", hmacSha256: "h" };
    return { contentHash: "stable", seal, sealedAt: new Date().toISOString() };
  };
  const r = checkDeterminism({ a: 1 }, reorderingSealer, 6);
  assert.equal(r.uniqueSealPreImages, 1, "key order must not break the seal pre-image match");
  assert.equal(r.deterministic, true);
});

test("VOLATILE_FIELDS · is frozen and includes sealedAt + TSA volatile fields", () => {
  assert.ok(Object.isFrozen(VOLATILE_FIELDS));
  for (const f of ["sealedAt", "genTime", "serial", "token"]) {
    assert.ok(VOLATILE_FIELDS.includes(f), `${f} must be treated as volatile`);
  }
});

// ── harness adapter ───────────────────────────────────────────────────────────

test("runDeterminismDimension · aggregates per-artifact and matches the dimension contract", () => {
  const corpus = {
    artifacts: [
      { url: "https://a.test", content: "one" },
      { url: "https://b.test", content: "two" },
      { url: "https://c.test", content: "three" },
    ],
  };
  const d = runDeterminismDimension(corpus, deterministicSealer, 3);
  assert.equal(d.status, "OK");
  assert.equal(d.dimension, "determinism");
  assert.equal(d.artifacts, 3);
  assert.equal(d.deterministic_artifacts, 3);
  assert.equal(d.all_deterministic, true);
  assert.equal(typeof d.reproduce, "string");
  assert.ok(d.reproduce.includes("determinism"));
});

test("runDeterminismDimension · a non-deterministic sealer lowers the aggregate honestly", () => {
  const corpus = { artifacts: [{ url: "https://a.test" }, { url: "https://b.test" }] };
  const d = runDeterminismDimension(corpus, nonDeterministicSealer, 3);
  assert.equal(d.status, "OK");
  assert.equal(d.deterministic_artifacts, 0);
  assert.equal(d.all_deterministic, false);
});

test("runDeterminismDimension · empty corpus → NOT_IMPLEMENTED (nothing measured, no fake metric)", () => {
  const d = runDeterminismDimension({ artifacts: [] }, deterministicSealer, 2);
  assert.equal(d.status, "NOT_IMPLEMENTED");
  assert.equal(d.artifacts, 0);
  assert.equal(d.all_deterministic, false);
});
