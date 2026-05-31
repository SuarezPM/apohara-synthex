// Stress dimension: tamper-detection. `node --test`. ZERO network.
//
// Builds REAL sealed evidence with the shipped buildEvidence (HMAC-only and
// HMAC+Ed25519), then drives the dimension's injectTampers +
// measureTamperDetection against the shipped verifyEvidence. The contract under
// test: every injected tamper is detected (100%), an untouched seal verifies
// (0 false-accepts). No TSA is requested → no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildEvidence, verifyEvidence } from "../../src/prove/evidence-report.js";
import { generateKeyPair } from "../../src/prove/asymmetric.js";
import {
  injectTampers,
  measureTamperDetection,
  TAMPER_KINDS,
} from "../../scripts/stress/dimensions/tamper-detection.mjs";

const HMAC_KEY = "synthex-stress-tamper-key";

// Offline-only seals (requestTsa:false). One HMAC-only, one HMAC+Ed25519.
async function sealedFixtures() {
  const { privateKeyPem } = generateKeyPair();
  const payload = {
    target: "example.com",
    schema_version: 2,
    findings: [{ id: 1, severity: "high" }, { id: 2, severity: "low" }],
    note: "baseline",
  };
  const hmacOnly = await buildEvidence(payload, { hmacKey: HMAC_KEY, requestTsa: false });
  const signed = await buildEvidence(payload, {
    hmacKey: HMAC_KEY,
    requestTsa: false,
    signingKey: privateKeyPem,
    signerIdentity: { channel: "dns", url: "https://synthex.apohara.dev/.well-known/keyid" },
  });
  return { hmacOnly, signed };
}

const verifyImpl = (evidence) => verifyEvidence(evidence, { hmacKey: HMAC_KEY });

test("control: an untouched HMAC-only seal verifies", async () => {
  const { hmacOnly } = await sealedFixtures();
  const v = await verifyImpl(hmacOnly);
  assert.equal(v.hashOk, true);
  assert.equal(v.hmacOk, true);
});

test("control: an untouched HMAC+Ed25519 seal verifies", async () => {
  const { signed } = await sealedFixtures();
  const v = await verifyImpl(signed);
  assert.equal(v.hashOk, true);
  assert.equal(v.hmacOk, true);
  assert.equal(v.signatureValid, true);
});

test("injectTampers: does NOT mutate the input evidence", async () => {
  const { signed } = await sealedFixtures();
  const before = JSON.stringify(signed);
  const tampers = injectTampers(signed, 4);
  assert.equal(JSON.stringify(signed), before, "input must be untouched");
  assert.equal(tampers.length, 4);
  // every returned copy differs from the original in exactly its target field.
  for (const t of tampers) {
    assert.notEqual(JSON.stringify(t.evidence), before);
  }
});

test("injectTampers: only emits applicable kinds (no signature tamper on HMAC-only)", async () => {
  const { hmacOnly } = await sealedFixtures();
  const tampers = injectTampers(hmacOnly, TAMPER_KINDS.length);
  const kinds = new Set(tampers.map((t) => t.kind));
  assert.ok(kinds.has("contentHash"));
  assert.ok(kinds.has("payload"));
  assert.ok(kinds.has("hmac"));
  assert.ok(!kinds.has("signature"), "HMAC-only seal has no signature to tamper");
});

test("tampered contentHash is caught (hashOk false)", async () => {
  const { hmacOnly } = await sealedFixtures();
  const [t] = injectTampers(hmacOnly, 1); // first kind = contentHash
  assert.equal(t.kind, "contentHash");
  const v = await verifyImpl(t.evidence);
  assert.equal(v.hashOk, false);
});

test("tampered payload field is caught (hashOk false)", async () => {
  const { hmacOnly } = await sealedFixtures();
  const t = injectTampers(hmacOnly, 2)[1]; // second kind = payload
  assert.equal(t.kind, "payload");
  const v = await verifyImpl(t.evidence);
  assert.equal(v.hashOk, false);
});

test("tampered HMAC tag is caught (hmacOk false)", async () => {
  const { hmacOnly } = await sealedFixtures();
  const t = injectTampers(hmacOnly, 3)[2]; // third kind = hmac
  assert.equal(t.kind, "hmac");
  const v = await verifyImpl(t.evidence);
  assert.equal(v.hmacOk, false);
});

test("tampered Ed25519 signature is caught (signatureValid not true)", async () => {
  const { signed } = await sealedFixtures();
  const t = injectTampers(signed, 4)[3]; // fourth kind = signature
  assert.equal(t.kind, "signature");
  const v = await verifyImpl(t.evidence);
  assert.notEqual(v.signatureValid, true);
});

test("measureTamperDetection: 100% detected, 0 false-accepts on a sealed corpus", async () => {
  const { hmacOnly, signed } = await sealedFixtures();
  const m = await measureTamperDetection([hmacOnly, signed], { verifyImpl });
  // HMAC-only contributes 3 applicable kinds, signed contributes 4 → 7 tampers.
  assert.equal(m.injected, 7);
  assert.equal(m.detected, 7);
  assert.equal(m.falseAccepts, 0);
  assert.equal(m.controlFailures, 0);
  // per-kind: every injected of every kind detected.
  for (const k of Object.keys(m.byKind)) {
    assert.equal(m.byKind[k].detected, m.byKind[k].injected, `kind ${k} fully detected`);
  }
  assert.equal(typeof m.reproduce, "string");
});

test("measureTamperDetection: an untampered seal is NOT a false-accept (control passes)", async () => {
  const { hmacOnly } = await sealedFixtures();
  const m = await measureTamperDetection([hmacOnly], { verifyImpl });
  assert.equal(m.controlFailures, 0); // healthy seal verifies → no spurious failure
  assert.equal(m.falseAccepts, 0);
});

test("measureTamperDetection: a verifier that blindly passes everything surfaces falseAccepts", async () => {
  // A broken verifyImpl that always returns all-green MUST produce falseAccepts ==
  // injected — proving the harness measures the verifier, not a hardcoded pass.
  const { signed } = await sealedFixtures();
  const blindPass = () => ({ hashOk: true, hmacOk: true, signatureValid: true });
  const m = await measureTamperDetection([signed], { verifyImpl: blindPass });
  assert.equal(m.detected, 0);
  assert.equal(m.falseAccepts, m.injected);
  assert.ok(m.injected > 0);
});

test("measureTamperDetection: rejects a missing verifyImpl", async () => {
  await assert.rejects(
    () => measureTamperDetection([], {}),
    /verifyImpl must be a function/,
  );
});

test("injectTampers: rejects a non-object evidence", () => {
  assert.throws(() => injectTampers(null, 1), /sealed evidence object/);
});
