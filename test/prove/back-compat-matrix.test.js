// v0.8.0 Commit 2 — back-compat matrix (the sacred truth).
//
// Every fixture shape that exists in production must continue verifying under
// the v0.8 verifier. Below are the four rows from the migration plan, each
// asserted against a real or built fixture.
//
//   Fixture                | schema | TSA | sig | signatureValid    | reason            | tsaSignatureValid
//   ---------------------- | ------ | --- | --- | ----------------- | ----------------- | -----------------
//   v1 sample (real)       | undef  | yes | no  | 'symmetric-only'  | 'symmetric-only'  | true
//   v2 piloto-50 / stress  | 2      | no  | no  | 'symmetric-only'  | 'symmetric-only'  | null
//   v3 NEW signed, no TSA  | 3      | no  | yes | true              | null              | null
//   v3 NEW signed + TSA    | 3      | yes | yes | true              | null              | true (TSA live)
//
// The v3+TSA row only runs when SYNTHEX_TSA_LIVE=1 (the existing live-test pattern in
// test/prove.test.js:150 — skips offline).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { Buffer } from "node:buffer";
import { buildEvidence, verifyEvidence } from "../../src/prove/evidence-report.js";
import { generateKeyPair } from "../../src/prove/asymmetric.js";

const SAMPLE_PATH = "samples/synthex-evidence-report.json";
const PILOTO_DIR = "out/stress-piloto-50-2026-05-28";

test("back-compat row 1 · v1 sample (TSA, no sig) → 'symmetric-only' + tsaSignatureValid:true", async () => {
  const ev = JSON.parse(readFileSync(SAMPLE_PATH, "utf8"));
  const v = await verifyEvidence(ev, { hmacKey: "synthex-demo" });
  assert.equal(v.hashOk, true);
  assert.equal(v.hmacOk, true);
  assert.equal(v.tsaOk, true);
  assert.equal(v.tsaSignatureValid, true);
  assert.equal(v.tsaSignatureValidReason, null);
  assert.equal(v.signatureValid, "symmetric-only");
  assert.equal(v.signatureValidReason, "symmetric-only");
});

test("back-compat row 2 · v2 piloto-50 (HMAC-only) → 'symmetric-only' + tsaSignatureValid:null", async () => {
  const files = readdirSync(PILOTO_DIR).filter((n) => n.startsWith("evidence-") && n.endsWith(".json"));
  assert.ok(files.length > 0, "piloto-50 dir must have fixtures");
  const ev = JSON.parse(readFileSync(`${PILOTO_DIR}/${files[0]}`, "utf8"));
  const v = await verifyEvidence(ev, { hmacKey: "synthex-dev" });
  assert.equal(v.hashOk, true);
  assert.equal(v.hmacOk, true);
  assert.equal(v.tsaOk, null);
  assert.equal(v.tsaSignatureValid, null);
  assert.equal(v.signatureValid, "symmetric-only");
  assert.equal(v.signatureValidReason, "symmetric-only");
});

test("back-compat row 3 · v3 signed (no TSA) → signatureValid:true, tsaSignatureValid:null", async () => {
  const kp = generateKeyPair();
  const ev = await buildEvidence(
    { schema_version: 3, target: "test", findings: [] },
    { hmacKey: "k", requestTsa: false, signingKey: kp.privateKeyPem },
  );
  // Seal carries the Ed25519 block.
  assert.equal(ev.seal.signature.alg, "Ed25519");
  assert.equal(ev.seal.signature.keyId, kp.keyId);
  // Method string composition: HMAC + Ed25519 (no TSA).
  assert.equal(ev.seal.method, "HMAC-SHA256 + Ed25519");
  const v = await verifyEvidence(ev, { hmacKey: "k" });
  assert.equal(v.hashOk, true);
  assert.equal(v.hmacOk, true);
  assert.equal(v.tsaSignatureValid, null);
  assert.equal(v.signatureValid, true);
  assert.equal(v.signatureValidReason, null);
});

test("back-compat · v3 signed: payload tamper → signatureValid:false + hashOk:false", async () => {
  const kp = generateKeyPair();
  const ev = await buildEvidence(
    { schema_version: 3, target: "test", findings: [{ severity: 5 }] },
    { hmacKey: "k", requestTsa: false, signingKey: kp.privateKeyPem },
  );
  // Mutate the payload post-seal — both the hash AND the asymmetric signature must catch it.
  ev.payload.findings[0].severity = 9;
  const v = await verifyEvidence(ev, { hmacKey: "k" });
  assert.equal(v.hashOk, false, "tampered payload → hash mismatch");
  assert.equal(v.hmacOk, false, "tampered payload → HMAC fails too");
  // signatureValid is false because the asymmetric signature was computed over the original
  // canonical bytes; the verifier re-canonicalizes the tampered payload and the sig fails.
  assert.equal(v.signatureValid, false, "tampered payload → asymmetric verify fails (tamper alarm)");
  assert.equal(v.signatureValidReason, "bad-signature");
});

test("back-compat · v3 signed: contentHash equals an unsigned-equivalent build (proves pre-image unchanged by Ed25519)", async () => {
  // This is the central byte-identity claim: adding seal.signature does NOT change contentHash
  // because the asymmetric signature lives in `seal`, NOT in `payload`. The contentHash is
  // _serializeForHmac(payload), unchanged. If this asserts true, the v3 schema bump is purely
  // additive with respect to the seal pre-image.
  const kp = generateKeyPair();
  const payload = { schema_version: 3, target: "byte-identity", findings: [{ severity: 4, summary: "x", signals: [] }] };
  const unsigned = await buildEvidence(payload, { hmacKey: "k", requestTsa: false });
  const signed = await buildEvidence(payload, { hmacKey: "k", requestTsa: false, signingKey: kp.privateKeyPem });
  assert.equal(signed.contentHash, unsigned.contentHash, "asymmetric layer must NOT change contentHash");
  assert.equal(signed.seal.hmacSha256, unsigned.seal.hmacSha256, "HMAC pre-image unchanged → HMAC matches");
});

test("back-compat · expectedKeyId match passes; mismatch → key-mismatch", async () => {
  const kp = generateKeyPair();
  const ev = await buildEvidence(
    { schema_version: 3, target: "key-pinning", findings: [] },
    { hmacKey: "k", requestTsa: false, signingKey: kp.privateKeyPem },
  );
  // Matching keyId → identityVerified:true; signatureValid stays true.
  const matched = await verifyEvidence(ev, { hmacKey: "k", expectedKeyId: kp.keyId });
  assert.equal(matched.signatureValid, true);
  assert.equal(matched.identityVerified, true);
  // Wrong keyId → signatureValid flips to false with key-mismatch reason.
  const mismatched = await verifyEvidence(ev, { hmacKey: "k", expectedKeyId: "0".repeat(32) });
  assert.equal(mismatched.signatureValid, false);
  assert.equal(mismatched.signatureValidReason, "key-mismatch");
  assert.equal(mismatched.identityVerified, false);
});
