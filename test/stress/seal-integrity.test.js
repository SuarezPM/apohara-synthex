// Tests for the stress dimension (2) SEAL INTEGRITY. `node --test`.
// Uses the REAL shipped verifyEvidence (src/prove/evidence-report.js) injected as
// verifyImpl, with fixtures built by the REAL buildEvidence. ZERO network:
// requestTsa:false everywhere, Rekor/C2PA exercised via injected stub verifiers.
import { test } from "node:test";
import assert from "node:assert/strict";

import { buildEvidence, verifyEvidence } from "../../src/prove/evidence-report.js";
import { generateKeyPair } from "../../src/prove/asymmetric.js";
import { verifySealIntegrity } from "../../scripts/stress/dimensions/seal-integrity.mjs";

const HMAC_KEY = "synthex-stress-seal-integrity-key";

// One fully sealed (HMAC + Ed25519) artifact and one symmetric-only (HMAC) one.
// No TSA layer (requestTsa:false) → tsaOk is null (absent), which is honest offline.
async function buildFixtures() {
  const kp = generateKeyPair();
  const sealed = await buildEvidence(
    { target: "example.com", findings: ["a", "b"], schema_version: 3 },
    { hmacKey: HMAC_KEY, requestTsa: false, signingKey: kp.privateKeyPem },
  );
  const symmetricOnly = await buildEvidence(
    { target: "example.org", findings: ["c"], schema_version: 2 },
    { hmacKey: HMAC_KEY, requestTsa: false },
  );
  return { kp, sealed, symmetricOnly };
}

test("verifySealIntegrity: sealed + symmetric-only both verify; ed25519 counts only the signed one", async () => {
  const { sealed, symmetricOnly } = await buildFixtures();
  const out = await verifySealIntegrity(
    [
      { evidence: sealed, opts: { hmacKey: HMAC_KEY } },
      { evidence: symmetricOnly, opts: { hmacKey: HMAC_KEY } },
    ],
    { verifyImpl: verifyEvidence },
  );

  assert.equal(out.total, 2);
  assert.equal(out.verified, 2);
  assert.equal(out.failed, 0);
  // Only the Ed25519-signed artifact counts toward the ed25519 layer.
  assert.equal(out.byLayer.ed25519, 1);
  // No TSA layer present offline → not counted, not failed.
  assert.equal(out.byLayer.tsa, 0);
  assert.equal(out.byLayer.rekor, 0);
  assert.equal(out.byLayer.c2pa, 0);

  // symmetric-only artifact: layer absent (null), NOT counted as a pass.
  const symResult = out.results[1];
  assert.equal(symResult.verified, true);
  assert.equal(symResult.layers.ed25519, null);
});

test("verifySealIntegrity: tampered payload is detected, never counted as verified", async () => {
  const { sealed } = await buildFixtures();
  // Tamper the payload AFTER sealing → contentHash no longer matches.
  const tampered = { ...sealed, payload: { ...sealed.payload, findings: ["TAMPERED"] } };

  const out = await verifySealIntegrity(
    [{ evidence: tampered, opts: { hmacKey: HMAC_KEY } }],
    { verifyImpl: verifyEvidence },
  );

  assert.equal(out.total, 1);
  assert.equal(out.verified, 0);
  assert.equal(out.failed, 1);
  assert.equal(out.byLayer.ed25519, 0); // signature over the original bytes fails on tampered
  assert.equal(out.results[0].verified, false);
  assert.equal(out.results[0].reason, "hash-mismatch");
});

test("verifySealIntegrity: a bad Ed25519 signature is a present-but-failed layer → artifact fails", async () => {
  const { sealed } = await buildFixtures();
  // Corrupt the signature value but keep the payload/hash intact → hashOk true, sig false.
  const badSig = {
    ...sealed,
    seal: {
      ...sealed.seal,
      signature: { ...sealed.seal.signature, value: Buffer.from("garbage-signature-bytes").toString("base64") },
    },
  };

  const out = await verifySealIntegrity(
    [{ evidence: badSig, opts: { hmacKey: HMAC_KEY } }],
    { verifyImpl: verifyEvidence },
  );

  assert.equal(out.verified, 0);
  assert.equal(out.failed, 1);
  assert.equal(out.byLayer.ed25519, 0);
  assert.equal(out.results[0].layers.ed25519, false);
  assert.equal(out.results[0].reason, "ed25519-bad-signature");
});

test("verifySealIntegrity: Rekor/C2PA counted ONLY via their own injected verifiers", async () => {
  const { sealed } = await buildFixtures();
  const rekorBundle = { tlogEntry: { logIndex: 42 } }; // opaque to this dimension
  const c2paSidecar = { signature_b64: "deadbeef" };

  // Without rekorVerify/c2paVerify: present-unverified → NOT counted, but artifact still passes.
  const noVerifiers = await verifySealIntegrity(
    [{ evidence: sealed, opts: { hmacKey: HMAC_KEY }, rekorBundle, c2paSidecar }],
    { verifyImpl: verifyEvidence },
  );
  assert.equal(noVerifiers.byLayer.rekor, 0);
  assert.equal(noVerifiers.byLayer.c2pa, 0);
  assert.equal(noVerifiers.verified, 1, "present-unverified sidecars must not fail the artifact");
  assert.equal(noVerifiers.results[0].layers.rekor, "present-unverified");
  assert.equal(noVerifiers.results[0].layers.c2pa, "present-unverified");

  // With injected verifiers reporting ok → counted.
  const withVerifiers = await verifySealIntegrity(
    [{ evidence: sealed, opts: { hmacKey: HMAC_KEY }, rekorBundle, c2paSidecar }],
    {
      verifyImpl: verifyEvidence,
      rekorVerify: (b) => ({ ok: b.tlogEntry.logIndex === 42 }),
      c2paVerify: async (s) => ({ ok: s.signature_b64 === "deadbeef" }),
    },
  );
  assert.equal(withVerifiers.byLayer.rekor, 1);
  assert.equal(withVerifiers.byLayer.c2pa, 1);
  assert.equal(withVerifiers.verified, 1);

  // A failing Rekor verifier makes it a present-but-failed layer → artifact fails.
  const rekorFails = await verifySealIntegrity(
    [{ evidence: sealed, opts: { hmacKey: HMAC_KEY }, rekorBundle }],
    { verifyImpl: verifyEvidence, rekorVerify: () => ({ ok: false }) },
  );
  assert.equal(rekorFails.byLayer.rekor, 0);
  assert.equal(rekorFails.verified, 0);
  assert.equal(rekorFails.results[0].reason, "rekor-failed");
});

test("verifySealIntegrity: a throwing verifier fails that artifact, does not crash the batch", async () => {
  const { sealed } = await buildFixtures();
  // First call throws, the rest verify normally → batch must survive and mark only idx 0 failed.
  let calls = 0;
  const flakyVerify = async (ev, opts) => {
    if (calls++ === 0) throw new Error("boom");
    return verifyEvidence(ev, opts);
  };

  const out = await verifySealIntegrity(
    [
      { evidence: sealed, opts: { hmacKey: HMAC_KEY } },
      { evidence: sealed, opts: { hmacKey: HMAC_KEY } },
    ],
    { verifyImpl: flakyVerify },
  );

  assert.equal(out.total, 2);
  assert.equal(out.verified, 1);
  assert.equal(out.failed, 1);
  assert.match(out.results[0].reason, /verifier threw: boom/);
  assert.equal(out.results[1].verified, true);
});

test("verifySealIntegrity: accepts a bare evidence object (no wrapper)", async () => {
  const { symmetricOnly } = await buildFixtures();
  // Bare object, opts provided at the batch level via verifyOpts.
  const out = await verifySealIntegrity(
    [symmetricOnly],
    { verifyImpl: verifyEvidence, verifyOpts: { hmacKey: HMAC_KEY } },
  );
  assert.equal(out.total, 1);
  assert.equal(out.verified, 1);
});

test("verifySealIntegrity: missing verifyImpl throws (fail-fast contract)", async () => {
  await assert.rejects(
    () => verifySealIntegrity([], {}),
    /requires cfg\.verifyImpl/,
  );
});

test("verifySealIntegrity: empty list → zeroed, well-formed result", async () => {
  const out = await verifySealIntegrity([], { verifyImpl: verifyEvidence });
  assert.deepEqual(out, {
    total: 0,
    verified: 0,
    failed: 0,
    byLayer: { ed25519: 0, tsa: 0, rekor: 0, c2pa: 0 },
    results: [],
  });
});
