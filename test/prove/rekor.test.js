// Rekor v2 keyId-anchor tests. Offline verification runs against a REAL bundle
// captured from the public Rekor v2 instance (test/fixtures/rekor/), so the
// Merkle inclusion proof + checkpoint Ed25519 signature are verified against
// genuine log data — deterministic, no network. The publish path is covered with
// an injected fetch.
//
// Fixture provenance / Procedencia del fixture (re-anchored 2026-05-29, item 0.3b):
//   keyId    835ae008640ccd0a8a2174b3c7535fc4
//   log      log2025-1.rekor.sigstore.dev   logIndex 4729698   treeSize 4729699
//   The subject digest is now sha256(SPKI DER) (full 32-byte hash), NOT the old
//   keyId-padded-with-zeros fabrication. Re-anchored for real against Rekor v2
//   production via `synthex rekor-anchor`; the verifier now checks subjectDigest.
//   El digest del subject es sha256(SPKI DER) completo; re-anclado real contra
//   Rekor v2 producción. El verificador ahora chequea subjectDigest.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { generateKeyPair } from "../../src/prove/asymmetric.js";
import { pae, buildKeyIdStatement, anchorKeyId, verifyRekorBundle, rootFromInclusionProof } from "../../src/prove/rekor.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const bundle = JSON.parse(readFileSync(join(HERE, "..", "fixtures", "rekor", "keyid-anchor-bundle.json"), "utf8"));
const clone = (o) => JSON.parse(JSON.stringify(o));

test("pae: DSSE pre-auth encoding shape", () => {
  assert.equal(pae("t", "body").toString(), "DSSEv1 1 t 4 body");
});

test("buildKeyIdStatement: in-toto statement binds keyId + pubkey", () => {
  const { payloadType, payload } = buildKeyIdStatement({ keyId: "abc", publicKeySpkiB64: "xyz" });
  assert.equal(payloadType, "application/vnd.in-toto+json");
  const s = JSON.parse(payload.toString());
  assert.equal(s._type, "https://in-toto.io/Statement/v1");
  assert.equal(s.predicate.keyId, "abc");
  assert.equal(s.predicate.publicKeySpkiB64, "xyz");
});

test("buildKeyIdStatement: rejects missing fields", () => {
  assert.throws(() => buildKeyIdStatement({ keyId: "x" }), TypeError);
});

test("verifyRekorBundle: real bundle → ok with all checks true", () => {
  const v = verifyRekorBundle(bundle);
  assert.equal(v.ok, true, `reason: ${v.reason}`);
  for (const [k, val] of Object.entries(v.checks)) assert.equal(val, true, `check ${k} should pass`);
});

test("verifyRekorBundle: tampered statement payload → bad-dsse-signature", () => {
  const t = clone(bundle);
  const p = JSON.parse(Buffer.from(t.envelope.payload, "base64").toString());
  p.predicate.keyId = "evil";
  t.envelope.payload = Buffer.from(JSON.stringify(p)).toString("base64");
  const v = verifyRekorBundle(t);
  assert.equal(v.ok, false);
  assert.equal(v.reason, "bad-dsse-signature");
});

test("verifyRekorBundle: tampered canonicalizedBody → inclusion-proof-mismatch", () => {
  const t = clone(bundle);
  const body = Buffer.from(t.tlogEntry.canonicalizedBody, "base64");
  body[body.length - 5] ^= 0xff;
  t.tlogEntry.canonicalizedBody = body.toString("base64");
  const v = verifyRekorBundle(t);
  assert.equal(v.ok, false);
  assert.equal(v.reason, "inclusion-proof-mismatch");
});

test("verifyRekorBundle: tampered proof hash → inclusion-proof-mismatch", () => {
  const t = clone(bundle);
  const h = Buffer.from(t.tlogEntry.inclusionProof.hashes[0], "base64");
  h[0] ^= 0xff;
  t.tlogEntry.inclusionProof.hashes[0] = h.toString("base64");
  const v = verifyRekorBundle(t);
  assert.equal(v.ok, false);
  assert.equal(v.reason, "inclusion-proof-mismatch");
});

test("verifyRekorBundle: tampered checkpoint signature → bad-checkpoint-signature", () => {
  const t = clone(bundle);
  const env = t.tlogEntry.inclusionProof.checkpoint.envelope;
  const sep = env.indexOf("\n\n—");
  const head = env.slice(0, sep + 2);
  const lines = env.slice(sep + 2).split("\n");
  const i = lines.findIndex((l) => l.trim().startsWith("—"));
  const parts = lines[i].trim().split(" ");
  const blob = Buffer.from(parts[parts.length - 1], "base64");
  blob[10] ^= 0xff; // a signature byte (>=4 → leaves the 4-byte key hint intact)
  parts[parts.length - 1] = blob.toString("base64");
  lines[i] = parts.join(" ");
  t.tlogEntry.inclusionProof.checkpoint.envelope = head + lines.join("\n");
  const v = verifyRekorBundle(t);
  assert.equal(v.ok, false);
  assert.equal(v.reason, "bad-checkpoint-signature");
});

test("verifyRekorBundle: unpinned log origin → unpinned-log-origin", () => {
  const v = verifyRekorBundle(bundle, { logs: [], findLog: () => null });
  assert.equal(v.ok, false);
  assert.equal(v.reason, "unpinned-log-origin");
});

test("verifyRekorBundle: malformed bundle → malformed-bundle (no throw)", () => {
  assert.equal(verifyRekorBundle(null).reason, "malformed-bundle");
  assert.equal(verifyRekorBundle({}).reason, "malformed-bundle");
});

test("rootFromInclusionProof: index out of range throws", () => {
  assert.throws(() => rootFromInclusionProof(5, 5, Buffer.alloc(32), []));
});

test("anchorKeyId: builds DSSE + Ed25519 verifier and assembles a bundle (injected fetch)", async () => {
  const kp = generateKeyPair();
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, body: JSON.parse(init.body) };
    return { status: 201, text: async () => JSON.stringify(bundle.tlogEntry) };
  };
  const out = await anchorKeyId(kp.privateKeyPem, {
    keyId: kp.keyId, publicKeySpkiB64: kp.publicKeySpkiB64, fetchImpl,
  });
  assert.match(captured.url, /\/api\/v2\/log\/entries$/);
  const req = captured.body.dsseRequestV002;
  assert.equal(req.verifiers[0].keyDetails, "PKIX_ED25519");
  assert.equal(req.verifiers[0].publicKey.rawBytes, kp.publicKeySpkiB64);
  assert.ok(req.envelope.signatures[0].sig, "must carry a DSSE signature");
  assert.equal(out.format, "synthex-rekor-anchor-v1");
  assert.equal(out.keyId, kp.keyId);
  assert.ok(out.tlogEntry);
});

test("anchorKeyId: non-201 response throws", async () => {
  const kp = generateKeyPair();
  const fetchImpl = async () => ({ status: 400, text: async () => '{"message":"nope"}' });
  await assert.rejects(
    () => anchorKeyId(kp.privateKeyPem, { keyId: kp.keyId, publicKeySpkiB64: kp.publicKeySpkiB64, fetchImpl }),
    /Rekor v2 anchor failed: HTTP 400/,
  );
});
