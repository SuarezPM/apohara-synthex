// Tests para src/prove/c2pa.js — round-trip build + verify, tampering, hash binding.
// Interop con c2patool (Rust binary) NO se cubre acá — ver scripts/c2pa-interop-test.sh.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { Buffer } from "node:buffer";
import { generateKeyPair } from "../../src/prove/asymmetric.js";
import { buildEvidence } from "../../src/prove/evidence-report.js";
import { buildSelfSignedEd25519Cert, buildC2paManifest, verifyC2paManifest } from "../../src/prove/c2pa.js";

// Pequeño helper: arma un evidence sellado + cert + sidecar listos para verify.
async function _fixture() {
  const kp = generateKeyPair();
  const certDer = await buildSelfSignedEd25519Cert({
    privateKeyPem: kp.privateKeyPem,
    publicKeyPem: kp.publicKeyPem,
    validityDays: 365,
  });
  const evidence = await buildEvidence({ test: true, schema_version: 3 }, {
    hmacKey: "k",
    requestTsa: false,
    signingKey: kp.privateKeyPem,
  });
  const { sidecar } = await buildC2paManifest(evidence, {
    x509CertDer: certDer,
    signingKey: kp.privateKeyPem,
  });
  return { kp, certDer, evidence, sidecar };
}

test("buildSelfSignedEd25519Cert: produce DER parseable + SPKI = clave Ed25519", async () => {
  const kp = generateKeyPair();
  const der = await buildSelfSignedEd25519Cert({
    privateKeyPem: kp.privateKeyPem,
    publicKeyPem: kp.publicKeyPem,
    validityDays: 30,
  });
  assert.ok(der instanceof Uint8Array);
  assert.ok(der.length > 100, "DER debe tener tamaño realista para X.509");

  // Parsea con pkijs
  const asn1 = asn1js.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
  assert.notEqual(asn1.offset, -1);
  const cert = new pkijs.Certificate({ schema: asn1.result });
  // SignatureAlgorithm debe ser Ed25519 OID (1.3.101.112)
  assert.equal(cert.signatureAlgorithm.algorithmId, "1.3.101.112");
  // SubjectPublicKey OID también Ed25519
  assert.equal(cert.subjectPublicKeyInfo.algorithm.algorithmId, "1.3.101.112");
});

test("buildSelfSignedEd25519Cert: defaults — CN='Apohara Synthex Evidence Signer'", async () => {
  const kp = generateKeyPair();
  const der = await buildSelfSignedEd25519Cert({
    privateKeyPem: kp.privateKeyPem,
    publicKeyPem: kp.publicKeyPem,
  });
  const asn1 = asn1js.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
  const cert = new pkijs.Certificate({ schema: asn1.result });
  const cn = cert.subject.typesAndValues.find((t) => t.type === "2.5.4.3");
  assert.match(cn.value.valueBlock.value, /Apohara Synthex/);
});

test("buildC2paManifest + verifyC2paManifest: round-trip OK", async () => {
  const { evidence, sidecar } = await _fixture();
  const v = await verifyC2paManifest(sidecar);
  assert.equal(v.ok, true, `verify failed: ${v.reason}`);
  assert.equal(v.contentHash, evidence.contentHash);
  assert.ok(v.claim, "claim debe estar decodificado");
});

test("buildC2paManifest: sidecar shape — claim/signature/cert b64 + content_hash bound", async () => {
  const { evidence, sidecar } = await _fixture();
  assert.equal(sidecar.format, "synthex-c2pa-sidecar-v1");
  assert.equal(sidecar.spec, "C2PA v2");
  assert.equal(sidecar.evidence_content_hash, evidence.contentHash);
  assert.ok(sidecar.claim_b64);
  assert.ok(sidecar.signature_b64);
  assert.ok(sidecar.cert_x509_b64);
});

test("verifyC2paManifest: expectedContentHash mismatch → hash-mismatch", async () => {
  const { sidecar } = await _fixture();
  const v = await verifyC2paManifest(sidecar, {
    expectedContentHash: "0".repeat(64),
  });
  assert.equal(v.ok, false);
  assert.equal(v.reason, "hash-mismatch");
});

test("verifyC2paManifest: signature tampered → bad-signature", async () => {
  const { sidecar } = await _fixture();
  // Flip 1 byte cerca del final del COSE_Sign1 (que es donde vive la signature)
  const sig = Buffer.from(sidecar.signature_b64, "base64");
  sig[sig.length - 5] ^= 0xff;
  const tampered = { ...sidecar, signature_b64: sig.toString("base64") };
  const v = await verifyC2paManifest(tampered);
  assert.equal(v.ok, false);
  assert.match(v.reason, /bad-signature|decode-error|malformed/);
});

test("verifyC2paManifest: sidecar malformado → malformed-sidecar (no throw)", async () => {
  const v = await verifyC2paManifest(null);
  assert.equal(v.ok, false);
  assert.equal(v.reason, "malformed-sidecar");
  const v2 = await verifyC2paManifest({});
  assert.equal(v2.ok, false);
});

test("verifyC2paManifest: sidecar.evidence_content_hash mismatched vs claim → hash-mismatch-vs-sidecar", async () => {
  const { sidecar } = await _fixture();
  const tampered = { ...sidecar, evidence_content_hash: "0".repeat(64) };
  const v = await verifyC2paManifest(tampered);
  assert.equal(v.ok, false);
  assert.equal(v.reason, "hash-mismatch-vs-sidecar");
});

test("buildC2paManifest: rechaza evidence sin contentHash", async () => {
  const kp = generateKeyPair();
  const certDer = await buildSelfSignedEd25519Cert({
    privateKeyPem: kp.privateKeyPem,
    publicKeyPem: kp.publicKeyPem,
  });
  await assert.rejects(
    () => buildC2paManifest({}, { x509CertDer: certDer, signingKey: kp.privateKeyPem }),
    TypeError,
  );
});
