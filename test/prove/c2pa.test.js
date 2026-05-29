// Tests para src/prove/c2pa.js — round-trip build + verify, tampering, hash binding.
// Interop con c2patool (Rust binary) NO se cubre acá — ver scripts/c2pa-interop-test.sh.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { Buffer } from "node:buffer";
import { createPublicKey, createHash } from "node:crypto";
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

test("buildSelfSignedEd25519Cert: incluye EKU documentSigning + AKI + SKI (perfil c2pa-rs)", async () => {
  // c2pa-rs check_certificate_profile exige, para el end-entity (CA:FALSE):
  // EKU en allow-list + AKI presente + KeyUsage digitalSignature. Sin las 3,
  // c2patool rechaza el cert como "the certificate is invalid".
  const kp = generateKeyPair();
  const der = await buildSelfSignedEd25519Cert({ privateKeyPem: kp.privateKeyPem, publicKeyPem: kp.publicKeyPem });
  const asn1 = asn1js.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
  const cert = new pkijs.Certificate({ schema: asn1.result });
  const ext = (oid) => cert.extensions.find((e) => e.extnID === oid);

  const eku = ext("2.5.29.37");
  assert.ok(eku, "cert debe tener ExtendedKeyUsage (2.5.29.37)");
  assert.ok(eku.parsedValue?.keyPurposes?.includes("1.3.6.1.5.5.7.3.36"),
    "EKU debe incluir id-kp-documentSigning (1.3.6.1.5.5.7.3.36, RFC 9336)");
  assert.ok(ext("2.5.29.14"), "cert debe tener SubjectKeyIdentifier (2.5.29.14)");
  assert.ok(ext("2.5.29.35"), "cert debe tener AuthorityKeyIdentifier (2.5.29.35)");
});

test("buildSelfSignedEd25519Cert: SKI y AKI keyId == SHA-1(pubkey raw) (self-issued)", async () => {
  const kp = generateKeyPair();
  const der = await buildSelfSignedEd25519Cert({ privateKeyPem: kp.privateKeyPem, publicKeyPem: kp.publicKeyPem });
  const asn1 = asn1js.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
  const cert = new pkijs.Certificate({ schema: asn1.result });

  const spkiDer = createPublicKey(kp.publicKeyPem).export({ type: "spki", format: "der" });
  const rawPub = Buffer.from(spkiDer).subarray(-32);
  const expectedKid = createHash("sha1").update(rawPub).digest("hex");

  const ski = cert.extensions.find((e) => e.extnID === "2.5.29.14");
  const skiHex = Buffer.from(ski.parsedValue.valueBlock.valueHexView).toString("hex");
  assert.equal(skiHex, expectedKid, "SKI debe ser SHA-1 de la pubkey raw");

  const aki = cert.extensions.find((e) => e.extnID === "2.5.29.35");
  const akiHex = Buffer.from(aki.parsedValue.keyIdentifier.valueBlock.valueHexView).toString("hex");
  assert.equal(akiHex, expectedKid, "AKI keyIdentifier debe igualar el SKI (self-issued)");
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
