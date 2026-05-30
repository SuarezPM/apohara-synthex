// C2PA (v0.8.0) — Content Provenance and Authenticity sidecar emission.
//
// **Honest framing (HONESTY §1.6 is binding):**
//   - This implementation builds a structurally-spec-shaped C2PA sidecar
//     wrapping our Ed25519 seal. The seal IS the source of truth;
//     C2PA is an interoperability narrative on top, for tooling that wants
//     the Content Credentials format.
//   - `c2patool verify` interop is the GOAL but not auto-verified by `npm test`
//     (c2patool is a Rust binary, not on npm). See `scripts/c2pa-interop-test.sh`
//     for the explicit run-when-installed gate. If c2patool rejects EdDSA in your
//     environment, switch to ES256 (the spec also supports it — RFC 8152 §8.1).
//   - Algorithm: Ed25519 (COSE alg -8 EdDSA per RFC 8152). C2PA v2 spec text:
//     "ES256, ES384, ES512, PS256, PS384, PS512, EdDSA".
//   - Cert: self-signed X.509 wrapping the Ed25519 public key, generated at
//     keygen time. NOT a CA-issued cert — provides integrity binding within the
//     sidecar, NOT external CA-rooted identity. CA-rooted identity is a v0.9
//     goal (Sigstore/Rekor or CA-issued cert).
//
// **Cbor-x usage:** the only new dep added in v0.8.0. MIT, well-maintained, fast.
// Used in canonical (Core-Deterministic) mode so two emissions of the same claim
// produce byte-identical sidecars.
import { Buffer } from "node:buffer";
import { randomBytes, webcrypto, createPublicKey, createPrivateKey, createHash } from "node:crypto";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { Encoder, Tag as CborTag, decode as cborDecode } from "cbor-x";

// ─── Constants ────────────────────────────────────────────────────────────
const ED25519_OID = "1.3.101.112"; // RFC 8410 §3
const EKU_DOCUMENT_SIGNING_OID = "1.3.6.1.5.5.7.3.36"; // id-kp-documentSigning, RFC 9336
const COSE_SIGN1_TAG = 18;
const COSE_HEADER_ALG = 1;
const COSE_HEADER_X5CHAIN = 33;
const COSE_ALG_EDDSA = -8;

// CAWG (Creator Assertions Working Group) identity assertion (v1.0.0 item R2). This adds a
// structurally spec-shaped `cawg.identity` assertion (sig_type `cawg.x509.cose`) binding the
// signer's SELF-SIGNED organizational identity to the SAME c2pa.hash.data hard-binding hash, via a
// COSE_Sign1 over the signer_payload with the SAME self-signed Ed25519 cert. **Honest (binding):**
// SELF-SIGNED + UNTRUSTED — it asserts WHO claims the org identity, not that any trust ecosystem
// vouches for it. NOT CA-rooted, NOT the CAWG Organizational Identity Profile, and NOT validated by
// c2patool in this sidecar path (c2patool never reads our JSON sidecar — that path is disjoint from
// evidence-card.js). It is "structurally spec-shaped", verified by our own verifyC2paManifest. A
// c2patool-VALIDATED CAWG identity (native [cawg_x509_signer] flow) is separate future work.
const CAWG_IDENTITY_LABEL = "cawg.identity";
const CAWG_SIG_TYPE = "cawg.x509.cose";

// Canonical CBOR encoder — definite-length, integer-keyed maps, sorted.
// `mapsAsObjects: false` keeps Map() instances as CBOR maps (not converted to
// objects with string keys, which would fail COSE header structure).
const _encoder = new Encoder({
  mapsAsObjects: false,
  useRecords: false,
  variableMapSize: false,
});
const cborEncode = (v) => new Uint8Array(_encoder.encode(v));

pkijs.setEngine("synthex-c2pa", new pkijs.CryptoEngine({ name: "synthex-c2pa", crypto: webcrypto }));

// ─── Self-signed X.509 with Ed25519 ───────────────────────────────────────

/**
 * Build a self-signed X.509 cert wrapping an Ed25519 public key. Returns DER.
 *
 * Intended use: pin the seal's signer identity into the C2PA x5chain header so
 * downstream C2PA-aware tools can introspect "who signed this." NOT a CA-rooted
 * identity — the cert is self-attesting (operator's keyId is the real identity
 * via DNS / .well-known publication; see HONESTY §1.4).
 *
 * @param {{
 *   privateKeyPem: string,
 *   publicKeyPem: string,
 *   commonName?: string,
 *   organization?: string,
 *   validityDays?: number,
 * }} opts
 * @returns {Promise<Uint8Array>} X.509 DER
 */
export async function buildSelfSignedEd25519Cert(opts) {
  const {
    privateKeyPem,
    publicKeyPem,
    commonName = "Apohara Synthex Evidence Signer",
    organization = "Apohara",
    validityDays = 3650,
  } = opts;

  const cert = new pkijs.Certificate();
  cert.version = 2; // X.509 v3
  cert.serialNumber = new asn1js.Integer({ valueHex: randomBytes(16).buffer });

  const dn = (cn, o) => [
    new pkijs.AttributeTypeAndValue({ type: "2.5.4.3", value: new asn1js.Utf8String({ value: cn }) }),
    new pkijs.AttributeTypeAndValue({ type: "2.5.4.10", value: new asn1js.Utf8String({ value: o }) }),
  ];
  cert.issuer.typesAndValues = dn(commonName, organization);
  cert.subject.typesAndValues = dn(commonName, organization);

  cert.notBefore.value = new Date();
  cert.notAfter.value = new Date(Date.now() + validityDays * 24 * 60 * 60 * 1000);

  // SubjectPublicKeyInfo from Ed25519 SPKI
  const pubKeyObj = createPublicKey(publicKeyPem);
  const spkiDer = pubKeyObj.export({ type: "spki", format: "der" });
  const spkiAsn1 = asn1js.fromBER(
    spkiDer.buffer.slice(spkiDer.byteOffset, spkiDer.byteOffset + spkiDer.byteLength),
  );
  cert.subjectPublicKeyInfo = new pkijs.PublicKeyInfo({ schema: spkiAsn1.result });

  // RFC 5280 keyIdentifier (method 1): SHA-1 of the raw public key bytes.
  // Ed25519 SPKI DER is 44 bytes; the trailing 32 are the raw public key.
  // c2pa-rs's check_certificate_profile requires AKI present on the end-entity
  // (aki_good) — without it the cert is rejected as "certificate params incorrect".
  const rawPubKey = Buffer.from(spkiDer).subarray(-32);
  const keyIdentifier = createHash("sha1").update(rawPubKey).digest();
  const kidAb = new Uint8Array(keyIdentifier).buffer;

  // Extensions: KeyUsage (digitalSignature) + BasicConstraints (CA:FALSE) +
  // ExtendedKeyUsage (id-kp-documentSigning). The EKU is what c2pa-rs's
  // certificate_trust_policy validates the end-entity profile against — without
  // it c2patool rejects the cert outright. 1.3.6.1.5.5.7.3.36 (RFC 9336) is in
  // c2pa-rs's default valid_eku_oids allow-list, so no custom trust_config is
  // needed for the manifest to validate (the signer is still "untrusted source"
  // because it's self-signed — see HONESTY §1.6).
  cert.extensions = [
    new pkijs.Extension({
      extnID: "2.5.29.15",
      critical: true,
      extnValue: new asn1js.BitString({
        valueHex: new Uint8Array([0x80]).buffer, // bit 0 = digitalSignature
        unusedBits: 7,
      }).toBER(false),
    }),
    new pkijs.Extension({
      extnID: "2.5.29.19",
      critical: true,
      extnValue: new asn1js.Sequence({ value: [new asn1js.Boolean({ value: false })] }).toBER(false),
    }),
    new pkijs.Extension({
      extnID: "2.5.29.37", // extKeyUsage
      critical: false,
      extnValue: new pkijs.ExtKeyUsage({
        keyPurposes: [EKU_DOCUMENT_SIGNING_OID],
      }).toSchema().toBER(false),
    }),
    new pkijs.Extension({
      extnID: "2.5.29.14", // subjectKeyIdentifier
      critical: false,
      extnValue: new asn1js.OctetString({ valueHex: kidAb }).toBER(false),
    }),
    new pkijs.Extension({
      extnID: "2.5.29.35", // authorityKeyIdentifier (self-issued → points at own SKI)
      critical: false,
      extnValue: new asn1js.Sequence({
        value: [
          // [0] keyIdentifier IMPLICIT OCTET STRING
          new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 }, valueHex: kidAb }),
        ],
      }).toBER(false),
    }),
  ];

  cert.signatureAlgorithm = new pkijs.AlgorithmIdentifier({ algorithmId: ED25519_OID });
  cert.signature = new pkijs.AlgorithmIdentifier({ algorithmId: ED25519_OID });

  // Manual Ed25519 sign of the TBS — pkijs.cert.sign() doesn't natively
  // handle Ed25519 (no separate hashAlgo), so we do it via webcrypto.subtle.
  const tbsBer = cert.encodeTBS().toBER(false);
  const privKeyObj = createPrivateKey(privateKeyPem);
  const pkcs8Der = privKeyObj.export({ type: "pkcs8", format: "der" });
  const cryptoKey = await webcrypto.subtle.importKey(
    "pkcs8",
    pkcs8Der.buffer.slice(pkcs8Der.byteOffset, pkcs8Der.byteOffset + pkcs8Der.byteLength),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const sig = await webcrypto.subtle.sign("Ed25519", cryptoKey, tbsBer);
  cert.signatureValue = new asn1js.BitString({ valueHex: sig });

  return new Uint8Array(cert.toSchema(true).toBER(false));
}

// ─── CAWG identity assertion (R2) ──────────────────────────────────────────

/**
 * Build a CAWG `cawg.identity` assertion (sig_type cawg.x509.cose): a COSE_Sign1 over the
 * signer_payload, signed with the SAME self-signed Ed25519 cert (x5chain). The signer_payload binds
 * the SAME c2pa.hash.data hard-binding hash (NOT a recompute — reuses contentHashBytes). The COSE
 * payload is ATTACHED, so the verifier rebuilds Sig_structure from the attached bytes (no canonical
 * re-encoding needed). Self-signed → untrusted org identity (see header).
 * @param {Uint8Array} contentHashBytes  the c2pa.hash.data hash bytes (the hard binding).
 * @param {Uint8Array} x509CertDer
 * @param {string} signingKey  pkcs8 PEM
 * @param {{role?:string[]}} [opts]
 * @returns {Promise<{signer_payload:Map, signature:Uint8Array, pad1:Uint8Array}>}
 */
async function _buildCawgAssertion(contentHashBytes, x509CertDer, signingKey, { role = ["cawg.creator"] } = {}) {
  const signerPayload = new Map([
    ["referenced_assertions", [new Map([
      ["url", "self#jumbf=c2pa.assertions/c2pa.hash.data"],
      ["hash", contentHashBytes],
    ])]],
    ["sig_type", CAWG_SIG_TYPE],
    ["role", role],
  ]);
  const signerPayloadCbor = cborEncode(signerPayload);
  // COSE_Sign1 protected header {1:-8 EdDSA, 33:[cert]} — same shape as the claim signature.
  const protectedBytes = cborEncode(new Map([[COSE_HEADER_ALG, COSE_ALG_EDDSA], [COSE_HEADER_X5CHAIN, [x509CertDer]]]));
  const sigStructureBytes = cborEncode(["Signature1", protectedBytes, new Uint8Array(0), signerPayloadCbor]);
  const privKeyObj = createPrivateKey(signingKey);
  const pkcs8Der = privKeyObj.export({ type: "pkcs8", format: "der" });
  const cryptoKey = await webcrypto.subtle.importKey(
    "pkcs8", pkcs8Der.buffer.slice(pkcs8Der.byteOffset, pkcs8Der.byteOffset + pkcs8Der.byteLength),
    { name: "Ed25519" }, false, ["sign"],
  );
  const signature = new Uint8Array(await webcrypto.subtle.sign("Ed25519", cryptoKey, sigStructureBytes));
  // Attached payload (signer_payload CBOR) so the verifier needs no canonical re-encoding.
  const coseSign1Bytes = cborEncode(new CborTag([protectedBytes, new Map(), signerPayloadCbor, signature], COSE_SIGN1_TAG));
  return new Map([
    ["signer_payload", signerPayload],
    ["signature", coseSign1Bytes],
    ["pad1", new Uint8Array(0)],
  ]);
}

// ─── C2PA manifest builder ────────────────────────────────────────────────

/**
 * Build a C2PA sidecar binding the evidence's contentHash via a c2pa.hash.data
 * assertion, signed with the same Ed25519 key as the seal but wrapped in a
 * self-signed X.509 cert for x5chain compliance.
 *
 * @param {object} evidence  — output of buildEvidence()
 * @param {{
 *   x509CertDer: Uint8Array,
 *   signingKey: string,        // pkcs8 PEM
 *   generatorVersion?: string,
 *   softwareAgent?: string,
 * }} opts
 * @returns {Promise<{
 *   sidecar: object,           // JSON-serializable sidecar object
 *   claimCbor: Uint8Array,
 *   coseSign1Bytes: Uint8Array,
 * }>}
 */
export async function buildC2paManifest(evidence, opts) {
  const {
    x509CertDer,
    signingKey,
    generatorVersion = "0.8.0",
    softwareAgent = "Apohara Synthex",
    includeCawgIdentity = true, // R2 — append the self-signed CAWG identity assertion
    orgIdentity = { role: ["cawg.creator"] },
  } = opts;

  if (!evidence?.contentHash || typeof evidence.contentHash !== "string") {
    throw new TypeError("buildC2paManifest: evidence.contentHash (hex string) is required");
  }

  const contentHashBytes = Buffer.from(evidence.contentHash, "hex");

  // C2PA v2-shaped claim. Maps preserved as Maps for canonical encoding.
  const claim = {
    claim_generator_info: [{ name: softwareAgent, version: generatorVersion }],
    created_assertions: [
      { label: "c2pa.hash.data", hash: contentHashBytes, alg: "sha256", name: "synthex-evidence" },
      {
        label: "c2pa.actions",
        actions: [{
          action: "c2pa.created",
          softwareAgent: `${softwareAgent} ${generatorVersion}`,
          when: evidence.sealedAt,
        }],
      },
    ],
    instance_id: `urn:uuid:${_uuid4()}`,
  };
  // R2 — append the CAWG identity assertion LAST (c2pa.hash.data stays first; verify finds it
  // order-independently via .find). Self-signed/untrusted org identity bound to the same hash.
  if (includeCawgIdentity) {
    const cawg = await _buildCawgAssertion(contentHashBytes, x509CertDer, signingKey, { role: orgIdentity.role });
    claim.created_assertions.push({
      label: CAWG_IDENTITY_LABEL,
      signer_payload: cawg.get("signer_payload"),
      signature: cawg.get("signature"),
      pad1: cawg.get("pad1"),
    });
  }
  const claimCbor = cborEncode(claim);

  // COSE_Sign1 protected header: {1: -8 (EdDSA), 33: [cert DER]}.
  // Integer keys → Map() (objects use string keys, which would fail COSE).
  const protectedHeader = new Map([
    [COSE_HEADER_ALG, COSE_ALG_EDDSA],
    [COSE_HEADER_X5CHAIN, [x509CertDer]],
  ]);
  const protectedBytes = cborEncode(protectedHeader);

  // Sig_structure (RFC 8152 §4.4): ["Signature1", protected, external_aad, payload]
  const sigStructure = ["Signature1", protectedBytes, new Uint8Array(0), claimCbor];
  const sigStructureBytes = cborEncode(sigStructure);

  const privKeyObj = createPrivateKey(signingKey);
  const pkcs8Der = privKeyObj.export({ type: "pkcs8", format: "der" });
  const cryptoKey = await webcrypto.subtle.importKey(
    "pkcs8",
    pkcs8Der.buffer.slice(pkcs8Der.byteOffset, pkcs8Der.byteOffset + pkcs8Der.byteLength),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await webcrypto.subtle.sign("Ed25519", cryptoKey, sigStructureBytes));

  // COSE_Sign1 = [protected, unprotected, payload, signature], tagged 18.
  // Attached payload (claim CBOR) so the sidecar is self-contained — easier for
  // operators who want to inspect the claim without re-running the pipeline.
  const coseSign1 = new CborTag([protectedBytes, new Map(), claimCbor, signature], COSE_SIGN1_TAG);
  const coseSign1Bytes = cborEncode(coseSign1);

  const sidecar = {
    format: "synthex-c2pa-sidecar-v1",
    spec: "C2PA v2",
    generator: `${softwareAgent} ${generatorVersion}`,
    evidence_content_hash: evidence.contentHash,
    claim_b64: Buffer.from(claimCbor).toString("base64"),
    signature_b64: Buffer.from(coseSign1Bytes).toString("base64"),
    cert_x509_b64: Buffer.from(x509CertDer).toString("base64"),
  };

  return { sidecar, claimCbor, coseSign1Bytes };
}

// ─── C2PA verifier (our own) ──────────────────────────────────────────────

/**
 * Verify our own C2PA sidecar: COSE_Sign1 math + cert binding + hash binding to
 * the evidence's contentHash. Returns `{ok, reason, claim?, contentHash?}`.
 * NEVER throws.
 *
 * @param {object} sidecar — the JSON wrapper from buildC2paManifest
 * @param {{ expectedContentHash?: string }} [opts]
 */
export async function verifyC2paManifest(sidecar, opts = {}) {
  try {
    if (!sidecar || typeof sidecar !== "object" || !sidecar.signature_b64) {
      return { ok: false, reason: "malformed-sidecar" };
    }
    const coseSign1Bytes = Buffer.from(sidecar.signature_b64, "base64");
    const decoded = cborDecode(coseSign1Bytes);

    const coseArray = decoded instanceof CborTag ? decoded.value : decoded;
    if (!Array.isArray(coseArray) || coseArray.length !== 4) {
      return { ok: false, reason: "malformed-cose-sign1" };
    }
    const [protectedBytes, _unprotected, payload, signature] = coseArray;

    const protectedHeader = cborDecode(_toBuf(protectedBytes));
    if (protectedHeader === null || typeof protectedHeader !== "object") {
      return { ok: false, reason: "protected-not-decodable" };
    }
    // cbor-x's default decoder returns Object for integer-keyed CBOR maps; some
    // configurations return Map. Accept both via a small accessor.
    const alg = _readCoseHeader(protectedHeader, COSE_HEADER_ALG);
    if (alg !== COSE_ALG_EDDSA) return { ok: false, reason: `unsupported-alg-${alg}` };
    const x5chain = _readCoseHeader(protectedHeader, COSE_HEADER_X5CHAIN);
    if (!Array.isArray(x5chain) || x5chain.length === 0) return { ok: false, reason: "missing-x5chain" };

    // Extract pubkey from leaf cert
    const certBytes = _toBuf(x5chain[0]);
    const certAsn1 = asn1js.fromBER(
      certBytes.buffer.slice(certBytes.byteOffset, certBytes.byteOffset + certBytes.byteLength),
    );
    if (certAsn1.offset === -1) return { ok: false, reason: "cert-parse-error" };
    const cert = new pkijs.Certificate({ schema: certAsn1.result });
    const spkiBer = cert.subjectPublicKeyInfo.toSchema().toBER(false);

    const cryptoKey = await webcrypto.subtle.importKey(
      "spki", spkiBer, { name: "Ed25519" }, false, ["verify"],
    );

    // Rebuild Sig_structure and verify
    const sigStructure = ["Signature1", _toBuf(protectedBytes), new Uint8Array(0), _toBuf(payload)];
    const sigStructureBytes = cborEncode(sigStructure);
    const sigBuf = _toBuf(signature);
    const sigOk = await webcrypto.subtle.verify(
      "Ed25519", cryptoKey,
      sigBuf.buffer.slice(sigBuf.byteOffset, sigBuf.byteOffset + sigBuf.byteLength),
      sigStructureBytes.buffer.slice(sigStructureBytes.byteOffset, sigStructureBytes.byteOffset + sigStructureBytes.byteLength),
    );
    if (!sigOk) return { ok: false, reason: "bad-signature" };

    // Decode claim, check hash binding
    const claim = cborDecode(_toBuf(payload));
    const createdAssertions = _readField(claim, "created_assertions");
    if (!Array.isArray(createdAssertions)) return { ok: false, reason: "missing-created_assertions" };
    const hashAssertion = createdAssertions.find((a) => _readField(a, "label") === "c2pa.hash.data");
    if (!hashAssertion) return { ok: false, reason: "missing-hash-assertion" };
    const claimedHashHex = Buffer.from(_toBuf(_readField(hashAssertion, "hash"))).toString("hex");

    if (opts.expectedContentHash && claimedHashHex !== opts.expectedContentHash) {
      return { ok: false, reason: "hash-mismatch", contentHash: claimedHashHex };
    }
    // Also cross-check against sidecar's stated contentHash if present.
    if (sidecar.evidence_content_hash && claimedHashHex !== sidecar.evidence_content_hash) {
      return { ok: false, reason: "hash-mismatch-vs-sidecar", contentHash: claimedHashHex };
    }

    // R2 — CAWG identity assertion (additive, self-signed/untrusted). Absent → present:false
    // (back-compat: old sidecars + includeCawgIdentity:false still verify ok). Verify the inner
    // COSE_Sign1 over the ATTACHED signer_payload against the SAME leaf cert key, and that the
    // CAWG referenced hash binds the SAME contentHash.
    let cawg = { present: false };
    const cawgAssertion = createdAssertions.find((a) => _readField(a, "label") === CAWG_IDENTITY_LABEL);
    if (cawgAssertion) {
      const coseBytes = _toBuf(_readField(cawgAssertion, "signature"));
      const cose = cborDecode(coseBytes);
      const coseArr = cose instanceof CborTag ? cose.value : cose;
      if (!Array.isArray(coseArr) || coseArr.length !== 4) return { ok: false, reason: "cawg-malformed" };
      const [cawgProtected, , cawgPayload, cawgSig] = coseArr;
      const cawgSigStructBytes = cborEncode(["Signature1", _toBuf(cawgProtected), new Uint8Array(0), _toBuf(cawgPayload)]);
      const cawgSigBuf = _toBuf(cawgSig);
      const cawgOk = await webcrypto.subtle.verify(
        "Ed25519", cryptoKey,
        cawgSigBuf.buffer.slice(cawgSigBuf.byteOffset, cawgSigBuf.byteOffset + cawgSigBuf.byteLength),
        cawgSigStructBytes.buffer.slice(cawgSigStructBytes.byteOffset, cawgSigStructBytes.byteOffset + cawgSigStructBytes.byteLength),
      );
      if (!cawgOk) return { ok: false, reason: "cawg-bad-signature" };
      const sp = cborDecode(_toBuf(cawgPayload));
      const refs = _readField(sp, "referenced_assertions");
      const refHashHex = Array.isArray(refs) && refs[0] ? Buffer.from(_toBuf(_readField(refs[0], "hash"))).toString("hex") : null;
      if (refHashHex !== claimedHashHex) return { ok: false, reason: "cawg-hash-mismatch", contentHash: claimedHashHex };
      cawg = { present: true, sigType: _readField(sp, "sig_type"), selfSigned: true, trusted: false };
    }

    return { ok: true, reason: null, claim, contentHash: claimedHashHex, cawg };
  } catch (e) {
    return { ok: false, reason: `decode-error: ${e?.message ?? String(e)}` };
  }
}

// ─── helpers ──────────────────────────────────────────────────────────────

/** Read COSE integer-keyed header from either Map or Object form. */
function _readCoseHeader(headerObj, intKey) {
  if (headerObj instanceof Map) return headerObj.get(intKey);
  // Objects: cbor-x may render integer keys as numeric or string properties.
  if (intKey in headerObj) return headerObj[intKey];
  return headerObj[String(intKey)];
}

/** Read a field from a claim object (Map or Object form). */
function _readField(obj, key) {
  if (obj == null) return undefined;
  if (obj instanceof Map) return obj.get(key);
  return obj[key];
}

function _toBuf(v) {
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (Buffer.isBuffer(v)) return new Uint8Array(v);
  return new Uint8Array(v);
}

function _uuid4() {
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = b.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}
