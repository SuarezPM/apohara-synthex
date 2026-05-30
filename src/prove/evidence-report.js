// PROVE — Evidence Report sellado. Sello base HMAC-SHA256 (siempre); capa
// opcional RFC 3161 TSA (DigiCert) si hay red; capa opcional Ed25519
// asymmetric signature (v0.8.0) si hay signing key. Fallback honesto a
// HMAC-only.
//
// Schema versions:
//   v1 (legacy, Synthex ≤v3) — `JSON.stringify(payload)` para HMAC.
//   v2 (Synthex v4–v0.7)     — `canonicalize(payload)` para HMAC.
//   v3 (Synthex v0.8+)       — same canonical bytes as v2 PLUS optional
//                              additive `seal.signature` (Ed25519 over the
//                              same canonical pre-image) and optional
//                              `seal.signerIdentity` (publication channel
//                              pointer for keyId out-of-band discovery).
//
// El verifier auto-detecta `payload.schema_version`. v3 cae por el branch
// `>= 2 ? canonicalize : JSON.stringify` igual que v2 — el contentHash
// pre-image es byte-identical entre v2 y v3 para el mismo payload. La
// migración v0.7→v0.8 es PURAMENTE aditiva en `seal`, NUNCA en `payload`.
//
// `signatureValid` (v0.8 NEW semantics) refleja la firma asimétrica:
//   true              → Ed25519 verify ok
//   false             → Ed25519 verify FAIL (tamper alarm)
//   'symmetric-only'  → no hay `seal.signature` (v1/v2 fixtures; v3 sin
//                       signing key) — NO es failure, es explainer
//   null              → malformed evidence (shape-guard path)
//
// `tsaSignatureValid` carries the OLD signatureValid TSA meaning (CMS
// chain verify) so the TSA verdict is preserved separately.
import { sha256, hmacSign, hmacVerify } from "./hmac.js";
import { requestTimestamp, verifyTimestamp } from "./tsa.js";
import { canonicalize } from "./canonicalize.js";
import { sign as asymSign, verify as asymVerify } from "./asymmetric.js";

export const HMAC_EXCLUDED_KEYS = Object.freeze([
  "kg_status",
  "kg_latency_ms",
  "surface_status",
  // Emit-metadata del classifier: si truncó el INPUT al LLM (la raw text del payload
  // sigue intacta). Fuera del HMAC pre-image → contentHash idéntico haya o no truncación.
  "truncated",
  "charsSeen",
  // Flag visible "low confidence" del tier free; sólo informativo para UI/PDF.
  "lowConfidenceTier",
]);

function _stripExcludedKeys(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(_stripExcludedKeys);
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (HMAC_EXCLUDED_KEYS.includes(k)) continue;
    out[k] = _stripExcludedKeys(v);
  }
  return out;
}

function _serializeForHmac(payload) {
  // strip HMAC_EXCLUDED_KEYS ANTES de detectar schema_version y canonicalizar.
  // Sin mutar el payload original (deep-copy via _stripExcludedKeys).
  const filtered = _stripExcludedKeys(payload);
  // Auto-detect: v>=2 → canonicalize; v=1/ausente → JSON.stringify legacy.
  // v3 cae por el branch `>= 2` — pre-image byte-identical with v2.
  const v = filtered && typeof filtered === "object" ? filtered.schema_version : undefined;
  return (v !== undefined && v >= 2) ? canonicalize(filtered) : JSON.stringify(filtered);
}

function _composeMethod({ hmac, signature, tsa }) {
  const parts = [];
  if (hmac) parts.push("HMAC-SHA256");
  if (signature) parts.push("Ed25519");
  if (tsa) parts.push("RFC 3161 TSA");
  return parts.join(" + ");
}

/**
 * Construye un Evidence Report a partir de un payload serializable.
 * @param {object} payload
 * @param {{
 *   hmacKey?:string,
 *   requestTsa?:boolean,
 *   signingKey?:string,      // v0.8.0 — pkcs8 PEM/base64 of Ed25519 private key
 *   signerIdentity?:object,  // v0.8.0 — {channel,url} pointer to out-of-band publication
 * }} opts
 */
export async function buildEvidence(payload, { hmacKey, requestTsa = true, signingKey, signerIdentity } = {}) {
  const canonical = _serializeForHmac(payload);
  const hash = sha256(canonical); // Buffer 32B
  const hmac = hmacKey ? hmacSign(canonical, hmacKey) : null;

  // v0.8.0 — asymmetric signature layer. Signs the EXACT SAME canonical bytes
  // HMAC signs (byte-identity == C2PA hash.data equivalence argument).
  const signature = signingKey ? await asymSign(canonical, signingKey) : null;

  let tsa = null; // null => sin TSA (declarado, no fabricado)
  if (requestTsa) {
    try {
      const token = await requestTimestamp(new Uint8Array(hash));
      const v = await verifyTimestamp(token, new Uint8Array(hash));
      if (v.granted && v.match) {
        // Multi-TSA (R4): describe WHICH TSA produced the token from the configured URL. Plain
        // descriptor only — NEVER "qualified"/"eIDAS" (the free Actalis endpoint is NOT qualified).
        const tsaUrl = process.env.SYNTHEX_TSA_URL || "";
        const authority = /actalis/i.test(tsaUrl) ? "actalis" : "digicert";
        tsa = {
          standard: "RFC 3161",
          authority,
          token: Buffer.from(token).toString("base64"),
          genTime: v.genTime,
          serial: v.serial,
        };
      }
    } catch {
      tsa = null; // sin red / TSA caída → seguimos
    }
  }

  return {
    payload,
    contentHash: hash.toString("hex"),
    seal: {
      hmacSha256: hmac,                                       // sello base verificable offline
      rfc3161Tsa: tsa,                                        // capa de tercero (DigiCert)
      signature,                                              // v0.8.0 — Ed25519 (additive, nullable)
      signerIdentity: signature ? (signerIdentity ?? null) : null, // v0.8.0 — out-of-band identity pointer
      method: _composeMethod({ hmac, signature, tsa }),
    },
    sealedAt: new Date().toISOString(),
  };
}

/**
 * Verifica un Evidence Report. Devuelve qué pasó (no afirma lo que no comprobó).
 * Async porque verifyTimestamp + asymmetric verify usan webcrypto.subtle.
 *
 * Return shape (v0.8.0 — additive; v0.7 keys preserved or migrated as documented):
 *
 *   hashOk                     boolean
 *   hmacOk                     boolean | null
 *
 *   signatureValid             true | false | 'symmetric-only' | null  ← v0.8 MEANING CHANGED
 *   signatureValidReason       null | 'no-signature' | 'bad-signature' |
 *                              'malformed-signature' | 'key-mismatch' | 'symmetric-only'
 *
 *   tsaOk                      boolean | null   ← unchanged key + meaning
 *   tsaSignatureValid          boolean | null   ← v0.8 NEW (was the old v0.7 signatureValid)
 *   tsaSignatureValidReason    string | null    ← v0.8 NEW (was the old v0.7 signatureValidReason)
 *
 *   identityVerified           boolean | null   ← v0.8 NEW — Commit 3 wires --expected-keyid
 *   identityChannel            string | null    ← v0.8 NEW — channel name when verified
 *
 *   revocationChecked          boolean          ← v0.8 NEW — Commit 3 wires OCSP opt-in
 *   revocationStatus           'good'|'revoked'|'unknown'|null
 *
 *   error?                     'malformed evidence' (shape-guard path only)
 */
export async function verifyEvidence(evidence, {
  hmacKey,
  trustedCerts,
  expectedKeyId,
  checkRevocation = false,
  ocspTimeoutMs,
  ocspFetchImpl,
} = {}) {
  if (!evidence || typeof evidence !== "object" || !evidence.payload || typeof evidence.contentHash !== "string") {
    return {
      hashOk: false, hmacOk: null,
      signatureValid: null, signatureValidReason: null,
      tsaOk: null, tsaSignatureValid: null, tsaSignatureValidReason: null,
      identityVerified: null, identityChannel: null,
      revocationChecked: false, revocationStatus: null,
      error: "malformed evidence",
    };
  }
  const canonical = _serializeForHmac(evidence.payload);
  const hash = sha256(canonical);
  const hashOk = hash.toString("hex") === evidence.contentHash;

  const hmacSig = evidence.seal?.hmacSha256;
  const hmacOk = hmacSig && hmacKey ? hmacVerify(canonical, hmacKey, hmacSig) : null;

  // Asymmetric (Ed25519) layer — v0.8 NEW semantics for signatureValid.
  let signatureValid;
  let signatureValidReason;
  const sigBlock = evidence.seal?.signature;
  if (sigBlock) {
    const r = await asymVerify(canonical, sigBlock);
    if (r.ok && expectedKeyId && sigBlock.keyId !== expectedKeyId) {
      signatureValid = false;
      signatureValidReason = "key-mismatch";
    } else {
      signatureValid = r.ok;
      signatureValidReason = r.ok ? null : r.reason;
    }
  } else {
    // v1/v2 fixtures + v3 without signing key — explainer string, NOT failure.
    signatureValid = "symmetric-only";
    signatureValidReason = "symmetric-only";
  }

  // Identity (out-of-band publication) check. Default null until --expected-keyid wired
  // (Commit 3 adds the DNS / well-known fetch helpers). expectedKeyId presence alone
  // is integrity-not-identity per HONESTY §1.4; null is the honest default.
  let identityVerified = null;
  let identityChannel = null;
  if (expectedKeyId && sigBlock) {
    identityVerified = sigBlock.keyId === expectedKeyId;
    identityChannel = evidence.seal?.signerIdentity?.channel ?? null;
  }

  // TSA layer — old signatureValid meaning preserved under tsaSignatureValid*.
  // Revocation (OCSP) — opt-in via opts.checkRevocation; surfacing-only per
  // HONESTY §1.5 (revoked does NOT auto-flip tsaSignatureValid:false in v0.8).
  let tsaOk = null;
  let tsaSignatureValid = null;
  let tsaSignatureValidReason = null;
  let revocationChecked = false;
  let revocationStatus = null;
  const token = evidence.seal?.rfc3161Tsa?.token;
  if (token) {
    const der = new Uint8Array(Buffer.from(token, "base64"));
    const tsaOpts = {
      ...(trustedCerts !== undefined ? { trustedCerts } : {}),
      checkRevocation,
      ...(ocspTimeoutMs !== undefined ? { ocspTimeoutMs } : {}),
      ...(ocspFetchImpl !== undefined ? { ocspFetchImpl } : {}),
    };
    const v = await verifyTimestamp(der, new Uint8Array(hash), tsaOpts);
    tsaOk = v.granted && v.match;
    tsaSignatureValid = v.signatureValid;
    tsaSignatureValidReason = v.signatureValidReason;
    revocationChecked = v.revocationChecked === true;
    revocationStatus = v.revocationStatus ?? null;
  }

  return {
    hashOk, hmacOk,
    signatureValid, signatureValidReason,
    tsaOk, tsaSignatureValid, tsaSignatureValidReason,
    identityVerified, identityChannel,
    revocationChecked, revocationStatus,
  };
}
