// RFC 3161 Trusted Timestamp (DigiCert) — JS puro.
//
// Verificación CMS custom (NO usamos `signed.verify()` de pkijs porque su path
// para OCTET STRING constructed eContent retorna "Missed detached data input
// array" o "TSTInfo verification is failed" aun con `data` explícito — bug
// upstream de pkijs con CMS attached signature). Hacemos verify manual con
// webcrypto:
//   1. messageDigest attribute matches sha256(eContent value bytes)
//   2. signature math: webcrypto.subtle.verify sobre signedAttrs DER (tag
//      IMPLICIT [0] swap 0xA0 → SET 0x31) contra signer cert public key
//   3. Chain: walk signer → issuer (CMS certs ∪ anchors) verificando cada
//      cert's signature contra issuer pubkey, hasta llegar a un anchor pin
//      por fingerprint SHA-256.
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { Buffer } from "node:buffer";
import { webcrypto, createHash } from "node:crypto";
import { loadAnchors } from "./tsa-anchors.js";
import { checkRevocation } from "./ocsp.js";

const DEFAULT_TSA_URL = "http://timestamp.digicert.com";
const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4";

// Cert validity hardening (v0.8.0, audit 2026-05-29 reviewer F5–F7).
const EXT_KEY_USAGE_OID = "2.5.29.37";              // X.509 v3 extKeyUsage extension
const ID_KP_TIMESTAMPING_OID = "1.3.6.1.5.5.7.3.8"; // RFC 3161 §2.3 — required on TSA responder cert

pkijs.setEngine("synthex", new pkijs.CryptoEngine({ name: "synthex", crypto: webcrypto }));

function toArrayBuffer(bytes) {
  if (bytes instanceof ArrayBuffer) return bytes;
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

/**
 * Mapea (sigAlgo OID, optional digestAlgo OID) → spec webcrypto.subtle.
 * Cubre los algos de DigiCert TSA actuales (RSA PKCS#1 v1.5 con SHA-256/384/512).
 * Para SignerInfo.signatureAlgorithm == rsaEncryption (1.2.840.113549.1.1.1),
 * se requiere digestAlgo del SignerInfo para resolver el hash; sin él se asume
 * SHA-256 (ver fallback defensivo abajo).
 */
function resolveWebCryptoAlgo(sigAlgo, digestAlgo) {
  if (sigAlgo === "1.2.840.113549.1.1.11") return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  if (sigAlgo === "1.2.840.113549.1.1.12") return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" };
  if (sigAlgo === "1.2.840.113549.1.1.13") return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" };
  if (sigAlgo === "1.2.840.113549.1.1.1" && digestAlgo === SHA256_OID) {
    return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  }
  if (sigAlgo === "1.2.840.113549.1.1.1" && digestAlgo === "2.16.840.1.101.3.4.2.2") {
    return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" };
  }
  if (sigAlgo === "1.2.840.113549.1.1.1" && digestAlgo === "2.16.840.1.101.3.4.2.3") {
    return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" };
  }
  // Certificate.signatureAlgorithm no almacena el digest aparte (a diferencia de
  // SignerInfo.digestAlgorithm). Si un futuro issuer firma un cert con bare
  // rsaEncryption, sin digestAlgo no podemos inferir el hash → default a SHA-256
  // (mínimo moderno) para darle chance de verificar en vez de mislabel como
  // "chain-incomplete". Fails closed igual: si el hash real no es SHA-256, la
  // verificación crypto simplemente devuelve false.
  if (sigAlgo === "1.2.840.113549.1.1.1") return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  return null;
}

function certDerFingerprint(cert) {
  const der = cert.toSchema(true).toBER(false);
  return createHash("sha256").update(Buffer.from(der)).digest("hex");
}

function dnDer(dn) {
  return Buffer.from(dn.toSchema().toBER(false));
}

/**
 * Cert validity at a specific instant (NOT Date.now() — atDate is the TSTInfo
 * genTime so a token stays verifiable forever as of when it was stamped, even
 * if the signer cert eventually expires). Returns null when valid, or a
 * tsaSignatureValidReason when not.
 *
 * Exported for testing the precedence rules in isolation; production callers go
 * through verifyCmsSigned which folds this into the chain walk.
 *
 * @param {pkijs.Certificate} cert
 * @param {Date} atDate
 * @param {"signer"|"issuer"} role  — role determines the reason granularity
 *        (signer uses the more specific "gentime-outside-validity"; issuers
 *        use the generic "cert-expired" / "cert-not-yet-valid").
 * @returns {null|"cert-expired"|"cert-not-yet-valid"|"gentime-outside-validity"}
 */
export function certValidityReason(cert, atDate, role) {
  const nb = cert.notBefore?.value;
  const na = cert.notAfter?.value;
  if (!(nb instanceof Date) || !(na instanceof Date)) return null; // no validity info — don't block, surface only
  if (atDate < nb) return role === "signer" ? "gentime-outside-validity" : "cert-not-yet-valid";
  if (atDate > na) return role === "signer" ? "gentime-outside-validity" : "cert-expired";
  return null;
}

/**
 * Check that the signer cert carries id-kp-timeStamping in its Extended Key Usage
 * extension (RFC 3161 §2.3 — mandatory for TSA responder certs). Returns true if
 * the EKU is missing OR if id-kp-timeStamping is absent from it. Intermediate /
 * root certs do NOT use EKU (they use BasicConstraints + keyUsage) — only the
 * leaf signer is checked.
 *
 * Exported for tests; production callers go through verifyCmsSigned.
 *
 * @returns {boolean} true if the cert lacks the required EKU
 */
export function certMissingTimestampingEku(cert) {
  const ekuExt = (cert.extensions ?? []).find((e) => e.extnID === EXT_KEY_USAGE_OID);
  if (!ekuExt) return true;                // no EKU extension at all
  const purposes = ekuExt.parsedValue?.keyPurposes ?? [];
  return !purposes.includes(ID_KP_TIMESTAMPING_OID);
}

async function verifyCertSignature(child, issuer) {
  const wcAlgo = resolveWebCryptoAlgo(child.signatureAlgorithm.algorithmId);
  if (!wcAlgo) return false;
  const spki = issuer.subjectPublicKeyInfo.toSchema().toBER(false);
  const sig = child.signatureValue.valueBlock.valueHexView;
  const tbs = child.tbsView ?? (child.tbs ? new Uint8Array(child.tbs) : null);
  if (!tbs) return false;
  try {
    const pubKey = await webcrypto.subtle.importKey("spki", spki, wcAlgo, false, ["verify"]);
    return await webcrypto.subtle.verify(
      wcAlgo, pubKey,
      sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength),
      tbs.buffer.slice(tbs.byteOffset, tbs.byteOffset + tbs.byteLength),
    );
  } catch {
    return false;
  }
}

/**
 * Verifica una CMS SignedData (timestamp token) custom: messageDigest match,
 * signature math, cert validity (at TSTInfo genTime) + EKU id-kp-timeStamping
 * on the signer, y chain verify hasta un trust anchor pinned por fingerprint.
 *
 * Precedence of failure reasons (v0.8.0 reviewer F5–F7 hardening):
 *   chain-incomplete (structural) → forged (math/MD mismatch) →
 *   cert-missing-eku (signer EKU) → gentime-outside-validity (signer) /
 *   cert-expired | cert-not-yet-valid (chain issuers) → untrusted-anchor → null.
 *
 * @param {pkijs.SignedData} signed
 * @param {pkijs.Certificate[]} trustedCerts  — pinned anchors
 * @param {Date|null} [genTime]  — TSTInfo.genTime; cert validity is checked AS-OF this
 *        instant (NOT Date.now()), so a token stays verifiable forever as of when it was
 *        stamped. Pass null when called outside the timestamp flow (no validity check).
 * @returns {Promise<{ok:boolean, reason:string|null}>}
 */
async function verifyCmsSigned(signed, trustedCerts, genTime = null) {
  const si = signed.signerInfos?.[0];
  if (!si) return { ok: false, reason: "chain-incomplete" };

  const cmsCerts = signed.certificates ?? [];
  const sidSerialBytes = si.sid?.serialNumber?.valueBlock?.valueHexView;
  if (!sidSerialBytes) return { ok: false, reason: "chain-incomplete" };
  const sidSerial = Buffer.from(sidSerialBytes).toString("hex");
  const signerCert = cmsCerts.find(
    (c) => Buffer.from(c.serialNumber.valueBlock.valueHexView).toString("hex") === sidSerial,
  );
  if (!signerCert) return { ok: false, reason: "chain-incomplete", signerCert: null, issuerCert: null };

  // 1. messageDigest attribute == sha256(eContent VALUE bytes).
  const eContent = signed.encapContentInfo?.eContent;
  if (!eContent) return { ok: false, reason: "forged" };
  const eContentBytes = eContent.getValue ? eContent.getValue() : eContent.valueBlock.valueHexView;
  const eContentBuf = Buffer.from(
    eContentBytes.buffer
      ? eContentBytes.buffer.slice(eContentBytes.byteOffset, eContentBytes.byteOffset + eContentBytes.byteLength)
      : eContentBytes,
  );
  const expectedMd = createHash("sha256").update(eContentBuf).digest();
  const mdAttr = si.signedAttrs?.attributes?.find((a) => a.type === MESSAGE_DIGEST_OID);
  if (!mdAttr) return { ok: false, reason: "forged" };
  const claimedMd = Buffer.from(mdAttr.values[0].valueBlock.valueHexView);
  if (!claimedMd.equals(expectedMd)) return { ok: false, reason: "forged" };

  // 2. Signature math. signedAttrs se firma con la primera byte cambiado de
  //    IMPLICIT [0] (0xA0) a SET (0x31) — RFC 5652 §5.4.
  const wcAlgo = resolveWebCryptoAlgo(
    si.signatureAlgorithm.algorithmId,
    si.digestAlgorithm.algorithmId,
  );
  if (!wcAlgo) return { ok: false, reason: "forged" };
  const saBer = si.signedAttrs.toSchema().toBER(false);
  const saArr = new Uint8Array(saBer);
  saArr[0] = 0x31;
  const spki = signerCert.subjectPublicKeyInfo.toSchema().toBER(false);
  const sig = si.signature.valueBlock.valueHexView;
  try {
    const pubKey = await webcrypto.subtle.importKey("spki", spki, wcAlgo, false, ["verify"]);
    const sigOk = await webcrypto.subtle.verify(
      wcAlgo, pubKey,
      sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength),
      saArr.buffer.slice(saArr.byteOffset, saArr.byteOffset + saArr.byteLength),
    );
    if (!sigOk) return { ok: false, reason: "forged" };
  } catch {
    return { ok: false, reason: "forged" };
  }

  // 3. Signer cert MUST carry id-kp-timeStamping EKU (RFC 3161 §2.3).
  //    Runs after math/MD checks (so forged tokens still get the forged reason),
  //    before validity (so an EKU-less cert is rejected even if temporally OK).
  if (certMissingTimestampingEku(signerCert)) {
    return { ok: false, reason: "cert-missing-eku" };
  }

  // 4. Signer cert validity at genTime (more specific reason for the signer).
  //    Skipped when genTime is null (caller outside the timestamp flow).
  if (genTime instanceof Date) {
    const signerValidity = certValidityReason(signerCert, genTime, "signer");
    if (signerValidity) return { ok: false, reason: signerValidity };
  }

  // 5. Chain: walk signer → issuer (CMS ∪ anchors) hasta llegar a un anchor.
  if (!trustedCerts || trustedCerts.length === 0) {
    return { ok: false, reason: "untrusted-anchor", signerCert, issuerCert: null };
  }
  const anchorFps = new Set(trustedCerts.map(certDerFingerprint));

  let current = signerCert;
  let directIssuer = null; // immediate issuer of the signer (needed for OCSP)
  const seenFps = new Set();
  for (let depth = 0; depth < 10; depth++) {
    const currentFp = certDerFingerprint(current);
    if (anchorFps.has(currentFp)) return { ok: true, reason: null, signerCert, issuerCert: directIssuer };
    if (seenFps.has(currentFp)) return { ok: false, reason: "chain-incomplete", signerCert, issuerCert: directIssuer };
    seenFps.add(currentFp);

    const issuerDer = dnDer(current.issuer);
    const candidates = [...cmsCerts, ...trustedCerts].filter((c) =>
      dnDer(c.subject).equals(issuerDer),
    );
    if (candidates.length === 0) return { ok: false, reason: "untrusted-anchor", signerCert, issuerCert: directIssuer };

    let nextIssuer = null;
    for (const cand of candidates) {
      if (await verifyCertSignature(current, cand)) { nextIssuer = cand; break; }
    }
    if (!nextIssuer) return { ok: false, reason: "chain-incomplete", signerCert, issuerCert: directIssuer };

    // Issuer validity check (after we know it actually signed the child cert
    // we just walked from). genTime-anchored, same rationale as the signer.
    if (genTime instanceof Date) {
      const issuerValidity = certValidityReason(nextIssuer, genTime, "issuer");
      if (issuerValidity) return { ok: false, reason: issuerValidity, signerCert, issuerCert: directIssuer };
    }

    if (depth === 0) directIssuer = nextIssuer; // capture the signer's direct issuer for OCSP
    current = nextIssuer;
  }
  return { ok: false, reason: "chain-incomplete", signerCert, issuerCert: directIssuer };
}

/**
 * Solicita un timestamp RFC 3161 para un hash SHA-256.
 * @param {Uint8Array} hashBytes  32 bytes del SHA-256 del contenido.
 * @returns {Promise<Uint8Array>} TimeStampResp DER crudo (se guarda en el evidence).
 */
export async function requestTimestamp(hashBytes, { tsaUrl = process.env.SYNTHEX_TSA_URL || DEFAULT_TSA_URL, timeoutMs = 10000, retries = 2 } = {}) {
  const messageImprint = new pkijs.MessageImprint({
    hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: SHA256_OID }),
    hashedMessage: new asn1js.OctetString({ valueHex: toArrayBuffer(hashBytes) }),
  });
  const nonce = webcrypto.getRandomValues(new Uint8Array(8));
  const req = new pkijs.TimeStampReq({
    version: 1,
    messageImprint,
    certReq: true,
    nonce: new asn1js.Integer({ valueHex: nonce.buffer }),
  });
  const der = req.toSchema().toBER(false);

  // Retry-with-backoff sobre el fetch. Backoff exponencial bounded: intentos 1..(retries+1),
  // sleep 500ms, 1000ms, ..., 500ms * 2^(i-1). Si todos fallan rethrow el último error →
  // evidence-report.js cae a HMAC-only (fallback honesto preservado vía su try/catch).
  const maxAttempts = Math.max(1, retries + 1);
  let lastErr = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const resp = await fetch(tsaUrl, {
        method: "POST",
        headers: { "Content-Type": "application/timestamp-query" },
        body: Buffer.from(der),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!resp.ok) throw new Error(`TSA HTTP ${resp.status}`);
      return new Uint8Array(await resp.arrayBuffer());
    } catch (err) {
      lastErr = err;
      if (attempt < maxAttempts) {
        const backoffMs = 500 * Math.pow(2, attempt - 1); // 500, 1000, 2000, ...
        if (process.env.SYNTHEX_DEBUG) console.warn(`[tsa] retry ${attempt}/${maxAttempts - 1} after ${backoffMs}ms: ${err.message}`);
        await new Promise((r) => setTimeout(r, backoffMs));
      }
    }
  }
  throw lastErr ?? new Error("TSA request failed after retries");
}

/**
 * Verifica un TimeStampResp DER sella exactamente `hashBytes`.
 * Criterio v0.7.0 (M1): status granted + messageImprint del token == hash + CMS
 * signature verifies against pinned DigiCert anchors (Trusted G4 TimeStamping
 * 2025 CA1 intermediate + Trusted Root G4 cross-cert, ver `tsa-anchors.js`).
 *
 * Async porque la verify CMS usa webcrypto.subtle.
 *
 * @param {Uint8Array} respDer  TimeStampResp DER del token RFC 3161.
 * @param {Uint8Array} hashBytes  hash sellado (SHA-256, 32 bytes).
 * @param {{trustedCerts?: pkijs.Certificate[]}} opts  override de trust anchors (testing).
 *        Default: ANCHORS de `tsa-anchors.js`. Pasar `[]` para forzar untrusted-anchor.
 * @returns {Promise<{
 *   granted:boolean,
 *   match:boolean,
 *   genTime?:string,
 *   serial?:string,
 *   policy?:string,
 *   signatureValid: (boolean|null),
 *   signatureValidReason: (
 *     "forged" | "untrusted-anchor" | "chain-incomplete" |
 *     "cert-missing-eku" | "gentime-outside-validity" |
 *     "cert-expired" | "cert-not-yet-valid" | null
 *   ),
 * }>}
 *   signatureValid: true = CMS verifies against anchors; false = doesn't verify; null = couldn't check.
 *   signatureValidReason (v0.8.0 reviewer F5–F7 hardening — checked at genTime, NOT Date.now()):
 *     "forged" = signer crypto fail o messageDigest mismatch;
 *     "untrusted-anchor" = chain doesn't reach pinned anchors (most common cause:
 *       DigiCert rotated anchors y nuestra pin está stale);
 *     "chain-incomplete" = signer cert no está en CMS o chain malformada;
 *     "cert-missing-eku" = signer cert lacks id-kp-timeStamping (RFC 3161 §2.3);
 *     "gentime-outside-validity" = TSTInfo genTime falls outside signer cert's
 *       notBefore/notAfter window;
 *     "cert-expired" / "cert-not-yet-valid" = an intermediate or root cert in the
 *       chain was expired / not yet valid at the genTime of the token;
 *     null = success o sin chequeo.
 */
export async function verifyTimestamp(respDer, hashBytes, opts = {}) {
  const asn1 = asn1js.fromBER(toArrayBuffer(respDer));
  if (asn1.offset === -1) {
    return { granted: false, match: false, signatureValid: false, signatureValidReason: "chain-incomplete" };
  }
  const tspResp = new pkijs.TimeStampResp({ schema: asn1.result });
  const granted = tspResp.status.status === 0 || tspResp.status.status === 1;
  if (!granted) {
    return { granted: false, match: false, signatureValid: false, signatureValidReason: "chain-incomplete" };
  }

  const signed = new pkijs.SignedData({ schema: tspResp.timeStampToken.content });
  const eContent = signed.encapContentInfo.eContent;
  const tstBytes = eContent.getValue ? eContent.getValue() : eContent.valueBlock.valueHexView;
  const tstAsn1 = asn1js.fromBER(tstBytes.buffer ? tstBytes.buffer : tstBytes);
  const tstInfo = new pkijs.TSTInfo({ schema: tstAsn1.result });

  const tokenHash = new Uint8Array(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView);
  const h = hashBytes instanceof Uint8Array ? hashBytes : new Uint8Array(hashBytes);
  const match = tokenHash.length === h.length && tokenHash.every((b, i) => b === h[i]);

  // CMS signature verify against pinned trust anchors (custom path).
  // Pass genTime so cert validity / EKU checks are anchored to when the token
  // was stamped (NOT Date.now()) — tokens stay verifiable after cert expiry.
  const trustedCerts = opts.trustedCerts ?? loadAnchors();
  const { ok, reason, signerCert, issuerCert } = await verifyCmsSigned(
    signed, trustedCerts, tstInfo.genTime?.value ?? null,
  );

  // OCSP opt-in (v0.8 §1.5) — only attempted when CMS verifies AND we have the
  // signer + direct issuer. Surfacing-only: revoked NOT auto-flip signatureValid.
  let revocationChecked = false;
  let revocationStatus = null;
  let revocationReason = null;
  if (opts.checkRevocation && ok && signerCert && issuerCert) {
    revocationChecked = true;
    const r = await checkRevocation(signerCert, issuerCert, {
      timeoutMs: opts.ocspTimeoutMs ?? 5000,
      fetchImpl: opts.ocspFetchImpl,
    });
    revocationStatus = r.status;
    revocationReason = r.reason ?? null;
  }

  return {
    granted: true,
    match,
    genTime: tstInfo.genTime?.toISOString?.() ?? null,
    serial: Buffer.from(tstInfo.serialNumber.valueBlock.valueHexView).toString("hex"),
    policy: String(tstInfo.policy ?? ""),
    signatureValid: ok,
    signatureValidReason: reason,
    revocationChecked,
    revocationStatus,
    revocationReason,
  };
}
