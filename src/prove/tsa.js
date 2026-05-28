// RFC 3161 Trusted Timestamp (DigiCert) — JS puro, validado en el spike de de-risk.
// Lib: PKI.js (maneja TimeStampReq/Resp + SignedData/TSTInfo). TSA: DigiCert (CA pública).
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { webcrypto } from "node:crypto";
import { loadAnchors } from "./tsa-anchors.js";

const DEFAULT_TSA_URL = "http://timestamp.digicert.com";
const SHA256_OID = "2.16.840.1.101.3.4.2.1";

pkijs.setEngine("synthex", new pkijs.CryptoEngine({ name: "synthex", crypto: webcrypto }));

function toArrayBuffer(bytes) {
  if (bytes instanceof ArrayBuffer) return bytes;
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

/**
 * Solicita un timestamp RFC 3161 para un hash SHA-256.
 * @param {Uint8Array} hashBytes  32 bytes del SHA-256 del contenido.
 * @returns {Promise<Uint8Array>} TimeStampResp DER crudo (se guarda en el evidence).
 */
export async function requestTimestamp(hashBytes, { tsaUrl = DEFAULT_TSA_URL, timeoutMs = 10000 } = {}) {
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
  const resp = await fetch(tsaUrl, {
    method: "POST",
    headers: { "Content-Type": "application/timestamp-query" },
    body: Buffer.from(der),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!resp.ok) throw new Error(`TSA HTTP ${resp.status}`);
  return new Uint8Array(await resp.arrayBuffer());
}

/**
 * Verifica que un TimeStampResp DER sella exactamente `hashBytes`.
 * Criterio v0.7.0 (M1): status granted + messageImprint del token == hash + CMS
 * signature verifies against pinned DigiCert anchors (Trusted G4 TimeStamping
 * 2025 CA1 intermediate + Trusted Root G4 cross-cert, ver `tsa-anchors.js`).
 *
 * Async because `signed.verify()` returns a Promise (pkijs uses webcrypto).
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
 *   signatureValidReason: ("forged"|"untrusted-anchor"|"chain-incomplete"|null),
 * }>}
 *   signatureValid: true = CMS verifies against anchors; false = doesn't verify; null = couldn't check.
 *   signatureValidReason: "forged" = signer crypto fail; "untrusted-anchor" = chain doesn't
 *   reach pinned anchors (most common cause: DigiCert rotated anchors and our pin is stale);
 *   "chain-incomplete" = signer cert not in CMS or chain malformed; null = success or sin chequeo.
 */
export async function verifyTimestamp(respDer, hashBytes, opts = {}) {
  const asn1 = asn1js.fromBER(toArrayBuffer(respDer));
  if (asn1.offset === -1) return { granted: false, match: false, signatureValid: false, signatureValidReason: "chain-incomplete" };
  const tspResp = new pkijs.TimeStampResp({ schema: asn1.result });
  const granted = tspResp.status.status === 0 || tspResp.status.status === 1;
  if (!granted) return { granted: false, match: false, signatureValid: false, signatureValidReason: "chain-incomplete" };

  const signed = new pkijs.SignedData({ schema: tspResp.timeStampToken.content });
  const eContent = signed.encapContentInfo.eContent;
  const tstBytes = eContent.getValue ? eContent.getValue() : eContent.valueBlock.valueHexView;
  const tstAsn1 = asn1js.fromBER(tstBytes.buffer ? tstBytes.buffer : tstBytes);
  const tstInfo = new pkijs.TSTInfo({ schema: tstAsn1.result });

  const tokenHash = new Uint8Array(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView);
  const h = hashBytes instanceof Uint8Array ? hashBytes : new Uint8Array(hashBytes);
  const match = tokenHash.length === h.length && tokenHash.every((b, i) => b === h[i]);

  // M1 — CMS signature verify against pinned trust anchors.
  const trustedCerts = opts.trustedCerts ?? loadAnchors();
  let signatureValid = null;
  let signatureValidReason = null;
  try {
    const result = await signed.verify({ signer: 0, trustedCerts, checkChain: true, extendedMode: true });
    // extendedMode returns { signatureVerified, signerCertificate, signerCertificateVerified, ... }
    if (result && typeof result === "object") {
      if (result.signatureVerified === false) {
        signatureValid = false;
        signatureValidReason = "forged";
      } else if (result.signerCertificateVerified === false) {
        signatureValid = false;
        signatureValidReason = "untrusted-anchor";
      } else if (result.signatureVerified === true && result.signerCertificateVerified === true) {
        signatureValid = true;
      } else {
        signatureValid = false;
        signatureValidReason = "chain-incomplete";
      }
    } else if (result === true) {
      // legacy boolean shape
      signatureValid = true;
    } else if (result === false) {
      signatureValid = false;
      signatureValidReason = "forged";
    }
  } catch (err) {
    // pkijs.verify can throw on chain issues, missing signer cert, etc.
    signatureValid = false;
    const msg = String(err?.message ?? err);
    if (/signer certificate|signature value/i.test(msg)) {
      signatureValidReason = "forged";
    } else if (/trust|chain|issuer/i.test(msg)) {
      signatureValidReason = "untrusted-anchor";
    } else {
      signatureValidReason = "chain-incomplete";
    }
  }

  return {
    granted: true,
    match,
    genTime: tstInfo.genTime?.toISOString?.() ?? null,
    serial: Buffer.from(tstInfo.serialNumber.valueBlock.valueHexView).toString("hex"),
    policy: String(tstInfo.policy ?? ""),
    signatureValid,
    signatureValidReason,
  };
}
