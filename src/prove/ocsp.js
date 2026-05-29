// OCSP — opt-in revocation surface for the TSA signer cert (RFC 6960). Hand-rolled
// on the existing `pkijs` dep — zero new dependencies.
//
// **Contract (HONESTY §1.5 is binding):**
//   - Default OFF: verifyTimestamp / verifyEvidence behave identically to v0.7
//     when no `checkRevocation` flag is passed. No network I/O.
//   - Fail-open to 'unknown': any failure (no AIA, network down, non-200, parse
//     error, non-success responseStatus, etc.) returns `{status:'unknown', reason}`.
//     Never throws — the verifier MUST stay usable offline.
//   - Surfacing-only in v0.8: a 'revoked' verdict is REPORTED but does NOT auto-
//     flip `tsaSignatureValid:false`. The operator decides what to do with the
//     signal. Strict revoked=hard-fail is a follow-up.
//   - SHA-1 CertID per RFC 6960 §4.1.1 (modern responders accept it; SHA-256 is
//     supported via opts.hashAlgorithm but not the default — interop > strength
//     for this use-case).
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

const AIA_OID = "1.3.6.1.5.5.7.1.1";
const ID_AD_OCSP_OID = "1.3.6.1.5.5.7.48.1";
const SHA1_OID = "1.3.14.3.2.26";

/**
 * Extract the OCSP responder URL from a cert's AIA extension. Returns null when
 * the AIA extension is missing or contains no id-ad-ocsp accessMethod.
 */
export function extractOcspUrl(cert) {
  const aia = (cert?.extensions ?? []).find((e) => e.extnID === AIA_OID);
  if (!aia) return null;
  const descriptions = aia.parsedValue?.accessDescriptions ?? [];
  for (const ad of descriptions) {
    if (ad.accessMethod === ID_AD_OCSP_OID) {
      const loc = ad.accessLocation?.value;
      if (typeof loc === "string") return loc;
    }
  }
  return null;
}

/**
 * Build an OCSPRequest DER for (signerCert, issuerCert) using SHA-1 CertID.
 * Throws on cert shape issues — caller must wrap in try/catch (checkRevocation does).
 */
function buildOcspRequestDer(signerCert, issuerCert) {
  // Issuer Distinguished Name DER (the TBS form, no SEQUENCE wrapper) → SHA-1.
  const issuerNameDer = new Uint8Array(issuerCert.subject.toSchema().toBER(false));
  const issuerNameHash = createHash("sha1").update(Buffer.from(issuerNameDer)).digest();

  // Issuer public key BIT STRING value (raw key bytes, no SPKI wrapper) → SHA-1.
  const keyBytes = issuerCert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView;
  const issuerKeyHash = createHash("sha1").update(Buffer.from(keyBytes)).digest();

  const certID = new pkijs.CertID({
    hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: SHA1_OID }),
    issuerNameHash: new asn1js.OctetString({
      valueHex: issuerNameHash.buffer.slice(issuerNameHash.byteOffset, issuerNameHash.byteOffset + issuerNameHash.byteLength),
    }),
    issuerKeyHash: new asn1js.OctetString({
      valueHex: issuerKeyHash.buffer.slice(issuerKeyHash.byteOffset, issuerKeyHash.byteOffset + issuerKeyHash.byteLength),
    }),
    serialNumber: signerCert.serialNumber,
  });

  const request = new pkijs.Request({ reqCert: certID });
  const tbsRequest = new pkijs.TBSRequest({ version: 0, requestList: [request] });
  const ocspReq = new pkijs.OCSPRequest({ tbsRequest });
  return new Uint8Array(ocspReq.toSchema(true).toBER(false));
}

/**
 * Decode a CertStatus CHOICE into our string enum. CHOICE values use IMPLICIT
 * context-specific tags: [0] good, [1] revoked, [2] unknown.
 */
function decodeCertStatus(certStatus) {
  const tag = certStatus?.idBlock?.tagNumber;
  const isContext = certStatus?.idBlock?.tagClass === 3;
  if (!isContext) return "unknown";
  if (tag === 0) return "good";
  if (tag === 1) return "revoked";
  return "unknown";
}

/**
 * Query the OCSP responder for the (signerCert, issuerCert) pair and return
 * the revocation status. NEVER throws.
 *
 * @param {pkijs.Certificate} signerCert
 * @param {pkijs.Certificate} issuerCert
 * @param {{ timeoutMs?: number, fetchImpl?: typeof fetch }} [opts]
 * @returns {Promise<{
 *   status: "good"|"revoked"|"unknown",
 *   reason?: string,         // why we couldn't decide (only for "unknown")
 *   responder?: string,      // OCSP URL queried
 *   producedAt?: string,     // ISO timestamp from the response
 * }>}
 */
export async function checkRevocation(signerCert, issuerCert, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 5000;
  const fetchImpl = opts.fetchImpl ?? fetch;

  const url = extractOcspUrl(signerCert);
  if (!url) return { status: "unknown", reason: "no-aia-ocsp" };

  let reqDer;
  try {
    reqDer = buildOcspRequestDer(signerCert, issuerCert);
  } catch {
    return { status: "unknown", reason: "build-request-error", responder: url };
  }

  let respDer;
  try {
    const res = await fetchImpl(url, {
      method: "POST",
      headers: { "Content-Type": "application/ocsp-request" },
      body: Buffer.from(reqDer),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return { status: "unknown", reason: `http-${res.status}`, responder: url };
    respDer = new Uint8Array(await res.arrayBuffer());
  } catch {
    return { status: "unknown", reason: "network-error", responder: url };
  }

  try {
    const buf = respDer.buffer.slice(respDer.byteOffset, respDer.byteOffset + respDer.byteLength);
    const asn1 = asn1js.fromBER(buf);
    if (asn1.offset === -1) return { status: "unknown", reason: "parse-error", responder: url };

    const ocspResp = new pkijs.OCSPResponse({ schema: asn1.result });
    const respStatus = ocspResp.responseStatus?.valueBlock?.valueDec;
    if (respStatus !== 0) {
      return { status: "unknown", reason: `responseStatus-${respStatus}`, responder: url };
    }

    if (!ocspResp.responseBytes) return { status: "unknown", reason: "no-responseBytes", responder: url };
    const basicBytes = ocspResp.responseBytes.response.valueBlock.valueHexView;
    const basicAsn1 = asn1js.fromBER(
      basicBytes.buffer.slice(basicBytes.byteOffset, basicBytes.byteOffset + basicBytes.byteLength),
    );
    if (basicAsn1.offset === -1) return { status: "unknown", reason: "basic-parse-error", responder: url };

    const basicResp = new pkijs.BasicOCSPResponse({ schema: basicAsn1.result });
    const responses = basicResp.tbsResponseData?.responses;
    if (!responses || responses.length === 0) {
      return { status: "unknown", reason: "no-singleResponse", responder: url };
    }

    const status = decodeCertStatus(responses[0].certStatus);
    const producedAt = basicResp.tbsResponseData.producedAt?.toISOString?.() ?? null;
    return { status, responder: url, producedAt };
  } catch {
    return { status: "unknown", reason: "decode-error", responder: url };
  }
}
