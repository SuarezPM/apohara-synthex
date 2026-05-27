// PROVE — Evidence Report sellado. Sello base HMAC-SHA256 (siempre);
// capa opcional RFC 3161 TSA (DigiCert) si hay red. Fallback honesto a HMAC-only.
import { sha256, hmacSign, hmacVerify } from "./hmac.js";
import { requestTimestamp, verifyTimestamp } from "./tsa.js";

/**
 * Construye un Evidence Report a partir de un payload serializable.
 * @param {object} payload  contenido de la evidencia (lo clasificado, fuentes, etc.).
 * @param {{hmacKey?:string, requestTsa?:boolean}} opts
 */
export async function buildEvidence(payload, { hmacKey, requestTsa = true } = {}) {
  const canonical = JSON.stringify(payload);
  const hash = sha256(canonical); // Buffer 32B
  const hmac = hmacKey ? hmacSign(canonical, hmacKey) : null;

  let tsa = null; // null => HMAC-only (declarado, no fabricado)
  if (requestTsa) {
    try {
      const token = await requestTimestamp(new Uint8Array(hash));
      const v = verifyTimestamp(token, new Uint8Array(hash));
      if (v.granted && v.match) {
        tsa = {
          standard: "RFC 3161",
          authority: "digicert",
          token: Buffer.from(token).toString("base64"),
          genTime: v.genTime,
          serial: v.serial,
        };
      }
    } catch {
      tsa = null; // sin red / TSA caída → seguimos con HMAC
    }
  }

  return {
    payload,
    contentHash: hash.toString("hex"),
    seal: {
      hmacSha256: hmac,                 // sello base verificable offline
      rfc3161Tsa: tsa,                  // capa de tercero (DigiCert) o null
      method: tsa ? "HMAC-SHA256 + RFC 3161 TSA" : "HMAC-SHA256",
    },
    sealedAt: new Date().toISOString(),
  };
}

/**
 * Verifica un Evidence Report. Devuelve qué pasó (no afirma lo que no comprobó).
 * @returns {{hashOk:boolean, hmacOk:(boolean|null), tsaOk:(boolean|null)}}
 */
export function verifyEvidence(evidence, { hmacKey } = {}) {
  const canonical = JSON.stringify(evidence.payload);
  const hash = sha256(canonical);
  const hashOk = hash.toString("hex") === evidence.contentHash;

  const hmacSig = evidence.seal?.hmacSha256;
  const hmacOk = hmacSig && hmacKey ? hmacVerify(canonical, hmacKey, hmacSig) : null;

  let tsaOk = null;
  const token = evidence.seal?.rfc3161Tsa?.token;
  if (token) {
    const der = new Uint8Array(Buffer.from(token, "base64"));
    const v = verifyTimestamp(der, new Uint8Array(hash));
    tsaOk = v.granted && v.match;
  }

  return { hashOk, hmacOk, tsaOk };
}
