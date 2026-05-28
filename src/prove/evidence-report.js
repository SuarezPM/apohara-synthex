// PROVE — Evidence Report sellado. Sello base HMAC-SHA256 (siempre);
// capa opcional RFC 3161 TSA (DigiCert) si hay red. Fallback honesto a HMAC-only.
//
// Schema versions:
//   v1 (legacy, Synthex ≤v3) — `JSON.stringify(payload)` para HMAC. Insertion-order-dependent.
//   v2 (Synthex v4+)         — `canonicalize(payload)` para HMAC. Order-independent (JCS-like).
//
// El verifier auto-detecta `payload.schema_version` y aplica el path correcto (N3) — un
// verificador v4 sigue verificando Evidence Reports v1 ya publicados.
// El sealer emite v2 por default; flag `EVIDENCE_SCHEMA_V2=0` fuerza v1 legacy (rollback demo).
import { sha256, hmacSign, hmacVerify } from "./hmac.js";
import { requestTimestamp, verifyTimestamp } from "./tsa.js";
import { canonicalize } from "./canonicalize.js";

// HMAC_EXCLUDED_KEYS (T1.6 del PRD v0.6.0) — claves que SON metadata de "qué pasó al
// emitir/sellar" pero NO parte del contenido sellado. Excluirlas garantiza determinism
// cross-run: dos lecturas del MISMO URL con distinto kg_status (run A: Cognee ok, run B:
// Cognee timeout) producen el MISMO contentHash, evitando "cambios fantasma" en la cadena
// delta_chain. Sealer y verifier usan el mismo path → back-compat 100% con reports v0.5
// (no tenían estas keys; strip recursivo es no-op sobre ellos).
export const HMAC_EXCLUDED_KEYS = Object.freeze([
  "kg_status",
  "kg_latency_ms",
  "surface_status",
  // v0.7.0 T4/M3 — emit-metadata del classifier sobre la truncation del INPUT LLM (no de la
  // raw text). Excluidas del HMAC pre-image para que el contentHash no dependa de si el
  // classifier vio el doc entero o lo truncó. La raw text en el payload sigue intacta.
  "truncated",
  "charsSeen",
  // v0.7.0 T11/AI-3 — flag visible "low confidence" para tier free; emit-metadata UI/PDF.
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
  // T1.6: strip HMAC_EXCLUDED_KEYS ANTES de detectar schema_version y canonicalizar.
  // Sin mutar el payload original (deep-copy via _stripExcludedKeys).
  const filtered = _stripExcludedKeys(payload);
  // Auto-detect: v>=2 → canonicalize; v=1/ausente → JSON.stringify legacy.
  const v = filtered && typeof filtered === "object" ? filtered.schema_version : undefined;
  return (v !== undefined && v >= 2) ? canonicalize(filtered) : JSON.stringify(filtered);
}

/**
 * Construye un Evidence Report a partir de un payload serializable.
 * @param {object} payload  contenido de la evidencia (lo clasificado, fuentes, etc.).
 * @param {{hmacKey?:string, requestTsa?:boolean}} opts
 */
export async function buildEvidence(payload, { hmacKey, requestTsa = true } = {}) {
  const canonical = _serializeForHmac(payload);
  const hash = sha256(canonical); // Buffer 32B
  const hmac = hmacKey ? hmacSign(canonical, hmacKey) : null;

  let tsa = null; // null => HMAC-only (declarado, no fabricado)
  if (requestTsa) {
    try {
      const token = await requestTimestamp(new Uint8Array(hash));
      const v = await verifyTimestamp(token, new Uint8Array(hash));
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
 * Async (M1, v0.7.0) porque verifyTimestamp usa webcrypto.subtle para CMS verify.
 *
 * `signatureValid` + `signatureValidReason` solo se setean cuando hay TSA token;
 * en HMAC-only (rfc3161Tsa=null) ambos quedan en null (no se ejecutó .verify()).
 *
 * @returns {Promise<{
 *   hashOk:boolean,
 *   hmacOk:(boolean|null),
 *   tsaOk:(boolean|null),
 *   signatureValid:(boolean|null),
 *   signatureValidReason:("forged"|"untrusted-anchor"|"chain-incomplete"|null),
 * }>}
 */
export async function verifyEvidence(evidence, { hmacKey, trustedCerts } = {}) {
  // T7/M8 — shape guard contra input malformado. Sin esto, evidence.payload undefined
  // o evidence.contentHash no-string puede crashear _serializeForHmac. Defensa cheap.
  if (!evidence || typeof evidence !== "object" || !evidence.payload || typeof evidence.contentHash !== "string") {
    return { hashOk: false, hmacOk: null, tsaOk: null, signatureValid: null, signatureValidReason: null, error: "malformed evidence" };
  }
  // N3: el verifier auto-detecta schema_version del payload — back-compat v1 siempre.
  // El flag EVIDENCE_SCHEMA_V2 (env) sólo controla el sealer (qué emitir), nunca al verifier.
  const canonical = _serializeForHmac(evidence.payload);
  const hash = sha256(canonical);
  const hashOk = hash.toString("hex") === evidence.contentHash;

  const hmacSig = evidence.seal?.hmacSha256;
  const hmacOk = hmacSig && hmacKey ? hmacVerify(canonical, hmacKey, hmacSig) : null;

  let tsaOk = null;
  let signatureValid = null;
  let signatureValidReason = null;
  const token = evidence.seal?.rfc3161Tsa?.token;
  if (token) {
    const der = new Uint8Array(Buffer.from(token, "base64"));
    const opts = trustedCerts !== undefined ? { trustedCerts } : {};
    const v = await verifyTimestamp(der, new Uint8Array(hash), opts);
    tsaOk = v.granted && v.match;
    signatureValid = v.signatureValid;
    signatureValidReason = v.signatureValidReason;
  }

  return { hashOk, hmacOk, tsaOk, signatureValid, signatureValidReason };
}
