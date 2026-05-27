// Sello base de evidencia: SHA-256 + HMAC-SHA256 (siempre disponible, sin red).
import { createHmac, createHash, timingSafeEqual } from "node:crypto";

/** SHA-256 de un string/Buffer → Buffer (32 bytes). */
export function sha256(data) {
  return createHash("sha256").update(data).digest();
}

/** HMAC-SHA256 → hex. */
export function hmacSign(data, key) {
  return createHmac("sha256", key).update(data).digest("hex");
}

/** Verificación HMAC en tiempo constante. */
export function hmacVerify(data, key, sigHex) {
  const expected = Buffer.from(hmacSign(data, key), "hex");
  const got = Buffer.from(String(sigHex), "hex");
  return expected.length === got.length && timingSafeEqual(expected, got);
}
