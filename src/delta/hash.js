// DELTA/hash — sha256 hex de contenido normalizado.
// 64 hex chars, lowercase, sin separadores. Idempotente.
import { createHash } from "node:crypto";

/** sha256(content) → 64-char lowercase hex. */
export function hashSnapshot(content) {
  if (typeof content !== "string") {
    throw new TypeError(`hashSnapshot expects string, got ${typeof content}`);
  }
  return createHash("sha256").update(content, "utf8").digest("hex");
}
