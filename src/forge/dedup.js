// FORGE/dedup — deduplicación por fingerprint SHA-256 del contenido COMPLETO.
// Nota de diseño: el sampling prefix+middle+suffix de context_cache.js (PR #140) ahorra
// CPU en payloads enormes pero deja huecos no muestreados → colisiona si dos cuerpos
// difieren justo en un hueco (verificado con un test adversarial). Para datos web (KB por
// página) el SHA-256 completo es microsegundos y es correcto: cero colisiones, sin falsos
// positivos. Solo deduplicamos coincidencias EXACTAS, que es lo que el pipeline necesita.
import { createHash } from "node:crypto";

export function fingerprint(content) {
  const s = typeof content === "string" ? content : JSON.stringify(content);
  return createHash("sha256").update(s).digest("hex");
}

export class ContextCache {
  constructor() { this.seen = new Map(); }
  check(content, url) {
    const contentHash = fingerprint(content);
    if (this.seen.has(contentHash)) {
      return { isDuplicate: true, contentHash, duplicateOf: this.seen.get(contentHash) };
    }
    this.seen.set(contentHash, url ?? contentHash);
    return { isDuplicate: false, contentHash };
  }
  clear() { this.seen.clear(); }
}

/**
 * Deduplica un array de {url, content}. Devuelve {unique, duplicates, stats}.
 * @param {Array<{url?:string, content:any}>} items
 * @param {{mode?:"exact"|"semantic"}} opts  "exact" (default) = SHA-256 lossless, SÍNCRONO,
 *   byte-idéntico de siempre. "semantic" no se hace aquí (requiere modelo + async): la vía
 *   es `dedupeSemantic()` de dedup-semantic.js (opt-in, CLI-only, jamás serverless).
 */
export function dedupe(items, { mode = "exact" } = {}) {
  if (mode !== "exact") {
    throw new Error(
      `dedupe(): mode "${mode}" no se soporta en la vía síncrona/lossless. ` +
        "El dedup semántico (lossy, opt-in) es async → importá dedupeSemantic() de ./dedup-semantic.js.",
    );
  }
  const cache = new ContextCache();
  const unique = [];
  const duplicates = [];
  let bytesSaved = 0;
  for (const item of items) {
    const r = cache.check(item.content, item.url);
    const len = (typeof item.content === "string" ? item.content : JSON.stringify(item.content)).length;
    if (r.isDuplicate) {
      duplicates.push({ ...item, contentHash: r.contentHash, duplicateOf: r.duplicateOf });
      bytesSaved += len;
    } else {
      unique.push({ ...item, contentHash: r.contentHash });
    }
  }
  const total = items.length;
  return {
    unique,
    duplicates,
    stats: {
      uniqueBlocks: unique.length,
      duplicateBlocks: duplicates.length,
      bytesSaved,
      dedupRatio: total > 0 ? duplicates.length / total : 0,
    },
  };
}
