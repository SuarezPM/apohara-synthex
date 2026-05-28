// DELTA/normalize — quita ruido volátil del HTML para que dos scrapes del MISMO
// contenido produzcan el mismo hash. Sin esto, csrf tokens, timestamps inline,
// view-counters, etc. romperían la cadena delta_chain por reportar "cambio"
// donde no lo hay.
//
// Decisiones de diseño:
//   - Determinista: dado un input, siempre devuelve el mismo output.
//   - Pure: cero side effects, no toca process.env ni filesystem.
//   - Granularidad de strip: <script>, <style>, comentarios HTML, atributos
//     volátiles (csrf, nonce, data-timestamp*), timestamps ISO 8601 inline,
//     contadores de "X views", IDs auto-generados estilo `ember1234`/`ng-c123`.
//   - NO strip: estructura semántica (h1..h6, p, li, table) ni atributos no
//     volátiles (href, src, class, id estables).
//
// Coverage real: ~10 fixtures sintéticos en test/delta/normalize.test.js (T1.2).
// NO promete cubrir todos los CMS del mundo — promete idempotencia para los
// patrones que enumera abajo. Lista debe crecer con findings reales del stress.

const NOISE_PATTERNS = [
  // Bloques completos.
  /<script\b[^>]*>[\s\S]*?<\/script>/gi,
  /<style\b[^>]*>[\s\S]*?<\/style>/gi,
  /<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi,
  /<!--[\s\S]*?-->/g,
  // Atributos volátiles (csrf, nonces, framework-generated IDs).
  /\s+(data-csrf|csrf-token|data-nonce|nonce|data-timestamp[a-z-]*|data-render-id)=["'][^"']*["']/gi,
  /\s+id=["'](?:ember\d+|ng-c\d+|react-\d+|aria-radix-\d+)["']/gi,
  // Timestamps ISO 8601 inline (texto dentro de tags).
  /\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b/g,
  // View counters / live counters: "1,234 views", "Updated 5 minutes ago".
  /\b\d{1,3}(?:,\d{3})+\s*(?:views?|reads?|shares?|likes?)\b/gi,
  /\bUpdated\s+\d+\s+(?:second|minute|hour|day)s?\s+ago\b/gi,
];

const WHITESPACE_RUN = /[ \t\f\v]+/g;
const NEWLINE_RUN = /\n{3,}/g;

/**
 * Normaliza HTML/text para que el hash sea estable a través de scrapes
 * repetidos del mismo contenido lógico.
 * @param {string} input  HTML o texto crudo.
 * @returns {string}  texto normalizado (no es HTML válido garantizado).
 */
export function normalizeContent(input) {
  if (typeof input !== "string") {
    throw new TypeError(`normalizeContent expects string, got ${typeof input}`);
  }
  let s = input;
  for (const re of NOISE_PATTERNS) s = s.replace(re, "");
  // Colapsa whitespace para que reformatos de minificación no cambien el hash.
  s = s.replace(WHITESPACE_RUN, " ");
  s = s.replace(NEWLINE_RUN, "\n\n");
  return s.trim();
}
