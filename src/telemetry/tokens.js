// TELEMETRY/tokens — estimación honesta de tokens ahorrados pre-LLM.
//
// Sirve para reportar al usuario cuántos tokens (estimados) NO se gastaron en el LLM
// gracias a las 3 capas pre-LLM de Synthex:
//   1. dedupe (SHA-256 exact, lossless) → docs duplicados eliminados
//   2. DJL (78 reglas prompt-level)     → docs blocked, no llegan al LLM
//   3. prefilter (28 reglas web)         → idem para web-injection
//
// HONESTIDAD: "tokens" es una aproximación. Los tokenizers reales varían:
//   * GPT-4 (cl100k_base):  ~4.2 chars/token sobre texto en inglés
//   * Claude (cl-tokenizer): ~3.8 chars/token
//   * Texto multilingüe:    suele ser peor (~2-3 chars/token con CJK)
// Usamos 4 chars/token como aproximación conservadora documentada en cada payload.

export const CHARS_PER_TOKEN_ESTIMATE = 4;

export function bytesOf(content) {
  if (content == null) return 0;
  // Buffer.byteLength sería más preciso para UTF-8, pero String#length es lo que cobra
  // un tokenizer (que opera sobre chars, no bytes). Mantenemos la métrica char-based.
  return typeof content === "string" ? content.length : String(content).length;
}

export function estimateTokens(bytes) {
  return Math.round(bytes / CHARS_PER_TOKEN_ESTIMATE);
}

/**
 * Calcula tokens_saved a partir de los buckets del pipeline FORGE.
 * @param {object} args
 * @param {Array<{content:string}>} args.original  docs pre-dedup (entrada FETCH)
 * @param {Array<{content:string}>} args.unique    docs post-dedup
 * @param {Array<{content:string}>} args.blocked   docs bloqueados (DJL ∪ prefilter)
 * @returns {{dedup_bytes:number, blocked_bytes:number, total_bytes:number,
 *           estimated_tokens:number, chars_per_token:number, note:string}}
 */
export function computeTokensSaved({ original, unique, blocked }) {
  const originalBytes = original.reduce((s, d) => s + bytesOf(d.content), 0);
  const uniqueBytes = unique.reduce((s, d) => s + bytesOf(d.content), 0);
  const blockedBytes = blocked.reduce((s, d) => s + bytesOf(d.content), 0);
  const dedupBytes = Math.max(0, originalBytes - uniqueBytes);
  const totalBytes = dedupBytes + blockedBytes;
  return {
    dedup_bytes: dedupBytes,
    blocked_bytes: blockedBytes,
    total_bytes: totalBytes,
    estimated_tokens: estimateTokens(totalBytes),
    chars_per_token: CHARS_PER_TOKEN_ESTIMATE,
    note: "Estimated assuming 4 chars/token; actual depends on tokenizer (GPT-4 cl100k ~4.2, Claude ~3.8)",
  };
}
