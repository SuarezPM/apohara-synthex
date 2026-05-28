// MODEL TIERS — tres niveles cost/quality que el playground y los stress tests pueden
// invocar explícitamente. AI/ML API expone los tres modelos en /chat/completions con
// la misma forma OpenAI-compatible, así que aiml-client.js solo necesita resolverlos.
//
// - free: FREE tier en AI/ML API. Sub-3B param, calidad calibrada en T0.6.
// - oss:  default user-facing v0.5+ (DeepSeek non-thinking, open weights).
// - paid: DeepSeek v3.2 thinking, mayor calidad para reportes finales.
export const MODEL_TIERS = Object.freeze({
  free: "nvidia/nemotron-3-nano-omni",
  oss: "deepseek/deepseek-non-thinking-v3.2-exp",
  paid: "deepseek/deepseek-v3.2-exp",
});

export const DEFAULT_TIER = "oss";

/**
 * Resuelve el model id a usar dado un opts {tier, model}. Reglas:
 *  - opts.model explícito gana siempre (back-compat con callers existentes).
 *  - opts.tier en MODEL_TIERS retorna el id mapeado.
 *  - Sin nada → tier por defecto (DEFAULT_TIER → MODEL_TIERS[oss]).
 * Tier desconocido lanza para no fallar silente a un tier diferente al esperado.
 */
export function pickModel(opts = {}) {
  if (typeof opts.model === "string" && opts.model.length > 0) return opts.model;
  const tier = opts.tier ?? DEFAULT_TIER;
  if (!(tier in MODEL_TIERS)) {
    throw new Error(`Unknown model tier "${tier}". Valid tiers: ${Object.keys(MODEL_TIERS).join(", ")}`);
  }
  return MODEL_TIERS[tier];
}
