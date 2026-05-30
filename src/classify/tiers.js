// MODEL TIERS — cost/quality levels the playground and stress tests can invoke explicitly.
// NIVELES cost/quality que el playground y los stress tests pueden invocar explícitamente.
//
// AI/ML API exposes these models at /chat/completions in the same OpenAI-compatible shape,
// so aiml-client.js only needs to resolve the id. AI/ML API expone estos modelos en
// /chat/completions con la misma forma OpenAI-compatible; aiml-client.js solo resuelve el id.
//
// Migrated v1.0.0 (item 1.4 / decisión §1.5): DeepSeek V4 family. The prior NVIDIA free
// tier was removed (it 404s on the current API). El free tier NVIDIA previo se eliminó.
// Smoke-tested live via scripts/probe-aiml-models.mjs (gate-before-trust):
//   OK deepseek/deepseek-v4-flash · OK deepseek/deepseek-v4-pro (2026-05-29).
//
// - flash: default/bulk — fast, cheap reasoner for the always-on 4-lens classify.
//          default/bulk — razonador rápido y barato para el classify de 4 lentes always-on.
// - pro:   spot-quality + council/L3 high-stakes only, NEVER bulk.
//          spot-quality + council/L3 high-stakes únicamente, NUNCA bulk.
export const MODEL_TIERS = Object.freeze({
  flash: "deepseek/deepseek-v4-flash",
  pro: "deepseek/deepseek-v4-pro",
});

// Default tier = flash (maps to deepseek/deepseek-v4-flash). Tier por defecto = flash.
export const DEFAULT_TIER = "flash";

/**
 * Resolve the model id to use given opts {tier, model}. Rules:
 * Resuelve el model id a usar dado un opts {tier, model}. Reglas:
 *  - opts.model explícito gana siempre (back-compat con callers existentes).
 *  - opts.tier en MODEL_TIERS retorna el id mapeado.
 *  - Sin nada → tier por defecto (DEFAULT_TIER → MODEL_TIERS.flash).
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
