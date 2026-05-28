// CLASSIFY — clasificación tri-lente (GTM / Finance / Security) vía AI/ML API.
// AI/ML API es OpenAI-compatible (/chat/completions). Key: process.env.AIML_API_KEY.
// El parseo está separado de la llamada de red para poder testear la lógica sin gastar API.
import { pickModel, MODEL_TIERS, DEFAULT_TIER } from "./tiers.js";

const DEFAULT_BASE = process.env.AIML_BASE_URL || "https://api.aimlapi.com/v1";
// AIML_MODEL env conserva back-compat: si está set, gana sobre tier.
// Si no, se resuelve por tier (DEFAULT_TIER=oss → MODEL_TIERS.oss).
const DEFAULT_MODEL = process.env.AIML_MODEL || MODEL_TIERS[DEFAULT_TIER];

export const LENSES = {
  gtm: "GTM/competitive intelligence: pricing, hiring, product launches, market moves, competitor signals",
  finance: "Finance/market intelligence: vendor & supplier risk, regulatory exposure, earnings/pre-earnings signals",
  security: "Security & compliance: threats, CVEs, leaked credentials, brand/data exposure, regulatory changes",
  "supply-chain": "Supply chain disruption: supplier/vendor failures, logistics & shipping disruption, raw-material shortages, multi-tier supplier risk, force majeure",
};

/** Normaliza la salida del modelo a {lens, severity 0-10, summary, signals[]}. Fallback seguro. */
export function parseClassification(content, lens) {
  let parsed;
  try {
    parsed = typeof content === "string" ? JSON.parse(content) : (content ?? {});
  } catch {
    parsed = { severity: 0, summary: String(content ?? "").slice(0, 240), signals: [] };
  }
  const severity = Math.max(0, Math.min(10, Number(parsed.severity) || 0));
  return {
    lens,
    severity,
    summary: typeof parsed.summary === "string" ? parsed.summary : "",
    signals: Array.isArray(parsed.signals) ? parsed.signals : [],
  };
}

/** Clasifica `text` bajo una lente. Llama AI/ML API. Lanza error claro sin key. */
export async function classify(text, lens = "security", opts = {}) {
  // `null` explícito = "sin key" (lanza); `undefined` = usar el env.
  const apiKey = opts.apiKey !== undefined ? opts.apiKey : process.env.AIML_API_KEY;
  if (!apiKey) throw new Error("Falta AIML_API_KEY para clasificar (AI/ML API).");
  // opts.model gana; si no, pickModel(opts.tier) o DEFAULT_MODEL si tampoco hay tier.
  const model = opts.model
    ? opts.model
    : opts.tier
      ? pickModel({ tier: opts.tier })
      : DEFAULT_MODEL;
  const baseUrl = opts.baseUrl ?? DEFAULT_BASE;
  const lensDesc = LENSES[lens] ?? lens;

  const system =
    `Sos un clasificador de inteligencia web. Lente: ${lensDesc}. ` +
    `Devolvé EXCLUSIVAMENTE JSON válido con esta forma: ` +
    `{"lens":"${lens}","severity":<0-10>,"summary":"<1-2 frases>","signals":["<señal>","..."]}.`;

  const res = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      messages: [
        { role: "system", content: system },
        { role: "user", content: String(text).slice(0, 8000) },
      ],
      temperature: 0,
      response_format: { type: "json_object" },
    }),
    signal: AbortSignal.timeout(opts.timeoutMs ?? 30000),
  });
  if (!res.ok) {
    throw new Error(`AI/ML API HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  }
  const data = await res.json();
  if (opts.onUsage && data.usage) opts.onUsage(data.usage); // telemetría de tokens (sin contaminar el finding)
  const content = data.choices?.[0]?.message?.content ?? "{}";
  return parseClassification(content, lens);
}

/** Clasifica el mismo texto bajo las 3 lentes (una tubería, tres inteligencias). */
export async function classifyTriLens(text, opts = {}) {
  const lenses = ["gtm", "finance", "security"];
  const results = await Promise.all(lenses.map((l) => classify(text, l, opts)));
  return Object.fromEntries(lenses.map((l, i) => [l, results[i]]));
}
