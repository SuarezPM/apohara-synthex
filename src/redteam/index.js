// REDTEAM/index — orchestrate the 5 adversarial lenses (personas.js) over ONE frontier
// reasoner (deepseek-v4-pro), ground each lens's concerns against the window the model saw
// (grounding 1.5), and aggregate into Risk Score 0-100 + band + Top-3 board questions +
// verdict PROCEED | CAUTION | DO NOT PROCEED. On-demand ONLY (high-stakes) — NEVER bulk.
//
// Honesty (M4): 5 PROMPTS, 1 model. Prompt-diversity, not model-diversity; temperature can be
// raised >0 to de-correlate the lenses (documented), but we do NOT claim statistical
// independence. Each lens is sealed per-lens (stage REDTEAM_<key>) with its model_id + grounding.
import { PERSONAS, OUTPUT_CONTRACT, parsePersonaVerdict } from "./personas.js";
import { spotlight, spotlightInstruction } from "../classify/spotlight.js";
import { ground } from "../classify/grounding.js";
import { pickModel } from "../classify/tiers.js";

const REDTEAM_MODEL = process.env.SYNTHEX_REDTEAM_MODEL || pickModel({ tier: "pro" });
const MAX_CHARS = 8000;
export const REDTEAM_VERSION = "redteam-v1";

// Default runner: a real deepseek-v4-pro call. Throws on no-key / non-200 / timeout so the
// per-lens loop degrades that lens to risk 0 (fail-safe — a dead lens cannot inflate the verdict).
async function defaultRunner({ system, wrapped, model, apiKey, timeoutMs, temperature }) {
  const key = apiKey !== undefined ? apiKey : process.env.AIML_API_KEY;
  if (!key) throw new Error("no AIML_API_KEY");
  const baseUrl = process.env.AIML_BASE_URL || "https://api.aimlapi.com/v1";
  const res = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      messages: [
        { role: "system", content: system },
        { role: "user", content: wrapped },
      ],
      temperature: temperature ?? 0.3, // >0 to de-correlate lenses (documented; NOT independence)
      response_format: { type: "json_object" },
    }),
    signal: AbortSignal.timeout(timeoutMs ?? 60000), // v4-pro is a slow reasoner; a per-lens timeout degrades only that lens (fail-safe)
  });
  if (!res.ok) throw new Error(`AI/ML API HTTP ${res.status}`);
  const data = await res.json();
  return data.choices?.[0]?.message?.content ?? "{}";
}

function aggregate(perLens) {
  const risks = perLens.map((l) => l.risk);
  if (!risks.length) return { score: 0, band: "LOW", verdict: "PROCEED" };
  const avg = risks.reduce((a, b) => a + b, 0) / risks.length;
  const max = Math.max(...risks);
  // Blend mean + worst-case (a single deal-breaker lens should pull the score up).
  const score = Math.round(avg * 0.5 + max * 0.5);
  const band = score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW";
  const verdict = score >= 70 ? "DO NOT PROCEED" : score >= 40 ? "CAUTION" : "PROCEED";
  return { score, band, verdict };
}

/**
 * Run the sealed 5-lens red-team over `text`.
 * @param {string} text  the document (S-1 / filing / page) to red-team.
 * @param {{
 *   runner?: Function,   // injectable per-lens transport (offline/tests); default = real v4-pro
 *   model?: string,
 *   apiKey?: string|null,
 *   timeoutMs?: number,
 *   temperature?: number,
 * }} [opts]
 * @returns {Promise<{score:number, band:string, verdict:string, topQuestions:string[], perLens:object[], model_id:string, degraded:boolean}>}
 */
export async function redTeam(text, opts = {}) {
  const raw = String(text ?? "");
  const charsSeen = Math.min(raw.length, MAX_CHARS);
  const slice = raw.slice(0, charsSeen);
  const run = typeof opts.runner === "function" ? opts.runner : defaultRunner;
  const model = opts.model ?? REDTEAM_MODEL;

  const perLens = [];
  for (const p of PERSONAS) {
    const { nonce, wrapped } = spotlight(slice);
    const system = `${p.system} ${spotlightInstruction(nonce)}${OUTPUT_CONTRACT}`;
    let verdict;
    let degraded = false;
    try {
      const content = await run({
        system, wrapped, model, persona: p.key,
        apiKey: opts.apiKey, timeoutMs: opts.timeoutMs, temperature: opts.temperature,
      });
      verdict = parsePersonaVerdict(typeof content === "string" ? content : content?.content ?? content);
    } catch {
      verdict = { risk: 0, concerns: [], rationale: "lens unavailable (degraded)" };
      degraded = true;
    }
    // Ground each lens's concerns against the window the model saw (drops fabricated figures).
    const g = ground({ signals: verdict.concerns }, raw, { charsSeen });
    perLens.push({
      stage: `REDTEAM_${p.key}`,
      persona: p.key,
      name: p.name,
      risk: verdict.risk,
      concerns: g.signals,
      droppedConcerns: g.droppedSignals,
      rationale: verdict.rationale,
      grounding: g.outcome,
      charsSeen,
      model_id: model,
      version: REDTEAM_VERSION,
      degraded,
    });
  }

  const agg = aggregate(perLens);
  // Top-3 board questions: pull the highest-risk lenses' top grounded concerns.
  const topQuestions = perLens
    .slice()
    .sort((a, b) => b.risk - a.risk)
    .flatMap((l) => l.concerns.map((c) => `[${l.persona}] ${c}`))
    .slice(0, 3);

  return {
    ...agg,
    topQuestions,
    perLens,
    model_id: model,
    degraded: perLens.every((l) => l.degraded),
  };
}
