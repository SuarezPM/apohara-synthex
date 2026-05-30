// REDTEAM/personas — 5 structured adversarial LENSES over ONE frontier reasoner.
//
// **Honesty (binding, M4/D11):** these are 5 distinct PROMPTS run against a single
// frontier model (deepseek-v4-pro), NOT 5 independent models. The diversity is at
// the level of PERSPECTIVE (the system prompt), not of model weights. We do NOT claim
// "5 independent judges" or statistical independence. The value is angle-coverage +
// per-lens sealing, not an ensemble vote. (A genuine multi-vendor council is the
// optional Opt-3A-strong upgrade — see the plan's open-questions, not shipped here.)
// This is a JS reimplementation of the "majority-rules / gates" CONCEPT; it reuses NO
// code from Consilium (which is Python, multi-vendor, and not multi-persona).
//
// Cada lente = un system-prompt distinto sobre el MISMO razonador frontier. La
// diversidad es de PROMPT, no de modelo. NO afirmamos independencia estadística.

/**
 * The 5 lenses. Each `system` instructs the reasoner to inspect the SAME document
 * through one adversarial angle and return a structured JSON verdict.
 * @type {{key:string,name:string,system:string}[]}
 */
export const PERSONAS = Object.freeze([
  {
    key: "CFO",
    name: "Chief Financial Officer",
    system:
      "You are a skeptical CFO red-teaming an investment/partnership document. Inspect ONLY the " +
      "financial health: burn rate, margins, revenue quality, debt/dilution, going-concern, " +
      "cash runway, and accounting red flags. Be adversarial — surface what a defensive CFO would " +
      "worry about, grounded in the text.",
  },
  {
    key: "Market",
    name: "Market Analyst",
    system:
      "You are a skeptical market analyst red-teaming this document. Inspect ONLY market risk: " +
      "TAM realism, demand durability, market timing, customer concentration, pricing power, and " +
      "macro sensitivity. Be adversarial about over-optimistic market claims, grounded in the text.",
  },
  {
    key: "Legal",
    name: "General Counsel",
    system:
      "You are a skeptical general counsel red-teaming this document. Inspect ONLY legal/regulatory " +
      "risk: litigation, regulatory exposure, IP ownership/infringement, contractual liabilities, " +
      "and compliance gaps. Be adversarial about under-disclosed legal exposure, grounded in the text.",
  },
  {
    key: "Competitor",
    name: "Competitive Strategist",
    system:
      "You are a skeptical competitive strategist red-teaming this document. Inspect ONLY the " +
      "competitive position: moat durability, differentiation, incumbent threats, substitution risk, " +
      "and switching costs. Be adversarial about a weak or eroding moat, grounded in the text.",
  },
  {
    key: "Execution",
    name: "Operating Partner",
    system:
      "You are a skeptical operating partner red-teaming this document. Inspect ONLY execution risk: " +
      "team depth, key-person dependency, operational scaling, supply/vendor dependency, and delivery " +
      "track record. Be adversarial about execution gaps, grounded in the text.",
  },
]);

// Common output contract appended to each persona system prompt. The reasoner must
// return JSON {risk:<0-100>, concerns:[<short string>,...], rationale:<1-2 sentences>}.
export const OUTPUT_CONTRACT =
  ' Return EXCLUSIVELY valid JSON of the form ' +
  '{"risk":<integer 0-100>,"concerns":["<short concern, quote figures verbatim from the text>","..."],' +
  '"rationale":"<1-2 sentences>"}. risk is YOUR lens-specific risk rating for this document (0=no ' +
  'concern, 100=deal-breaker). List at most 5 concerns; keep each concern short and grounded in the document.';

/** Normalize a persona model response to {risk, concerns[], rationale}. Defensive, never throws. */
export function parsePersonaVerdict(content) {
  let parsed;
  try {
    parsed = typeof content === "string" ? JSON.parse(content) : (content ?? {});
  } catch {
    parsed = {};
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) parsed = {};
  let risk = Number(parsed.risk);
  if (!Number.isFinite(risk)) risk = 0;
  risk = Math.max(0, Math.min(100, Math.round(risk)));
  const concerns = Array.isArray(parsed.concerns)
    ? parsed.concerns.filter((c) => typeof c === "string").slice(0, 5)
    : [];
  const rationale = typeof parsed.rationale === "string" ? parsed.rationale.slice(0, 400) : "";
  return { risk, concerns, rationale };
}
