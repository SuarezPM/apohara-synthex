// FORGE/injection-guard — Layer-2 prompt-injection detector. Calibrated as
// REVIEW-by-default with a high-confidence BLOCK threshold. NOT regex,
// NOT CaMeL — a stronger detector than the regex layers (DJL/prefilter) with
// documented domain-mismatch false-positive risk on technical content.
//
// **Honesty (HONESTY §8.A is binding):**
//   - This is a detector, NOT an architecture fix. We DO NOT claim "resolves
//     injection." We claim "stronger Layer-2 detector than regex, calibrated
//     for REVIEW with high-confidence BLOCK threshold."
//   - The Prompt-Guard model was trained on PROMPTS; we feed it scraped
//     DOCUMENTS. Domain mismatch → false positives on security blogs, CVE
//     pages, prompt-injection tutorials, etc. are expected. The REVIEW
//     verdict (0.5 ≤ score < 0.95) is designed for exactly that: surface
//     the decision without dropping the doc.
//   - The heuristic fallback runs when the model endpoint is unreachable.
//     guard_mode + model_hash are recorded in decisions[] (per the seal,
//     not run-dependent ops) so the divergence between two identical runs
//     under model-vs-heuristic is auditable instead of silent.
//   - NEVER uses Lakera or any cloud LLM API for screening (data egress
//     would break self-contained-evidence + offline-verify guarantees).
//     Self-hosted only via SYNTHEX_GUARD_URL.
//
// Naming choice (A3 binding): this is `injection-guard.js`, NOT `guard.js`.
// `src/guard.js` is the network-edge SSRF/rate-limit guard for the public
// endpoint — a completely separate concern. HONESTY §2.1 documents the
// two-guards distinction.
import { createHash } from "node:crypto";

// ─── Heuristic patterns (deterministic, zero-dep fallback) ─────────────────
//
// HIGH-confidence patterns: each match scores 0.92. Covers explicit jailbreak
// markers + system-prompt extraction phrasing the regex layer already catches —
// included here as a redundant Layer-2 safety net + multilingual coverage.
// Single hit → REVIEW (under the 0.95 BLOCK threshold by design); stacking
// (≥2 distinct labels) lifts the score to 0.95 → BLOCK.
const HIGH = [
  /\b(jailbreak|jailbroken)\b/i,
  /\b(developer mode|DAN mode)\b/i,
  /\bpretend (you are|to be)\s+(an? )?(unrestricted|uncensored|dan)\b/i,
  /\b(haz de cuenta|finj[íi]|finge|pretend[éa])\s+(que (sos|eres)|ser|estar)\s+(jailbroken|sin restricciones|sin censura)\b/i,
  /\b(reveal|show|print|leak|dump)\s+(your\s+)?(system prompt|hidden instructions|original prompt|secret prompt)\b/i,
  /\bmostr[áa]\s+(tu|el|tus|las)\s+(prompt|instrucciones)\s+(de sistema|del sistema|original|originales)\b/i,
];

// MEDIUM-confidence patterns: each match scores 0.6. Captures softer override
// framings, role-injection, and hypothetical phrasings. Stacks with HIGH.
const MED = [
  // Override framing — allows ANY chain of qualifiers between verb and noun
  // (handles "ignore all previous instructions", "forget every single one", etc.)
  /\b(?:forget|ignore|disregard|override)\s+(?:(?:all|every|your|the|previous|those|above|prior)\s+)+(?:instructions|rules|prompts|policies)\b/i,
  // Spanish/voseo override — same chain pattern (handles "olvidá todas las instrucciones")
  /\b(?:olvid[áa]|ignor[áa]|descart[áa])\s+(?:(?:todo|todas?|las|tus|esas|anteriores)\s+)+(?:instrucciones|reglas|directivas|órdenes)\b/i,
  /\bafter (?:you )?(?:read|process|see) this[,.]?\s+(?:do|execute|run|call|invoke)\b/i,
  /\bif you were (?:not |to be )?(?:bound|restricted|limited|unrestricted)\b/i,
  /\b(?:you are now|sos ahora|eres ahora)\s+(?:an?|un[ao]?)\s+(?:unrestricted|jailbroken|developer|sin restricciones)\b/i,
  // Chat-template smuggling — no \b prefix (angle bracket isn't a word char)
  /<\|(?:im_start|system|assistant)\|>/i,
  /\brole["\s:]+(?:system|assistant|developer)\b/i, // role-key smuggling in structured data
];

/**
 * Heuristic deterministic screener. Zero dependencies. Used as fallback when
 * the Prompt-Guard model endpoint is unreachable, and as the basis for offline
 * tests. Calibrated to REVIEW-by-default; only stacks to BLOCK with ≥2 hits.
 *
 * @param {string} text  — scraped content (untrusted)
 * @returns {GuardVerdict}
 */
export function heuristicScreen(text) {
  const t = String(text ?? "");
  let score = 0;
  const labels = [];
  for (const re of HIGH) {
    if (re.test(t)) {
      score = Math.max(score, 0.92);
      labels.push("high-confidence-injection");
    }
  }
  for (const re of MED) {
    if (re.test(t)) {
      score = Math.max(score, 0.6);
      labels.push("medium-confidence-injection");
    }
  }
  // Stacking: ≥2 distinct hits raise score above the BLOCK threshold.
  // Capped at 0.97 so we never claim 1.0 confidence from heuristics.
  if (labels.length >= 2) score = Math.min(0.97, score + 0.1);
  const verdict = _verdict(score);
  return {
    verdict,
    score,
    label: labels[0] ?? null,
    source: "heuristic",
    model_hash: null,
    degraded: true,
    policy_bundle_version: POLICY_BUNDLE_VERSION,
  };
}

/**
 * Parse a Prompt-Guard-shaped response into {score, label}. Tolerant of
 * three common return shapes from popular self-hosted servers (vLLM/TGI/TEI):
 *   A. {label: "INJECTION", score: 0.87}
 *   B. {scores: {BENIGN: 0.05, INJECTION: 0.82, JAILBREAK: 0.13}}
 *   C. {predictions: [{label, score}, ...]}
 *
 * Returns {score:0, label:null} on unparseable input — caller decides whether
 * that's an ALLOW or a degraded fallback.
 */
export function parseGuardResponse(json) {
  if (!json || typeof json !== "object") return { score: 0, label: null };
  // Shape A — flat label+score
  if (typeof json.score === "number") {
    return { score: _clamp01(json.score), label: typeof json.label === "string" ? json.label : null };
  }
  // Shape B — Meta Prompt-Guard 3-class softmax {BENIGN, INJECTION, JAILBREAK}
  if (json.scores && typeof json.scores === "object") {
    const benign = Number(json.scores.BENIGN ?? 0);
    const score = _clamp01(1 - benign);
    const ranked = Object.entries(json.scores)
      .filter(([k]) => k !== "BENIGN")
      .map(([k, v]) => [k, Number(v) || 0])
      .sort((a, b) => b[1] - a[1]);
    return { score, label: ranked[0]?.[0] ?? null };
  }
  // Shape C — array of predictions
  if (Array.isArray(json.predictions)) {
    const top = [...json.predictions].sort((a, b) => (Number(b?.score) || 0) - (Number(a?.score) || 0))[0];
    return { score: _clamp01(Number(top?.score) || 0), label: typeof top?.label === "string" ? top.label : null };
  }
  return { score: 0, label: null };
}

/**
 * Screen text via the Prompt-Guard endpoint at SYNTHEX_GUARD_URL, with
 * fail-open fallback to the heuristic. NEVER throws. The endpoint MUST be
 * self-hosted (we do not send scraped content to any external API — see HONESTY
 * §8.A on the data-egress + self-contained-evidence guarantees).
 *
 * @param {string} text
 * @param {{
 *   guardUrl?: string,
 *   timeoutMs?: number,
 *   modelHash?: string,
 *   fetchImpl?: typeof fetch,  // inyectable para tests sin red
 * }} [opts]
 * @returns {Promise<GuardVerdict>}
 */
export async function screen(text, opts = {}) {
  const url = opts.guardUrl ?? process.env.SYNTHEX_GUARD_URL;
  if (!url) return heuristicScreen(text); // no endpoint configured → heuristic
  const timeoutMs = opts.timeoutMs ?? 5000;
  const fetchImpl = opts.fetchImpl ?? fetch;
  try {
    const res = await fetchImpl(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: String(text ?? "") }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return heuristicScreen(text);
    const json = await res.json();
    const { score, label } = parseGuardResponse(json);
    return {
      verdict: _verdict(score),
      score,
      label,
      source: "prompt-guard",
      model_hash: opts.modelHash ?? process.env.SYNTHEX_GUARD_MODEL_HASH ?? null,
      degraded: false,
      policy_bundle_version: POLICY_BUNDLE_VERSION,
    };
  } catch {
    return heuristicScreen(text);
  }
}

// ─── internals ──────────────────────────────────────────────────────────

function _clamp01(n) {
  return Math.max(0, Math.min(1, Number(n) || 0));
}

function _verdict(score) {
  if (score >= 0.95) return "block";
  if (score >= 0.5) return "review";
  return "allow";
}

// POLICY_BUNDLE_VERSION — sha256-12 of the corpus + thresholds, same pattern
// as djl.js / prefilter.js. Captures changes to HIGH/MED regex sources or the
// 0.95/0.5 thresholds automatically. Bump the `vN` only if the verdict
// contract or shape changes (currently: {verdict, score, label, source,
// model_hash, degraded, policy_bundle_version}).
const _corpus = JSON.stringify({
  high: HIGH.map((r) => r.source).sort(),
  med: MED.map((r) => r.source).sort(),
  thresholds: { block: 0.95, review: 0.5 },
});
export const POLICY_BUNDLE_VERSION = `guard-v1-${createHash("sha256").update(_corpus).digest("hex").slice(0, 12)}`;

/**
 * @typedef {object} GuardVerdict
 * @property {"allow"|"review"|"block"} verdict
 * @property {number} score  — 0..1
 * @property {string|null} label  — top non-BENIGN class or heuristic label
 * @property {"prompt-guard"|"heuristic"} source
 * @property {string|null} model_hash  — sha of model weights when source=prompt-guard
 * @property {boolean} degraded  — true when running on the heuristic fallback
 * @property {string} policy_bundle_version
 */
