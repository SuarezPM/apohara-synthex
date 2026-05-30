// CLASSIFY/grounding — deterministic, ZERO-LLM grounding verifier.
//
// The classifier (and L3 / red-team) can hallucinate a NUMBER that the source
// never stated — "$42B acquisition" on a page that mentions no money. The seal
// proves the report wasn't tampered AFTER signing; it cannot prove the model
// didn't invent a figure. This verifier closes that gap with pure code (no LLM,
// no network, no new deps): every NAMED FIGURE in a finding's signals must match
// — number-normalized — against the SAME byte window the model actually saw
// (`raw.slice(0, charsSeen)`, where charsSeen = min(len, 8000) — aiml-client.js).
//
// Verdict per figure-bearing signal:
//   - figure present INSIDE [0, charsSeen)        -> VERIFIED  (kept)
//   - figure present ONLY in raw[charsSeen:]       -> UNVERIFIED (kept, flagged):
//        the model could NOT have derived it from the text it received, so we do
//        NOT claim grounding — we tag it, we don't assert it.
//   - figure present NOWHERE in the source         -> DROPPED   (removed from the finding)
// Signals with NO named figure are pass-through (not adjudicated): the verifier
// targets fabricated FIGURES, the real risk, and stays conservative — it does NOT
// drop legitimate keyword/paraphrase signals (the "too aggressive" failure mode).
//
// CLASSIFY/grounding — verificador de grounding determinista, CERO LLM. Cada CIFRA
// NOMBRADA de un finding debe matchear (number-normalized) contra la MISMA ventana
// de bytes que el modelo vio (raw.slice(0, charsSeen)). Dentro de la ventana →
// VERIFIED; solo más allá → UNVERIFIED (no afirmamos grounding); en ningún lado →
// DROPPED. Señales sin cifra pasan sin tocar (conservador: no dropea paráfrasis).
//
// charsSeen is SEALED in the GROUNDING decision row as the verification frontier.

// Window the LLM saw (mirrors aiml-client.js MAX_CHARS). The raw payload text is
// NEVER altered — only the verification window is bounded.
const MAX_CHARS = 8000;

// Scale words/suffixes → multiplier. Lowercased before lookup.
const SCALE = {
  k: 1e3, thousand: 1e3,
  m: 1e6, mm: 1e6, million: 1e6,
  b: 1e9, bn: 1e9, billion: 1e9,
  t: 1e12, trillion: 1e12,
};

// A figure = optional currency, a number (with thousands/decimal separators),
// an optional scale word/suffix (word-bounded so "5moves" is not "5M"), and an
// optional trailing %. Currency symbol is ignored for matching ("$1.5M" == "1.5M");
// "%" is kept in the canonical token so "20%" never matches a bare "20".
const FIGURE_RE = /(?:\$|€|£|usd\s*)?\s*(\d[\d,]*(?:\.\d+)?)\s*(thousand|million|billion|trillion|bn|mm|[kmbt])?\b\s*(%)?/gi;

/**
 * Extract the canonical figures mentioned in `text` as a Set of normalized
 * tokens. "$1,500,000" and "1.5M" both → "1500000"; "20%" → "20%". This is the
 * number/currency normalization that lets "$1,500,000" and "1.5M" match.
 *
 * @param {string} text
 * @returns {Set<string>}
 */
export function extractFigures(text) {
  const out = new Set();
  const s = String(text ?? "");
  for (const m of s.matchAll(FIGURE_RE)) {
    const numRaw = m[1].replace(/,/g, "");
    let val = parseFloat(numRaw);
    if (!Number.isFinite(val)) continue;
    const scaleKey = m[2] ? m[2].toLowerCase() : null;
    if (scaleKey && SCALE[scaleKey]) val *= SCALE[scaleKey];
    const isPct = !!m[3];
    // Normalize to a stable string. Integers print without a trailing ".0";
    // percentages keep their marker so they don't collide with bare counts.
    const canon = Number.isInteger(val) ? String(val) : String(val);
    out.add(isPct ? `${canon}%` : canon);
  }
  return out;
}

/**
 * Verify ONE signal's figures. Returns its grounding status, or {hasFigure:false}
 * when the signal carries no named figure (pass-through, not adjudicated).
 */
function groundSignal(signal, windowFigures, sourceFigures) {
  const figs = extractFigures(signal);
  if (figs.size === 0) return { hasFigure: false };
  for (const f of figs) if (windowFigures.has(f)) return { hasFigure: true, status: "VERIFIED" };
  for (const f of figs) if (sourceFigures.has(f)) return { hasFigure: true, status: "UNVERIFIED" }; // only beyond window
  return { hasFigure: true, status: "DROPPED" }; // fabricated — nowhere in the source
}

/**
 * Ground a finding's signals against the source window. Drops fabricated figures,
 * flags beyond-window ones, keeps verified + non-figure signals. Pure & sync.
 *
 * @param {{signals?:string[]}} finding  a classify/L3/red-team finding.
 * @param {string} source                the FULL raw scraped text (unaltered).
 * @param {{charsSeen?:number}} [opts]    the LLM window frontier; default min(len, 8000).
 * @returns {{
 *   finding: object,        // {...finding, signals: kept[]}
 *   signals: string[],      // alias of finding.signals (kept)
 *   outcome: "VERIFIED"|"DROPPED"|"UNVERIFIED",
 *   charsSeen: number,      // sealed verification frontier
 *   counts: {verified:number, dropped:number, unverified:number},
 *   adjudicated: number,    // # signals that carried a figure to verify
 *   droppedSignals: string[],
 *   unverifiedSignals: string[],
 * }}
 */
export function ground(finding, source, opts = {}) {
  const src = String(source ?? "");
  const charsSeen = Number.isFinite(opts.charsSeen)
    ? Math.max(0, Math.min(opts.charsSeen, src.length))
    : Math.min(src.length, MAX_CHARS);

  const windowFigures = extractFigures(src.slice(0, charsSeen));
  const sourceFigures = extractFigures(src);

  const signals = Array.isArray(finding?.signals) ? finding.signals : [];
  const kept = [];
  const droppedSignals = [];
  const unverifiedSignals = [];
  let verified = 0;
  let dropped = 0;
  let unverified = 0;
  let adjudicated = 0;

  for (const sig of signals) {
    const r = groundSignal(sig, windowFigures, sourceFigures);
    if (!r.hasFigure) {
      kept.push(sig); // no named figure → pass-through (conservative, not dropped)
      continue;
    }
    adjudicated++;
    if (r.status === "VERIFIED") {
      verified++;
      kept.push(sig);
    } else if (r.status === "UNVERIFIED") {
      unverified++;
      kept.push(sig); // kept but the GROUNDING row records it as unverified
      unverifiedSignals.push(sig);
    } else {
      dropped++; // fabricated → removed from the finding
      droppedSignals.push(sig);
    }
  }

  const outcome = dropped > 0 ? "DROPPED" : unverified > 0 ? "UNVERIFIED" : "VERIFIED";
  return {
    finding: { ...finding, signals: kept },
    signals: kept,
    outcome,
    charsSeen,
    counts: { verified, dropped, unverified },
    adjudicated,
    droppedSignals,
    unverifiedSignals,
  };
}

// Exported for the pipeline so the window constant has a single source of truth.
export const GROUNDING_WINDOW = MAX_CHARS;
