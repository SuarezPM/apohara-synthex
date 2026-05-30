// MULTIMODAL SCREEN — vision-assisted screening for prompt injections HIDDEN by CSS/layout that pure
// DOM-text extraction misses: white-on-white text, off-screen positioning, zero-opacity nodes, and
// alt-text payloads that render to a human (or a vision model) but never reach the classifier's text.
//
// Why this exists: the text pipeline (forge → classify) only ever sees the extracted DOM text. An
// attacker can paint an instruction onto the page so a screenshot shows it while `innerText` does not
// (e.g. `color:#fff` on a white background, `position:absolute;left:-9999px`, an <img alt="ignore all
// previous instructions">). This module renders the page, asks a vision-capable model what it SEES,
// and reconciles that against the extracted text to surface what slipped past extraction.
//
// HONESTY (load-bearing):
//   - `src/fetch/browser-client.js` returns TEXT ONLY today (`document.body.innerText`); it has no
//     screenshot method yet. So this module's pixel path is wired through an INJECTED `screenshotter`
//     pending a real screenshot capture on the browser client (a SEPARATE integration). Until then the
//     only non-stub way to get pixels is to pass your own screenshotter.
//   - The vision call is likewise INJECTED (`visionClient`). This module does NOT assert any specific
//     live vision-API request/response field shape — it delegates transport to the injected client and
//     normalizes a minimal, documented result contract (see `normalizeVisionResult`). The OpenAI-style
//     `image_url` data-URI scaffolding below is what a caller's adapter would send; it is NOT verified
//     against a live endpoint here. // TODO(verify): gate-probe the AI/ML API vision shape before
//     claiming a live multimodal capability in slides/docs.
//
// FAIL-SAFE: a missing/failing screenshotter or visionClient NEVER throws — it returns the envelope
// with `degraded:true` and an empty `findings` so the pipeline keeps going on text-only evidence.

const SURFACE = "multimodal";

/** Severity buckets for a multimodal finding (string, per the seal-ready envelope contract). */
export const SEVERITIES = Object.freeze(["low", "medium", "high"]);

/** Kinds of layout-hidden artifact this module reasons about. Stable identifiers for downstream rows. */
export const FINDING_KINDS = Object.freeze([
  "hidden-text", // visible in the render but absent from the extracted DOM text (CSS/off-screen)
  "alt-text-injection", // an instruction smuggled in image alt-text / aria-label
  "visual-mismatch", // the render shows instruction-like content the text layer does not account for
]);

/** A frozen, seal-ready envelope. Always this shape, success or degraded — never throws to the caller. */
function envelope({ findings = [], degraded = false, model, note } = {}) {
  const env = {
    surface: SURFACE,
    findings: Object.freeze(findings.map((f) => Object.freeze({ ...f }))),
    degraded,
    screenedAt: new Date().toISOString(),
  };
  if (model !== undefined) env.model = model;
  if (note !== undefined) env.note = note;
  return Object.freeze(env);
}

/** Coerce raw bytes/base64 into a canonical base64 string WITHOUT mutating the input. Returns null on failure. */
function toBase64(image) {
  try {
    if (image == null) return null;
    if (typeof image === "string") {
      // Accept a data-URI ("data:image/png;base64,XXXX") or a bare base64 string.
      const comma = image.indexOf(",");
      return image.startsWith("data:") && comma !== -1 ? image.slice(comma + 1) : image;
    }
    // Buffer | Uint8Array | ArrayBuffer → base64 via a fresh Buffer (no source mutation).
    const buf = image instanceof ArrayBuffer ? Buffer.from(new Uint8Array(image)) : Buffer.from(image);
    return buf.toString("base64");
  } catch {
    return null;
  }
}

/** Build the data-URI a vision adapter would attach. Pure; exported for the caller's adapter + tests. */
export function toDataUri(image, mime = "image/png") {
  const b64 = toBase64(image);
  return b64 ? `data:${mime};base64,${b64}` : null;
}

/**
 * Normalize whatever the injected `visionClient` returns into the finding contract this module emits.
 * Tolerant by design: the model adapter may already return findings, or just raw observed text we
 * reconcile against the extracted DOM text. Defensive — drops anything off-contract, never throws.
 *
 * Accepted input shapes (any one of):
 *   { findings: [{kind, evidence, severity}] }     ← adapter already structured the result
 *   { findings: [...], model }                      ← optional model id passed through
 *   { observedText: "...string the model read..." } ← we diff it against extractedText ourselves
 *
 * @param {object} raw                result from the injected visionClient
 * @param {string} extractedText      the DOM text the text pipeline already saw (for reconciliation)
 * @returns {{findings: object[], model: (string|undefined)}}
 */
export function normalizeVisionResult(raw, extractedText = "") {
  const out = { findings: [], model: undefined };
  if (raw == null || typeof raw !== "object") return out;
  if (typeof raw.model === "string") out.model = raw.model;

  // Path A — adapter already produced structured findings. Whitelist + clamp each one.
  if (Array.isArray(raw.findings)) {
    for (const f of raw.findings) {
      const norm = normalizeFinding(f);
      if (norm) out.findings.push(norm);
    }
  }

  // Path B — adapter returned the text the model SAW; reconcile against extracted DOM text.
  if (typeof raw.observedText === "string" && raw.observedText.length > 0) {
    for (const f of reconcile(raw.observedText, extractedText)) out.findings.push(f);
  }
  return out;
}

/** Whitelist a single finding to {kind, evidence, severity}; returns null if it can't be made valid. */
function normalizeFinding(f) {
  if (f == null || typeof f !== "object") return null;
  const kind = FINDING_KINDS.includes(f.kind) ? f.kind : "visual-mismatch";
  const evidence = typeof f.evidence === "string" ? f.evidence.slice(0, 500) : "";
  const severity = SEVERITIES.includes(f.severity) ? f.severity : "medium";
  if (!evidence) return null; // a finding with no evidence is not actionable — drop it
  return { kind, evidence, severity };
}

/** Normalize a string to a comparable form: lowercase, collapsed whitespace. Pure. */
function normalizeForCompare(s) {
  return String(s).toLowerCase().replace(/\s+/g, " ").trim();
}

/**
 * Reconcile what the model SAW against what text extraction CAPTURED. Any non-trivial line the model
 * read that is absent from the extracted text is a candidate "hidden-text" finding (it rendered but
 * never reached the classifier). Pure + deterministic; exported via normalizeVisionResult.
 */
function reconcile(observedText, extractedText) {
  const haystack = normalizeForCompare(extractedText);
  const findings = [];
  const lines = String(observedText).split(/\r?\n/);
  const seen = new Set();
  for (const line of lines) {
    const needle = normalizeForCompare(line);
    // Ignore trivial/short fragments — they false-positive against partial text matches.
    if (needle.length < 12) continue;
    if (seen.has(needle)) continue;
    seen.add(needle);
    if (!haystack.includes(needle)) {
      findings.push({
        kind: "hidden-text",
        evidence: line.trim().slice(0, 500),
        severity: "high", // seen-but-not-extracted is the exact CSS/layout-hidden case we screen for
      });
    }
  }
  return findings;
}

/**
 * Screen a rendered page for layout-hidden injections. BOTH collaborators are injected so this runs
 * fully offline in tests (no real browser, no real vision API):
 *
 *   - `screenshotter`: async () => (Buffer | Uint8Array | base64 string | data-URI). Captures the
 *     rendered PNG. If omitted you MUST pass `screenshot` directly. (No live browser capture exists on
 *     the browser client yet — see module header.)
 *   - `visionClient`: async ({ dataUri, extractedText, signal }) => raw result (see normalizeVisionResult).
 *     The vision-model call. If omitted/failing → degraded:true.
 *
 * Always returns the seal-ready envelope. NEVER throws on a recoverable failure.
 *
 * @param {{ extractedText?: string, screenshot?: (Buffer|Uint8Array|ArrayBuffer|string),
 *           screenshotter?: Function, visionClient?: Function, mime?: string, timeoutMs?: number }} [opts]
 * @returns {Promise<Readonly<{surface:'multimodal', findings:object[], degraded:boolean, screenedAt:string, model?:string, note?:string}>>}
 */
export async function screenMultimodal(opts = {}) {
  const {
    extractedText = "",
    screenshot,
    screenshotter,
    visionClient,
    mime = "image/png",
    timeoutMs = 30000,
  } = opts;

  // A vision client is mandatory for any real screening; without one we degrade rather than throw.
  if (typeof visionClient !== "function") {
    return envelope({ degraded: true, note: "no visionClient injected — text-only evidence stands" });
  }

  // 1) Obtain pixels: an explicit screenshot wins; otherwise call the injected screenshotter.
  let image = screenshot ?? null;
  if (image == null) {
    if (typeof screenshotter !== "function") {
      return envelope({ degraded: true, note: "no screenshot and no screenshotter injected" });
    }
    try {
      image = await screenshotter();
    } catch (err) {
      return envelope({ degraded: true, note: `screenshotter failed: ${errMsg(err)}` });
    }
  }

  const dataUri = toDataUri(image, mime);
  if (!dataUri) {
    return envelope({ degraded: true, note: "screenshot could not be encoded to a data-URI" });
  }

  // 2) Ask the injected vision client what it SEES; reconcile against the extracted DOM text.
  let raw;
  try {
    raw = await visionClient({
      dataUri,
      extractedText: String(extractedText),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    return envelope({ degraded: true, note: `visionClient failed: ${errMsg(err)}` });
  }

  const { findings, model } = normalizeVisionResult(raw, extractedText);
  return envelope({ findings, degraded: false, model });
}

/** Safe error-to-string; never throws on a weird error value. */
function errMsg(err) {
  try {
    return String(err?.message ?? err).slice(0, 200);
  } catch {
    return "unknown error";
  }
}
