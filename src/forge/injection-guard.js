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
import { spotlight } from "../classify/spotlight.js";

// ─── Featherless / Qwen3Guard-Gen-8B (L2 detector, opt-in) ─────────────────
//
// Qwen3Guard-Gen-8B is a *generative thinking* moderation model. Its official
// HF chat_template (verified verbatim against tokenizer_config.json on
// huggingface.co, 2026-05-29) wraps the LAST `user` query in a SAFETY POLICY +
// UNSAFE CONTENT CATEGORIES block and primes an empty <think></think> turn,
// then asks for a 2-line verdict:
//   Safety: Safe|Unsafe|Controversial
//   Categories: <comma list> | None
//
// GATE-BEFORE-TRUST FINDING (probe, 2026-05-29): Featherless's
// `/chat/completions` applies ITS OWN generic chat template and IGNORES the
// model's bundled moderation template, so a `{role:user,content}` POST makes
// the model CHAT (benign doc → explanation; injection → refusal), never
// emitting `Safety:`. The fix that classifies correctly is to RENDER the
// official moderation template ourselves and POST it to `/completions` (raw
// text, NO server-side templating). Verified output:
//   benign    → "Safety: Safe\nCategories: None"
//   injection → "Safety: Unsafe\nCategories: Jailbreak"
// Hence renderQwen3GuardPrompt() + the `/completions` path below.
//
// Real HF model id (NOT "Qwen3Guard-8B" — that 404s on Featherless).
export const QWEN3GUARD_MODEL_ID = "Qwen/Qwen3Guard-Gen-8B";

// FEATHERLESS_GUARD_VERSION — bumps when the request/parse contract changes
// (template-shape, tier→score map, or the model id). Sealed in decisions[] so
// two runs on different bundle versions are auditable.
export const FEATHERLESS_GUARD_VERSION = "qwen3guard-gen-v1";

// Tier → score map (documented). Qwen3Guard emits a 3-way severity; we map it
// onto the existing 0.95-block / 0.5-review thresholds so _verdict() is reused
// verbatim. Safe→allow, Controversial→review, Unsafe→block.
//   Safe          → 0.00 (allow)
//   Controversial → 0.60 (review band: 0.5 ≤ s < 0.95)
//   Unsafe        → 0.97 (block band: s ≥ 0.95)
const _QWEN_TIER_SCORE = { Safe: 0.0, Controversial: 0.6, Unsafe: 0.97 };

// Official USER-branch moderation template (verbatim from the HF chat_template,
// USER branch). The head carries the SAFETY POLICY + 9 UNSAFE CONTENT
// CATEGORIES (Jailbreak included — it's the input branch); the tail carries the
// assessment instruction and primes an empty <think></think> so the verdict
// follows the closed think tag. We render this ourselves because Featherless
// does not apply the model's bundled template (see finding above).
const _QWEN_TEMPLATE_HEAD = `<|im_start|>user
# Task:
1) Evaluate whether THE LAST USER's query belongs to safe or unsafe content based on our safety policy.
2) Identify the category of unsafe content found.

<BEGIN SAFETY POLICY>
**Safety: Safe**: The USER's query does not contain any prohibited content or content that could lead to prohibited content.
**Safety: Unsafe**: The USER's query contains prohibited content.
**Safety: Controversial**: The USER's query does not explicitly contain prohibited content, but its intent, context, or potential responses could be misinterpreted, misused, or exploited to generate unsafe content under certain conditions.
<END SAFETY POLICY>

<BEGIN UNSAFE CONTENT CATEGORIES>
Violent.
Non-violent Illegal Acts.
Sexual Content or Sexual Acts.
PII.
Suicide & Self-Harm.
Unethical Acts.
Politically Sensitive Topics.
Copyright Violation.
Jailbreak.
<END UNSAFE CONTENT CATEGORIES>

<BEGIN CONVERSATION>

`;
const _QWEN_TEMPLATE_TAIL = `

<END CONVERSATION>

Provide your safety assessment for ONLY THE LAST **USER's query** in the above conversation:
 - The first line must be one of: 'Safety: Safe', 'Safety: Unsafe', 'Safety: Controversial'.
 - The second line should start with 'Categories:' followed by a list of any unsafe content categories, separated by commas. If the content is safe, use 'Categories: None'.<|im_end|>
<|im_start|>assistant
<think>

</think>

`;

/**
 * Render the full Qwen3Guard moderation prompt (official template) for a single
 * untrusted document, ready to POST to `/completions` raw. The doc is placed as
 * the LAST USER turn so the template's "ONLY THE LAST USER's query" assessment
 * targets it.
 *
 * Spotlighting (1.6): the doc is wrapped in per-request nonce sentinels
 * (`../classify/spotlight.js`) — unguessable, so a hostile doc can't forge the
 * closing delimiter to escape the data block. Kept INSIDE the USER turn so the
 * moderation template still assesses "the LAST USER's query".
 *
 * @param {string} text  — scraped content (untrusted)
 * @returns {string} the rendered ChatML moderation prompt
 */
export function renderQwen3GuardPrompt(text) {
  const { wrapped } = spotlight(text);
  return `${_QWEN_TEMPLATE_HEAD}USER: ${wrapped}${_QWEN_TEMPLATE_TAIL}`;
}

/**
 * Parse a Qwen3Guard-Gen completion into {safety, categories, score, verdict}.
 * The model emits (after a <think>…</think> block we strip):
 *   Safety: Safe|Unsafe|Controversial
 *   Categories: <comma list> | None
 *
 * Tolerant: case-insensitive label match, ignores the think block, handles the
 * verdict appearing anywhere in the text. Returns safety:null when no
 * `Safety:` verdict is present (the model chatted instead → caller degrades).
 *
 * @param {string} text  — raw completion content
 * @returns {{safety: "Safe"|"Unsafe"|"Controversial"|null, categories: string[], score: number, verdict: "allow"|"review"|"block"}}
 */
export function parseQwen3GuardCompletion(text) {
  const raw = String(text ?? "");
  // Drop the reasoning block so a "Safety:" mention inside <think> can't fool us.
  const body = raw.replace(/<think>[\s\S]*?<\/think>/gi, " ");

  const safetyMatch = body.match(/Safety:\s*(Safe|Unsafe|Controversial)\b/i);
  if (!safetyMatch) {
    return { safety: null, categories: [], score: 0, verdict: "allow" };
  }
  // Normalize to canonical capitalization (Safe/Unsafe/Controversial).
  const canon = { safe: "Safe", unsafe: "Unsafe", controversial: "Controversial" };
  const safety = canon[safetyMatch[1].toLowerCase()];

  const catMatch = body.match(/Categories:\s*([^\n\r]*)/i);
  const categories = catMatch
    ? catMatch[1]
        .split(",")
        .map((c) => c.trim())
        .filter((c) => c && !/^none$/i.test(c))
    : [];

  const score = _QWEN_TIER_SCORE[safety] ?? 0;
  return { safety, categories, score, verdict: _verdict(score) };
}

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
    // 4 sealed fields (§4) — the heuristic ALWAYS runs as a real mode, so it
    // seals a coherent shape too (NEVER undefined). model_hash is null because
    // the heuristic has no weights. The mode that ran is always sealed.
    guard_provider: "heuristic",
    guard_model: "heuristic-zero-dep",
    guard_version: POLICY_BUNDLE_VERSION,
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
  // Provider routing (A6): Featherless/Qwen3Guard uses an OpenAI chat-shaped
  // request + a 3-tier completion parser; everything else uses the legacy
  // classifier-shape ({text}→softmax). Autodetect Featherless by URL host.
  const provider = (opts.guardProvider ?? process.env.SYNTHEX_GUARD_PROVIDER ?? "").toLowerCase();
  const isFeatherless = provider === "featherless" || /featherless\.ai/i.test(url);
  if (isFeatherless) return _screenFeatherless(text, { ...opts, url });
  return _screenClassifier(text, { ...opts, url });
}

/**
 * Legacy classifier-shape path (vLLM/TGI/TEI Prompt-Guard servers). Sends
 * {text} and parses a softmax via parseGuardResponse. Fail-open to heuristic.
 */
async function _screenClassifier(text, opts) {
  const { url } = opts;
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
      // 4 sealed fields (§4) for the self-hosted classifier path.
      guard_provider: "prompt-guard",
      guard_model: opts.guardModel ?? process.env.SYNTHEX_GUARD_MODEL ?? "prompt-guard",
      guard_version: POLICY_BUNDLE_VERSION,
    };
  } catch {
    return heuristicScreen(text);
  }
}

/**
 * Featherless / Qwen3Guard-Gen path. Renders the official moderation template
 * ourselves and POSTs it to `/completions` RAW (Featherless does NOT apply the
 * model's bundled moderation chat_template server-side — see the gate finding
 * at the top of this file). The model emits the 2-line verdict, parsed by
 * parseQwen3GuardCompletion → score → _verdict. Fail-open to heuristic on any
 * error, non-200, or a non-classifying (chatted) response.
 *
 * BLOCK authority is GATED on the FP measurement (item 1.2): until then L2 runs
 * REVIEW-capped (a model "Unsafe"→block is demoted to review) unless
 * SYNTHEX_GUARD_BLOCK_ENABLED is truthy. The model verdict + raw score are
 * always sealed; only the *cap* changes.
 */
async function _screenFeatherless(text, opts) {
  const { url } = opts;
  const timeoutMs = opts.timeoutMs ?? (Number(process.env.SYNTHEX_GUARD_TIMEOUT_MS) || 60000);
  const fetchImpl = opts.fetchImpl ?? fetch;
  const apiKey = opts.apiKey ?? process.env.FEATHERLESS_API_KEY;
  const model = opts.guardModel ?? process.env.SYNTHEX_GUARD_MODEL ?? QWEN3GUARD_MODEL_ID;
  // Normalize so we POST to <base>/completions exactly once (strip a trailing
  // /chat/completions or /completions the caller may have included in the URL).
  const completionsUrl = `${url.replace(/\/+$/, "").replace(/\/(?:chat\/)?completions$/, "")}/completions`;

  const sealOk = (score, label) => ({
    verdict: _capVerdict(_verdict(score), opts),
    score,
    label,
    source: "featherless",
    model_hash: opts.modelHash ?? process.env.SYNTHEX_GUARD_MODEL_HASH ?? null,
    degraded: false,
    policy_bundle_version: POLICY_BUNDLE_VERSION,
    // 4 sealed fields (§4).
    guard_provider: "featherless",
    guard_model: model,
    guard_version: FEATHERLESS_GUARD_VERSION,
  });

  try {
    const headers = { "Content-Type": "application/json" };
    if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
    const body = JSON.stringify({
      model,
      prompt: renderQwen3GuardPrompt(text),
      max_tokens: 1024, // thinking model — room for <think> + the verdict
      temperature: 0,
    });
    // Bounded retry on TRANSIENT capacity/rate errors (503 capacity_exhausted, 429)
    // before degrading to the heuristic. Hosted moderation models hit capacity
    // intermittently; a short retry keeps L2 live without weakening the fail-open
    // guarantee (after the retries are exhausted we still fall back). Tunable via
    // SYNTHEX_GUARD_RETRIES (default 2). NOT applied to other 4xx (those are real).
    const maxRetries = Math.max(0, Number(process.env.SYNTHEX_GUARD_RETRIES ?? 2));
    let res;
    for (let attempt = 0; ; attempt++) {
      res = await fetchImpl(completionsUrl, { method: "POST", headers, body, signal: AbortSignal.timeout(timeoutMs) });
      if ((res.status === 503 || res.status === 429) && attempt < maxRetries) {
        await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
        continue;
      }
      break;
    }
    if (!res.ok) return heuristicScreen(text);
    const json = await res.json();
    // /completions returns choices[].text (raw); tolerate the chat shape too.
    const raw = json?.choices?.[0]?.text ?? json?.choices?.[0]?.message?.content ?? "";
    const { safety, categories, score } = parseQwen3GuardCompletion(raw);
    if (!safety) return heuristicScreen(text); // chatted, not classified → degrade
    const label = safety === "Safe" ? null : (categories[0] ?? safety);
    return sealOk(score, label);
  } catch {
    return heuristicScreen(text);
  }
}

/**
 * REVIEW-cap for L2 BLOCK authority (item 1.2 gate). Until the benign-FP of the
 * guard is measured and SYNTHEX_GUARD_BLOCK_ENABLED is turned on, a `block`
 * verdict is demoted to `review` (fail-safe: never drop a scraped doc on an
 * unmeasured guard). The raw score stays sealed so 1.2 can measure FP.
 */
function _capVerdict(verdict, opts) {
  const blockEnabled = opts.blockEnabled
    ?? (process.env.SYNTHEX_GUARD_BLOCK_ENABLED === "1"
      || process.env.SYNTHEX_GUARD_BLOCK_ENABLED === "true");
  if (verdict === "block" && !blockEnabled) return "review";
  return verdict;
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
 * @property {"prompt-guard"|"heuristic"|"featherless"} source
 * @property {string|null} model_hash  — sha of model weights, or null (heuristic)
 * @property {boolean} degraded  — true when running on the heuristic fallback
 * @property {string} policy_bundle_version
 * @property {"prompt-guard"|"heuristic"|"featherless"} guard_provider  — sealed (§4), always set
 * @property {string} guard_model  — sealed model id (§4), always set
 * @property {string} guard_version  — sealed bundle/template version (§4), always set
 */
