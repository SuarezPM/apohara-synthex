// SERP SIGNAL LENS — a GTM/Security signal lens over the Bright Data SERP API.
//
// Why this exists: agents that scrape the open web also leave a SEARCHABLE footprint. A brand/entity's
// public SERP surface is itself intelligence — credential paste-dumps that mention it, regulatory
// filings, look-alike brand-abuse domains, hiring spikes. This module turns a (brand, signal-kind) pair
// into a SEARCH QUERY, fetches the SERP via the Bright Data SERP client, and returns a normalized,
// SEAL-READY envelope so the pipeline can classify + seal the signal the same way it seals scraped text.
//
// HONESTY: the only SERP result fields confirmed in-repo are `title` and `snippet` (see src/fetch/router.js
// + test/router.test.js). The per-result link field name returned by brd_json=1 is NOT confirmed here, so
// we read it defensively across the common candidates and never assert a single name. See TODO(verify).
//
// FAIL-SAFE: a configuration error (no token at fetch time) surfaces through the injected client. Every
// RECOVERABLE failure (network error, non-2xx, non-JSON SERP) returns a structured { ok:false, ... }
// envelope instead of throwing, so the pipeline never crashes on a bad signal fetch.
//
// PURE-ish: query building + normalization are pure and never mutate inputs; the only side effect is the
// injected fetch. The `fetcher` is INJECTABLE so the test suite uses a stub and never hits a live service.
import { BrightDataSerpClient } from "./serp-client.js";

export const SURFACE = "serp";

// The signal kinds this lens understands. Frozen so callers cannot mutate the contract.
export const SIGNAL_KINDS = Object.freeze(["credential-leak", "regulatory", "brand-abuse", "hiring"]);

/**
 * Build the Google search query for a (brand, kind) pair using STANDARD Google search operators
 * (site:, intitle:, quoted phrases) — no fabricated/undocumented syntax. Pure: returns a new string.
 *
 * @param {string} brand  the brand/entity to investigate (already trusted caller input).
 * @param {string} kind   one of SIGNAL_KINDS.
 * @returns {string} the search query.
 */
export function buildQuery(brand, kind) {
  const b = String(brand ?? "").trim();
  const quoted = `"${b}"`;
  switch (kind) {
    case "credential-leak":
      // Public paste/dump surfaces that name the brand alongside credential terms.
      return `${quoted} (password OR credentials OR "data breach" OR leak) (site:pastebin.com OR site:github.com)`;
    case "regulatory":
      // Regulator/enforcement surfaces (SEC, FTC) and filing/enforcement language.
      return `${quoted} (lawsuit OR fine OR violation OR settlement OR "enforcement action") (site:sec.gov OR site:ftc.gov)`;
    case "brand-abuse":
      // Look-alike / phishing / impersonation surfaces referencing the brand.
      return `${quoted} (phishing OR scam OR fake OR impersonation OR "look-alike domain")`;
    case "hiring":
      // Hiring footprint on the major job boards (security/GTM headcount signal).
      return `${quoted} (hiring OR "job opening" OR careers) (site:linkedin.com OR site:greenhouse.io OR site:lever.co)`;
    default:
      // Unknown kind: a plain brand query is the honest fallback (validation happens in scanSignal).
      return quoted;
  }
}

/**
 * Structured fail-safe envelope. NEVER thrown — returned so callers branch on `ok`.
 * @returns {{ok:false, surface:string, kind:string, query:string, fetchedAt:string, error:string, results:[], signals:[]}}
 */
function errorEnvelope(kind, query, message, extra = {}) {
  return {
    ok: false,
    surface: SURFACE,
    kind,
    query,
    fetchedAt: new Date().toISOString(),
    error: String(message),
    results: [],
    signals: [],
    ...extra,
  };
}

/**
 * Normalize the organic results of a brd_json=1 SERP payload into a stable [{title,url,snippet}] shape.
 * Pure: builds fresh records, never mutates the source array/objects. Caps the list to keep envelopes
 * small and the seal deterministic.
 *
 * Field provenance: `title` + `snippet` are confirmed (router.js / router.test.js). The link field name
 * is read defensively because brd_json=1's exact key is unconfirmed in-repo.
 *
 * @param {object} serp  parsed SERP JSON (expects an `organic` array).
 * @param {number} [limit=10]
 * @returns {Array<{title:string, url:string, snippet:string}>}
 */
export function normalizeResults(serp, limit = 10) {
  const organic = Array.isArray(serp?.organic) ? serp.organic : [];
  return organic.slice(0, limit).map((r) => ({
    title: typeof r?.title === "string" ? r.title : "",
    // TODO(verify): confirm the exact brd_json=1 organic link field. `link` is the SerpApi-style name;
    // `url`/`displayed_link` are read as fallbacks. Only title/snippet are confirmed in-repo.
    url: pickUrl(r),
    snippet: typeof r?.snippet === "string" ? r.snippet : "",
  }));
}

/** Read a result's URL defensively across the common candidate field names. Returns "" if none present. */
function pickUrl(r) {
  const candidate = r?.link ?? r?.url ?? r?.displayed_link;
  return typeof candidate === "string" ? candidate : "";
}

/**
 * Derive lightweight, string[] signals (the classify/redteam signal convention) from normalized results.
 * These are EVIDENCE-GROUNDED descriptors (count + domains seen), never fabricated claims — they only
 * restate what the SERP returned. Pure & deterministic.
 *
 * @param {string} kind
 * @param {Array<{title:string,url:string,snippet:string}>} results
 * @returns {string[]}
 */
export function deriveSignals(kind, results) {
  if (results.length === 0) return [`no SERP hits for ${kind}`];
  const domains = [];
  for (const r of results) {
    const host = hostOf(r.url);
    if (host && !domains.includes(host)) domains.push(host);
  }
  const signals = [`${results.length} SERP hit(s) for ${kind}`];
  if (domains.length > 0) signals.push(`domains: ${domains.slice(0, 8).join(", ")}`);
  return signals;
}

/** Extract a hostname from a result URL without throwing on a malformed/empty value. */
function hostOf(url) {
  if (!url) return "";
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

/**
 * Default SERP fetcher: wraps BrightDataSerpClient.search into the (query) => Promise<serpJson> shape
 * this module expects. Kept separate so callers/tests can inject their own fetcher instead.
 *
 * @param {{apiToken?:string, zone?:string, country?:string, timeoutMs?:number}} [opts]
 * @returns {(query:string) => Promise<object>}
 */
export function defaultSerpFetcher(opts = {}) {
  const client = new BrightDataSerpClient(opts);
  return (query) => client.search(query, { ...opts, json: true });
}

/**
 * Run the SERP signal lens for a (brand, kind) pair and return a SEAL-READY envelope.
 *
 * @param {string} brand  the brand/entity to investigate.
 * @param {string} kind   one of SIGNAL_KINDS.
 * @param {object} [opts]
 * @param {(query:string)=>Promise<object>} [opts.fetcher]  INJECTABLE SERP fetcher (defaults to the
 *   BrightDataSerpClient). Tests pass a stub so the suite never touches a live service.
 * @param {number} [opts.limit=10]  cap on normalized results.
 * @returns {Promise<{ok:boolean, surface:'serp', kind:string, query:string, fetchedAt:string,
 *   results:Array<{title:string,url:string,snippet:string}>, signals:string[], error?:string}>}
 */
export async function scanSignal(brand, kind, opts = {}) {
  const query = buildQuery(brand, kind);

  if (!SIGNAL_KINDS.includes(kind)) {
    return errorEnvelope(kind, query, `unknown signal kind "${kind}". Valid: ${SIGNAL_KINDS.join(", ")}`);
  }
  if (!String(brand ?? "").trim()) {
    return errorEnvelope(kind, query, "brand/entity is required");
  }

  const fetcher = opts.fetcher ?? defaultSerpFetcher(opts);
  const limit = Number.isInteger(opts.limit) && opts.limit > 0 ? opts.limit : 10;

  let serp;
  try {
    serp = await fetcher(query);
  } catch (err) {
    // Recoverable fetch failure (network/HTTP/auth) — structured envelope, never throw.
    return errorEnvelope(kind, query, err?.message ?? err);
  }

  if (serp == null || typeof serp !== "object") {
    return errorEnvelope(kind, query, "SERP fetcher returned a non-object payload");
  }

  const results = normalizeResults(serp, limit);
  const signals = deriveSignals(kind, results);

  return {
    ok: true,
    surface: SURFACE,
    kind,
    query,
    fetchedAt: new Date().toISOString(),
    results,
    signals,
  };
}
