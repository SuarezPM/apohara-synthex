// PROVE/epss — FIRST.org EPSS (Exploit Prediction Scoring System) enrichment.
//
// EPSS gives a DAILY, public probability (0..1) that a CVE will be exploited in the wild in the
// next 30 days. Synthex uses it ONLY as an OPT-IN, ADDITIVE, NON-SEALED enrichment of the
// Security-lens Risk Score (render-time, never sealed). Honest limits (binding, HONESTY §4 + §10):
//   1. Findings do NOT carry structured CVE ids — the classifier schema is
//      {lens,severity,summary,signals[]}. CVE ids appear only as FREE TEXT, so extraction is a
//      best-effort regex over summary+signals. A real exploitable CVE the LLM didn't name is MISSED.
//   2. EPSS is exploitation PROBABILITY, NOT severity/impact, and NOT CVSS. It's a separate
//      FIRST.org framework — mapping, not endorsement; FIRST has not reviewed our number.
//   3. NEVER sealed: EPSS changes daily, so it is fetched at report-RENDER time (like timings/
//      charsSeen), never enters the canonical pre-image, never changes contentHash/HMAC. A verifier
//      offline reproduces the SAME sealed payload.
//   4. Multiple CVEs in one finding → the MAX epss drives the weight (most-exploitable wins).
//
// PROVE/epss — enriquecimiento EPSS de FIRST.org. OPT-IN, aditivo, NUNCA sellado (render-time). Los
// CVE ids se extraen por regex del texto del finding (best-effort); EPSS es probabilidad de
// explotación, no severidad; multi-CVE → max epss. Cero deps nuevas; fail-safe (nunca lanza).

// Standard MITRE CVE id grammar. Over-matching is harmless: an unknown id just yields an EPSS miss.
export const EPSS_RE = /CVE-\d{4}-\d{4,7}/gi;

const DEFAULT_EPSS_URL = "https://api.first.org/data/v1/epss";

/**
 * Extract de-duplicated, upper-cased CVE ids from an array of strings. Pure, sync, no network.
 * @param {string[]} strings
 * @returns {string[]}
 */
export function extractCveIds(strings) {
  const out = new Set();
  for (const s of Array.isArray(strings) ? strings : []) {
    const matches = String(s ?? "").match(EPSS_RE);
    if (matches) for (const m of matches) out.add(m.toUpperCase());
  }
  return [...out];
}

/**
 * CVE ids referenced by a finding (or a flattened trilens row): summary + signals[].
 * @param {{summary?:string, signals?:string[]}} row
 * @returns {string[]}
 */
export function cveIdsFromFinding(row) {
  const parts = [];
  if (row && typeof row.summary === "string") parts.push(row.summary);
  if (row && Array.isArray(row.signals)) parts.push(...row.signals.map(String));
  return extractCveIds(parts);
}

/**
 * Fetch EPSS for a set of CVE ids. The ONLY network function here. FAIL-SAFE: on ANY error
 * (network, non-200, bad JSON, abort, empty input) returns an EMPTY Map — NEVER throws — so the
 * caller simply applies no weighting. Batches all ids into ONE request and indexes by data[].cve
 * (the live API does NOT preserve request order — gate-verified 2026-05-30).
 *
 * @param {string[]} cveIds
 * @param {{fetchImpl?:typeof fetch, baseUrl?:string, timeoutMs?:number}} [opts]
 * @returns {Promise<Map<string,{epss:number, percentile:number}>>}
 */
export async function fetchEpss(cveIds, opts = {}) {
  const ids = extractCveIds(cveIds); // normalize/dedup; also tolerates raw strings
  const out = new Map();
  if (ids.length === 0) return out; // no network when there's nothing to look up
  const fetchImpl = opts.fetchImpl ?? fetch;
  const baseUrl = opts.baseUrl ?? process.env.SYNTHEX_EPSS_URL ?? DEFAULT_EPSS_URL;
  try {
    const url = `${baseUrl}?cve=${encodeURIComponent(ids.join(","))}`;
    const res = await fetchImpl(url, { signal: AbortSignal.timeout(opts.timeoutMs ?? 8000) });
    if (!res.ok) return out;
    const json = await res.json();
    const data = Array.isArray(json?.data) ? json.data : [];
    for (const d of data) {
      const cve = String(d?.cve ?? "").toUpperCase();
      if (!cve) continue;
      const epss = Math.max(0, Math.min(1, Number(d.epss)));
      const percentile = Math.max(0, Math.min(1, Number(d.percentile)));
      if (Number.isFinite(epss)) out.set(cve, { epss, percentile: Number.isFinite(percentile) ? percentile : 0 });
    }
  } catch {
    return new Map(); // fail-safe: no weighting on any failure
  }
  return out;
}

/**
 * Compute the EPSS weight for a finding given the fetched map + the finding's CVE ids. Pure, sync.
 * The MAX epss across matched ids drives the weight (most-exploitable wins). factor = 1 + alpha*epss
 * (alpha default 0.3 → up to +30% on the severity term at epss=1.0). No match → factor 1.0 (no-op).
 *
 * @param {Map<string,{epss:number}>} epssMap
 * @param {string[]} cveIds
 * @param {{alpha?:number}} [opts]
 * @returns {{factor:number, epss:number|null, cve:string|null}}
 */
export function epssWeight(epssMap, cveIds, opts = {}) {
  const alpha = Number.isFinite(opts.alpha) ? opts.alpha : 0.3;
  let best = null;
  for (const id of Array.isArray(cveIds) ? cveIds : []) {
    const hit = epssMap instanceof Map ? epssMap.get(String(id).toUpperCase()) : null;
    if (hit && (best === null || hit.epss > best.epss)) best = { epss: hit.epss, cve: String(id).toUpperCase() };
  }
  if (!best) return { factor: 1, epss: null, cve: null };
  return { factor: 1 + alpha * best.epss, epss: best.epss, cve: best.cve };
}
