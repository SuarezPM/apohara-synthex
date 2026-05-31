// ============================================================================
// STRESS DIMENSION (5) — LATENCY. Pure percentile math over per-run stage
// timings. NOT a live run: this module never touches the network or the clock;
// it only computes p50/p95/p99 from samples the harness already collected.
//
// Input shape mirrors `evidence.timings` (src/pipeline.js line 116/124): each
// per-run object has uppercase stage keys { FETCH, FORGE, CLASSIFY, PROVE } in
// milliseconds. We expose lowercase stage keys in the output (perStage.fetch …)
// to match the V2_PLAN P4.1 dimension contract.
//
// HONESTY (the moat): every percentile is nearest-rank over the *given* samples.
// We never interpolate, fabricate, or fill missing stages — a stage with zero
// valid samples reports null, and `n` always states how many samples backed the
// numbers so a caller can never mistake an empty stage for a fast one.
// ============================================================================

// Stage contract: uppercase key as it appears in evidence.timings → lowercase
// key as it appears in the dimension output. Order is the pipeline order.
const STAGES = Object.freeze([
  ["FETCH", "fetch"],
  ["FORGE", "forge"],
  ["CLASSIFY", "classify"],
  ["PROVE", "prove"],
]);

/**
 * Nearest-rank percentile (no interpolation). For a sorted-ascending array of n
 * samples and percentile p in [0,100], the rank is ceil((p/100) * n), clamped to
 * [1, n], and the value is the element at that 1-based rank.
 *
 * This matches the convention already used in scripts/bench-tsa-rtt.mjs.
 *
 * @param {number[]} sortedAsc  samples sorted ascending (caller's responsibility)
 * @param {number} p            percentile in [0,100]
 * @returns {number|null}       the percentile value, or null if there are no samples
 */
export function nearestRank(sortedAsc, p) {
  const n = sortedAsc.length;
  if (n === 0) return null;
  const rank = Math.ceil((p / 100) * n); // 1-based rank
  const idx = Math.min(n - 1, Math.max(0, rank - 1)); // clamp to [0, n-1]
  return sortedAsc[idx];
}

/**
 * Compute {p50,p95,p99,n} for one list of samples. Filters out non-finite values
 * (a missing/failed stage may push undefined/NaN) so a bad sample can never skew
 * a percentile; `n` reports how many samples actually counted.
 *
 * @param {number[]} samples  raw per-run durations in ms (unsorted, may contain holes)
 * @returns {{p50:number|null, p95:number|null, p99:number|null, n:number}}
 */
export function summarize(samples) {
  const clean = (Array.isArray(samples) ? samples : [])
    .filter((v) => typeof v === "number" && Number.isFinite(v))
    .slice()
    .sort((a, b) => a - b);
  return {
    p50: nearestRank(clean, 50),
    p95: nearestRank(clean, 95),
    p99: nearestRank(clean, 99),
    n: clean.length,
  };
}

/**
 * Latency percentiles over a list of per-run stage timings.
 *
 * @param {Array<{FETCH?:number, FORGE?:number, CLASSIFY?:number, PROVE?:number}>} timingsList
 *        one entry per pipeline run; the shape of evidence.timings.
 * @returns {{
 *   perStage: {
 *     fetch:    {p50:number|null, p95:number|null, p99:number|null, n:number},
 *     forge:    {p50:number|null, p95:number|null, p99:number|null, n:number},
 *     classify: {p50:number|null, p95:number|null, p99:number|null, n:number},
 *     prove:    {p50:number|null, p95:number|null, p99:number|null, n:number}
 *   },
 *   e2e: {p50:number|null, p95:number|null, p99:number|null, n:number}
 * }}
 *   per-stage and end-to-end percentiles. e2e is the per-run sum of the four
 *   stages, computed only over runs where every stage is a finite number (a run
 *   missing a stage cannot have an honest total, so it is excluded and reflected
 *   in e2e.n — never silently treated as zero for the hole).
 */
export function percentiles(timingsList) {
  const runs = Array.isArray(timingsList) ? timingsList : [];

  // Collect per-stage sample columns and the e2e column in a single pass.
  const stageSamples = { fetch: [], forge: [], classify: [], prove: [] };
  const e2eSamples = [];

  for (const run of runs) {
    const r = run && typeof run === "object" ? run : {};
    let total = 0;
    let complete = true;
    for (const [upper, lower] of STAGES) {
      const v = r[upper];
      if (typeof v === "number" && Number.isFinite(v)) {
        stageSamples[lower].push(v);
        total += v;
      } else {
        // A hole in any stage means we cannot form an honest end-to-end total
        // for this run. The stage column simply skips it; e2e excludes it.
        complete = false;
      }
    }
    if (complete) e2eSamples.push(total);
  }

  return {
    perStage: {
      fetch: summarize(stageSamples.fetch),
      forge: summarize(stageSamples.forge),
      classify: summarize(stageSamples.classify),
      prove: summarize(stageSamples.prove),
    },
    e2e: summarize(e2eSamples),
  };
}
