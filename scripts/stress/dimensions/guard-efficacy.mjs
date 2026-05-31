// ============================================================================
// STRESS DIMENSION (3) — GUARD EFFICACY · reshape, NOT a live run.
//
// summarizeGuardEfficacy(results) is a PURE function. It takes the two-axis
// guard-recall payload (the shape scripts/measure-guard-recall.mjs writes to
// out/guard-recall/results.json) and reshapes it into the stress-report block:
//
//   { guards, winner, perLayer }
//
// - guards[]   per-guard recall + FP + block-recall + layer + BLOCK-eligibility
// - winner     the BLOCK-authority winner (qualifying L2 guard with max recall),
//              mirroring the decision rule in measure-guard-recall.mjs exactly
//              (FP ≤ threshold earns BLOCK authority; max recall wins; ties → none)
// - perLayer   L1 (zero-dep heuristic baseline) vs L2 (hosted guards) contribution
//
// HONESTY (the moat): this function MEASURES NOTHING. It only re-projects already
// measured numbers. It never invents recall/FP, never upgrades an unparsed sample
// into a catch, and never declares a winner the source decision did not earn. If a
// guard's FP is null (unmeasured) it is DISQUALIFIED, never silently passed. Pure,
// injectable, no I/O, no network, no mutation of the input.
// ============================================================================

// The canonical L1 guard key in measure-guard-recall.mjs (the only `local: true`
// guard). Everything else in guards{} is an L2 hosted candidate. Injectable so the
// caller can override if the L1 key set ever changes — kept honest, not guessed.
const DEFAULT_L1_KEYS = Object.freeze(["heuristic-l1"]);

// FP bar that earns BLOCK authority — identical to FP_THRESHOLD in
// measure-guard-recall.mjs. Read from the payload when present (the source records
// it as fp_threshold) so the two never drift; fall back to the documented 0.2.
const DEFAULT_FP_THRESHOLD = 0.2;

const isNum = (x) => typeof x === "number" && Number.isFinite(x);

// Resolve the benign-unparsed count for a guard. The source records it as the
// separate `unparsed_benign` (vs `unparsed_injection`); a single legacy `unparsed`
// total is NOT a substitute (it conflates injection drops, which leave fp valid).
// Returns null when benign coverage is unknown — fp validity then cannot be proven.
const unparsedBenignOf = (g) =>
  isNum(g.unparsed_benign) ? g.unparsed_benign : null;

const unparsedInjectionOf = (g) =>
  isNum(g.unparsed_injection) ? g.unparsed_injection : null;

/**
 * Reshape a two-axis guard-recall results payload into the stress-report block.
 *
 * @param {object} results  the out/guard-recall/results.json shape:
 *   { fp_threshold?, guards: { [name]: { id, tiers, recall, block_recall, fp,
 *     fp_describing, fp_neutral, unparsed_benign, unparsed_injection, n, counts } }, decision? }
 * @param {object} [opts]
 * @param {string[]} [opts.l1Keys]      guard keys treated as L1 (default ["heuristic-l1"])
 * @param {number}   [opts.fpThreshold] FP bar for BLOCK authority (default: payload.fp_threshold ?? 0.2)
 * @returns {{ guards: object[], winner: object|null, perLayer: object }}
 */
export function summarizeGuardEfficacy(results, opts = {}) {
  if (!results || typeof results !== "object" || !results.guards || typeof results.guards !== "object") {
    throw new Error("summarizeGuardEfficacy: results.guards object is required");
  }

  const l1Keys = new Set(opts.l1Keys ?? DEFAULT_L1_KEYS);
  const fpThreshold = isNum(opts.fpThreshold)
    ? opts.fpThreshold
    : isNum(results.fp_threshold)
      ? results.fp_threshold
      : DEFAULT_FP_THRESHOLD;

  // ── per-guard projection (no new numbers; only re-shape what was measured) ──
  const guards = Object.entries(results.guards).map(([name, g]) => {
    const layer = l1Keys.has(name) ? "L1" : "L2";
    const fp = isNum(g.fp) ? g.fp : null;
    const recall = isNum(g.recall) ? g.recall : null;
    const unparsed_benign = unparsedBenignOf(g);
    const unparsed_injection = unparsedInjectionOf(g);
    // FP is a valid measurement ONLY when every benign sample parsed. An unparsed
    // benign reply is not a clean ALLOW — it is a NON-MEASUREMENT; counting it in
    // the FP denominator fabricates a low FP (an all-unparsed-benign guard would
    // read fp→0 and qualify for BLOCK). fp is trustworthy iff unparsed_benign==0.
    // Unknown benign coverage (field absent) cannot prove validity → not valid.
    const fp_valid = fp != null && unparsed_benign === 0;
    // BLOCK eligibility mirrors the source rule (FP measured and ≤ bar) AND now
    // gates on fp validity: a guard with unparsed benign samples cannot earn BLOCK
    // authority on a fabricated-clean FP. L1 is the baseline, never a candidate.
    const block_eligible = layer === "L2" && fp_valid && fp <= fpThreshold;
    return Object.freeze({
      name,
      id: g.id ?? name,
      layer,
      tiers: Object.freeze([...(Array.isArray(g.tiers) ? g.tiers : [])]),
      recall,
      block_recall: isNum(g.block_recall) ? g.block_recall : null,
      fp,
      fp_valid,
      fp_describing: isNum(g.fp_describing) ? g.fp_describing : null,
      fp_neutral: isNum(g.fp_neutral) ? g.fp_neutral : null,
      unparsed_benign,
      unparsed_injection,
      samples: isNum(g.n) ? g.n : null,
      block_eligible,
    });
  });

  // ── BLOCK-authority winner — qualifying L2 guard with the highest recall. ──
  // Mirrors measure-guard-recall.mjs: rank L2 candidates by recall desc, keep
  // those with FP ≤ threshold, the top is the winner. A strict tie on recall
  // yields NO winner (we never pick arbitrarily — honesty over a coin flip).
  const eligible = guards
    .filter((g) => g.block_eligible)
    .sort((a, b) => (b.recall ?? -1) - (a.recall ?? -1));

  let winner = null;
  if (eligible.length) {
    const top = eligible[0];
    const tie = eligible[1] && (eligible[1].recall ?? -1) === (top.recall ?? -1);
    if (!tie) {
      winner = Object.freeze({
        name: top.name,
        id: top.id,
        fp: top.fp,
        recall: top.recall,
        block_recall: top.block_recall,
        fp_threshold: fpThreshold,
        reason: `FP ${fmtPct(top.fp)} ≤ ${fmtPct(fpThreshold)} earns BLOCK authority; highest recall ${fmtPct(top.recall)} among qualifying guards`,
        // FP is only valid because every benign sample parsed (unparsed_benign==0).
        // Qualification gates on this — an unparsed benign reply would invalidate FP.
        caveat: "fp is valid only when unparsed_benign==0 (an unparsed benign reply is a non-measurement, not a clean ALLOW)",
      });
    }
  }
  if (!winner) {
    winner = Object.freeze({
      name: null,
      reason: eligible.length
        ? `tie on recall among qualifying guards — no single BLOCK-authority winner`
        : `no L2 guard has FP ≤ ${fmtPct(fpThreshold)} — L2 stays all-REVIEW; L3 AlignmentCheck holds BLOCK authority`,
      fp_threshold: fpThreshold,
    });
  }

  // ── per-layer contribution — L1 baseline vs the best L2 catcher. ──
  // "Contribution" is the honest recall each layer delivers on the labeled
  // injections, plus the incremental recall L2 adds over the L1 baseline. We do
  // not sum overlapping catches (we cannot, without per-sample data here) — the
  // delta is reported as best-L2-recall minus L1-recall and labeled as such.
  const l1 = guards.find((g) => g.layer === "L1") ?? null;
  const l2 = guards.filter((g) => g.layer === "L2");
  const bestL2 = l2
    .filter((g) => isNum(g.recall))
    .sort((a, b) => (b.recall ?? -1) - (a.recall ?? -1))[0] ?? null;

  const l1Recall = l1 && isNum(l1.recall) ? l1.recall : null;
  const bestL2Recall = bestL2 ? bestL2.recall : null;
  const incrementalRecall =
    l1Recall != null && bestL2Recall != null ? round(bestL2Recall - l1Recall) : null;

  const perLayer = Object.freeze({
    L1: l1
      ? Object.freeze({
          name: l1.name,
          recall: l1.recall,
          fp: l1.fp,
          role: "zero-dep ingest screen (REVIEW-only baseline; not a BLOCK candidate)",
        })
      : null,
    L2: Object.freeze({
      candidates: Object.freeze(l2.map((g) => g.name)),
      best: bestL2 ? bestL2.name : null,
      best_recall: bestL2Recall,
      best_fp: bestL2 ? bestL2.fp : null,
    }),
    // Incremental recall the layered (L1→L2) posture buys over L1 alone, on the
    // labeled injections. Honest delta, NOT a deduplicated union of catches.
    layered_vs_l1_recall_delta: incrementalRecall,
  });

  return Object.freeze({ guards: Object.freeze(guards), winner, perLayer });
}

function round(x) {
  return Math.round(x * 1e6) / 1e6;
}

function fmtPct(x) {
  return x == null ? "n/a" : `${(x * 100).toFixed(0)}%`;
}

export { DEFAULT_L1_KEYS, DEFAULT_FP_THRESHOLD };
