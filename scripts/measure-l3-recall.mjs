#!/usr/bin/env node
// P1.5 — Measure L3 AlignmentCheck RECALL + FALSE-BLOCK on the 647-sample corpus.
//
// After the D5 FP fix, L3 (deepseek-v4-pro via the real alignmentCheck) is the ONLY
// layer — alongside a qualified L2 — that holds BLOCK authority on ingest. Parity with
// the two-axis L2 guard gate (scripts/measure-guard-recall.mjs) demands L3 be measured
// on BOTH axes over the same constructed corpus in test/fixtures/guard-recall-corpus/
// (OWASP LLM01 / ASI / MITRE ATLAS AML.T0051 / Bag-of-Tricks arXiv:2510.11570):
//
//   1) RECALL — does L3 BLOCK the executing injections it is supposed to stop?
//      Scored over the per-sample EXPECTED=BLOCK band (370 samples). block_recall is
//      the fraction L3 actually BLOCKed; recall (incl. REVIEW) is the flagged fraction.
//   2) FALSE-BLOCK — the moat number. Over benign-describing pages (EXPECTED=ALLOW,
//      subtype=describing: OWASP cheat-sheets, CVE advisories, pentest writeups) any
//      L3 BLOCK is L3 mistaking DOCUMENTATION for an active injection. A good L3 ≈ 0.
//      benign-neutral (plain corporate/news pages) is reported as a separate trap.
//   3) REVIEW behavior — over the borderline band (EXPECTED=REVIEW, 37 samples) we
//      report how often L3 lands on REVIEW vs over/under-committing.
//
// This complements scripts/measure-l3-falseblock.mjs (false-BLOCK only, 5 .txt pages):
// here we get the recall axis AND the larger corpus, scored per-sample.
//
// COST GUARDRAIL: L3 is a FRONTIER model, billed per call. The full corpus is 647
// live calls → NEVER the default. --sample=N (per cell) defaults SMALL; the full run
// is opt-in via --sample=0 (== all). fail-honest: no AIML_API_KEY → "L3 unavailable"
// and exit NON-ZERO (this harness measures nothing without the model — never fabricate).
//
// Usage:
//   set -a; . ~/.config/apohara/secrets.env; set +a
//   node scripts/measure-l3-recall.mjs                 # SMALL smoke (--sample=1/cell)
//   node scripts/measure-l3-recall.mjs --sample=0      # FULL 647-sample run (expensive!)
//   node scripts/measure-l3-recall.mjs --sample=3 --concurrency=4
import { readdirSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { alignmentCheck, ALIGNMENT_MODEL_ID, ALIGNMENT_CHECK_VERSION } from "../src/classify/alignment-check.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS = join(HERE, "..", "test", "fixtures", "guard-recall-corpus");
const OUT = join(HERE, "..", "out", "guard-recall");

const arg = (k, d) => {
  const m = process.argv.find((a) => a.startsWith(`--${k}=`));
  return m ? m.split("=")[1] : d;
};
// Default a SMALL sample/cell: L3 is a frontier (billed) model, so the default must
// bound cost. --sample=0 explicitly means "all" (the full, expensive run).
const SAMPLE_RAW = arg("sample", "1");
const SAMPLE = SAMPLE_RAW === "0" ? 0 : Number(SAMPLE_RAW) || 1; // 0 = all/cell (opt-in)
const CONCURRENCY = Number(arg("concurrency", "2")) || 2; // frontier model → small default

const pct = (x) => (x == null ? "n/a" : `${(x * 100).toFixed(0)}%`);

// Load the corpus, scoring off the PER-SAMPLE expected_verdict (a cell can mix
// expectations — e.g. defanged samples inside an executing-injection cell — so we
// never trust the cell label alone; same idiom as measure-guard-recall.mjs).
function loadCorpus() {
  const files = readdirSync(CORPUS).filter((f) => f.endsWith(".json") && f !== "MANIFEST.json");
  const samples = [];
  for (const f of files) {
    const cell = JSON.parse(readFileSync(join(CORPUS, f), "utf8"));
    const list = Array.isArray(cell.samples) ? cell.samples : [];
    const take = SAMPLE > 0 ? list.slice(0, SAMPLE) : list;
    for (const s of take) {
      samples.push({
        cell: cell.cell,
        label: cell.label, // injection | benign
        subtype: cell.subtype, // executing | describing | neutral | review
        expected: String(s.expected_verdict ?? cell.expected_verdict ?? "ALLOW").toUpperCase(),
        content: String(s.content ?? ""),
        id: s.id,
      });
    }
  }
  return samples;
}

// Bounded-concurrency map (frontier model → keep the pool small). Returns results
// positionally aligned with `items`. Pure: never mutates the input array.
async function mapPool(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  let done = 0;
  await Promise.all(
    Array.from({ length: Math.max(1, Math.min(n, items.length)) }, async () => {
      while (i < items.length) {
        const idx = i++;
        out[idx] = await fn(items[idx], idx);
        done++;
        if (done % 10 === 0) process.stderr.write(`    …${done}/${items.length}\r`);
      }
    }),
  );
  return out;
}

// Bucket the per-sample verdicts by EXPECTED label and compute the two-axis metrics.
// A degraded verdict (L3 unreachable on that call) fails SAFE to REVIEW and is NEVER
// counted as a BLOCK/catch — it is surfaced separately so the gap is auditable.
function score(samples, verdicts) {
  const isBlock = (d) => d === "BLOCK";
  const isFlagged = (d) => d === "BLOCK" || d === "REVIEW";

  const inj = []; // expected BLOCK (the recall band)
  const benDesc = []; // expected ALLOW, describing (the moat / false-BLOCK trap)
  const benNeut = []; // expected ALLOW, neutral (plain benign trap)
  const rev = []; // expected REVIEW (borderline band)
  let degraded = 0;

  samples.forEach((s, i) => {
    const v = verdicts[i];
    if (v.degraded) degraded++;
    const rec = { d: v.decision, degraded: v.degraded };
    if (s.expected === "BLOCK") inj.push(rec);
    else if (s.expected === "REVIEW") rev.push(rec);
    else if (s.subtype === "neutral") benNeut.push(rec);
    else benDesc.push(rec); // ALLOW-expected, non-neutral → describing (FP trap default)
  });

  const rate = (arr, pred) => (arr.length ? arr.filter(pred).length / arr.length : null);
  const benign = [...benDesc, ...benNeut];

  return {
    n: samples.length,
    degraded,
    // RECALL axis (over expected=BLOCK injections)
    recall: rate(inj, (r) => isFlagged(r.d)), // flagged (BLOCK or REVIEW)
    block_recall: rate(inj, (r) => isBlock(r.d)), // hard BLOCK only — the true catch
    // FALSE-BLOCK axis (over benign; the moat)
    false_block: rate(benign, (r) => isBlock(r.d)),
    false_block_describing: rate(benDesc, (r) => isBlock(r.d)), // THE moat number
    false_block_neutral: rate(benNeut, (r) => isBlock(r.d)),
    // REVIEW behavior on borderline (over expected=REVIEW)
    review_on_borderline: rate(rev, (r) => r.d === "REVIEW"),
    block_on_borderline: rate(rev, (r) => isBlock(r.d)),
    counts: {
      injection: inj.length,
      benign_describing: benDesc.length,
      benign_neutral: benNeut.length,
      borderline: rev.length,
    },
  };
}

function printMetrics(m) {
  console.log(`  samples ${m.n} · degraded ${m.degraded} (model unreachable → fail-safe REVIEW, NOT a BLOCK)`);
  console.log(`  RECALL (caught/injections): flagged ${pct(m.recall)}  [hard-BLOCK ${pct(m.block_recall)}]  n=${m.counts.injection}`);
  console.log(`  FALSE-BLOCK (BLOCKed/benign): ${pct(m.false_block)}  [describing ${pct(m.false_block_describing)} · neutral ${pct(m.false_block_neutral)}]  n=${m.counts.benign_describing + m.counts.benign_neutral}`);
  console.log(`  describing false-BLOCK is THE moat number (documentation ≠ execution)`);
  console.log(`  REVIEW on borderline: ${pct(m.review_on_borderline)}  [over-committed to BLOCK ${pct(m.block_on_borderline)}]  n=${m.counts.borderline}`);
}

async function main() {
  const KEY = process.env.AIML_API_KEY;
  if (!KEY) {
    // fail-honest: no model → no measurement. Exit NON-ZERO so a CI gate / caller
    // cannot mistake "unmeasured" for "measured & passing". Never fabricate a number.
    console.error(
      `L3 unavailable — AIML_API_KEY not set (source ~/.config/apohara/secrets.env). ` +
        `L3 recall / false-BLOCK NOT measured; nothing written.`,
    );
    process.exit(1);
  }

  const samples = loadCorpus();
  if (samples.length === 0) {
    console.error("FAIL: no samples loaded from", CORPUS);
    process.exit(1);
  }
  const perCell = SAMPLE === 0 ? "all" : SAMPLE;
  console.log(`\n== L3 AlignmentCheck recall/false-BLOCK · ${samples.length} samples (${perCell}/cell) · ${ALIGNMENT_MODEL_ID} ==`);
  if (SAMPLE === 0) {
    console.log(`  WARNING: full corpus = ${samples.length} live frontier-model calls (billed). Ctrl-C to abort.`);
  }

  // Each call is the REAL alignmentCheck → real deepseek-v4-pro. alignmentCheck is
  // already fail-SAFE internally (returns degraded:true REVIEW, never throws), but we
  // still guard the pool so one rejection cannot abort the whole run.
  const verdicts = await mapPool(samples, CONCURRENCY, (s) =>
    alignmentCheck(s.content, {}).catch((e) => ({
      decision: "REVIEW",
      rationale: `harness-caught error: ${String(e?.message ?? e)}`,
      confidence: 0,
      model_id: ALIGNMENT_MODEL_ID,
      version: ALIGNMENT_CHECK_VERSION,
      degraded: true,
    })),
  );
  process.stderr.write("\n");

  const m = score(samples, verdicts);
  console.log("");
  printMetrics(m);

  mkdirSync(OUT, { recursive: true });
  const stamp = new Date().toISOString();
  const payload = {
    measured_at: stamp,
    layer: "L3-alignment-check",
    model_id: ALIGNMENT_MODEL_ID,
    alignment_check_version: ALIGNMENT_CHECK_VERSION,
    corpus: "test/fixtures/guard-recall-corpus",
    samples: samples.length,
    sample_per_cell: perCell,
    concurrency: CONCURRENCY,
    metrics: m,
    caveats: [
      "Constructed corpus (adapted from published techniques), not in-the-wild pages.",
      "Frontier model — NOT run-to-run deterministic despite temperature=0; small samples are indicative, not statistically robust.",
      "Default --sample is SMALL to bound cost; --sample=0 runs the full (expensive) corpus.",
      "A degraded verdict (model unreachable on that call) fails SAFE to REVIEW and is NEVER counted as a BLOCK or a catch.",
      "false_block_describing is the moat number: BLOCK on a DOCUMENTING page = L3 confusing documentation with execution.",
      "reproduce: set -a; . ~/.config/apohara/secrets.env; set +a; node scripts/measure-l3-recall.mjs",
    ],
  };
  writeFileSync(join(OUT, "l3-results.json"), JSON.stringify(payload, null, 2) + "\n");
  console.log(`\nwrote out/guard-recall/l3-results.json  (${stamp})\n`);
}

main();
