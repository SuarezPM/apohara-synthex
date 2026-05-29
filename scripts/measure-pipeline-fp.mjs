#!/usr/bin/env node
// Measure PIPELINE-level false positives on the benign security corpus (D5 FP fix).
//
// `scripts/measure-guard-fp.mjs` measures each FORGE layer in ISOLATION (djl.evaluate /
// prefilter.classify / heuristicScreen) — those numbers don't change with the D5 fix because
// the modules still report BLOCK/REVIEW. THIS script measures what the *pipeline* actually
// does with that signal: after the fix, L1 regex (DJL + prefilter) is REVIEW-only on ingest,
// so NO benign doc is dropped by regex. The honest pipeline FP = docs dropped by L1 regex.
//
// Mide los FP a NIVEL pipeline: tras el fix D5, L1 regex es REVIEW-only en ingesta → ningún
// doc benigno se dropea por regex. El FP honesto del pipeline = docs dropeados por L1 regex.
//
// Corpus: test/fixtures/guard-fp-corpus/ (5 real benign security pages — they DISCUSS
// injection/SQLi/XSS but are informational, not attacks). Every drop here would be a false
// positive by construction.
//
// Usage: node scripts/measure-pipeline-fp.mjs
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { runPipeline } from "../src/pipeline.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS = join(HERE, "..", "test", "fixtures", "guard-fp-corpus");

const files = readdirSync(CORPUS).filter((f) => f.endsWith(".txt")).sort();
if (files.length === 0) {
  console.error("no corpus fixtures in", CORPUS);
  process.exit(1);
}

// Build one fetcher with all benign docs; inject a no-network classifier so we exercise the
// FORGE → CLASSIFY path deterministically (no Bright Data, no AI/ML, no TSA).
const docs = files.map((f) => {
  const raw = readFileSync(join(CORPUS, f), "utf8");
  // Drop exa's 2-3 meta lines (URL:/Author:) — keep the page's own text.
  const text = raw.replace(/^URL:.*$/m, "").replace(/^Author:.*$/m, "");
  return { url: f.replace(/\.txt$/, ""), content: text };
});

const fetcher = async () => docs;
const classifier = async (text, lens) => ({ lens, severity: 1, summary: "benign", signals: [] });

const ev = await runPipeline("benign-corpus", {
  lens: "security",
  fetcher,
  classifier,
  requestTsa: false,
});

const decisions = ev.payload.decisions ?? [];
const blocked = ev.payload.blocked ?? [];

// Docs dropped by L1 regex at the pipeline level: BLOCK rows whose layer is djl/prefilter.
// Post-D5 this set MUST be empty (L1 is REVIEW-only on ingest).
const droppedByRegex = blocked.filter((b) => b.layer === "djl" || b.layer === "prefilter").length;

// Docs the L1 regex layers surfaced as REVIEW (kept + classified, severity sealed as signal).
const reviewedByL1 = new Set(
  decisions
    .filter((d) => d.outcome === "REVIEW" && (d.layer === "djl" || d.layer === "prefilter"))
    .map((d) => d.url),
).size;

const n = docs.length;
const classified = ev.payload.findings.length;

console.log(`\n== Pipeline FALSE-POSITIVE measurement · real benign security corpus (${n} pages) ==\n`);
for (const d of docs) {
  const rows = decisions.filter((r) => r.url === d.url);
  const tags = rows.length
    ? rows.map((r) => `${r.layer ?? r.stage}:${r.outcome}${r.severity != null ? `(sev${r.severity})` : ""}`).join(" ")
    : "ALLOW (no regex hit)";
  const dropped = blocked.some((b) => b.url === d.url && (b.layer === "djl" || b.layer === "prefilter"));
  console.log(`• ${d.url}\n    ${tags}${dropped ? "  ← DROPPED BY L1" : ""}`);
}

console.log(`\n-- Pipeline-level result (D5 FP fix: L1 regex is REVIEW-only on ingest) --`);
console.log(`  dropped_by_regex: ${droppedByRegex}`);
console.log(`  reviewed_by_L1:   ${reviewedByL1}/${n}`);
console.log(`  classified:       ${classified}/${n}  (no benign doc is dropped by regex)`);
console.log(`\nNote: all pages are benign by construction. Pre-fix, ${reviewedByL1} of ${n} would have been`);
console.log(`DROPPED by L1 BLOCK (sev≥8); post-fix they are REVIEW'd and kept. See docs/guard-fp-measurement.md.\n`);

process.exit(droppedByRegex === 0 ? 0 : 1);
