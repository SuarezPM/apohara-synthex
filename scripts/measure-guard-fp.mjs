#!/usr/bin/env node
// Measure guard FALSE POSITIVES on a REAL benign security corpus.
//
// "The guard's FP number doesn't exist until measured on real scraped content,
// not synthetic." (2026-05-29 audit). The corpus in test/fixtures/guard-fp-corpus/
// is exactly the adversarial benign case: security blogs, OWASP cheat sheets,
// PortSwigger, and a CVE page — pages that DISCUSS prompt-injection / SQLi / XSS
// but are informational, not attacks. Every REVIEW/BLOCK verdict here is a false
// positive by construction.
//
// Measures all three FORGE layers independently:
//   - prefilter.classify  (Layer-1 regex, 32 rules — runs in every pipeline)
//   - djl.evaluate        (Layer-1 regex, 78 rules — runs in every pipeline)
//   - injection-guard heuristicScreen (Layer-2 fallback; the Prompt-Guard model
//     would FP differently — this measures the zero-dep deterministic path)
//
// Usage: node scripts/measure-guard-fp.mjs
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { classify as prefilterClassify } from "../src/forge/prefilter.js";
import { evaluate as djlEvaluate } from "../src/forge/djl.js";
import { heuristicScreen } from "../src/forge/injection-guard.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS = join(HERE, "..", "test", "fixtures", "guard-fp-corpus");

const files = readdirSync(CORPUS).filter((f) => f.endsWith(".txt")).sort();
if (files.length === 0) {
  console.error("no corpus fixtures in", CORPUS);
  process.exit(1);
}

const isFP = (v) => v === "REVIEW" || v === "BLOCK" || v === "review" || v === "block";
const up = (s) => String(s ?? "").toUpperCase();

const tally = { prefilter: 0, djl: 0, guard: 0, union: 0 };
const rows = [];

for (const f of files) {
  const raw = readFileSync(join(CORPUS, f), "utf8");
  // Drop exa's 2-3 meta lines (URL:/Author:) — keep the page's own text.
  const text = raw.replace(/^URL:.*$/m, "").replace(/^Author:.*$/m, "");

  const pf = prefilterClassify(text);
  const dj = djlEvaluate(text);
  const gd = heuristicScreen(text);

  const pfV = up(pf.action), djV = up(dj.decision), gdV = up(gd.verdict);
  if (isFP(pfV)) tally.prefilter++;
  if (isFP(djV)) tally.djl++;
  if (isFP(gdV)) tally.guard++;
  if (isFP(pfV) || isFP(djV) || isFP(gdV)) tally.union++;

  rows.push({
    page: f.replace(/\.txt$/, ""),
    prefilter: pfV, prefilterCat: pf.category,
    djl: djV, djlRules: (dj.matched_rules || []).slice(0, 4).join(","),
    guard: gdV, guardLabel: gd.label,
  });
}

const n = files.length;
const pct = (k) => `${((tally[k] / n) * 100).toFixed(0)}%`;

console.log(`\n== Guard FALSE-POSITIVE measurement · real benign security corpus (${n} pages) ==\n`);
for (const r of rows) {
  console.log(`• ${r.page}`);
  console.log(`    prefilter: ${r.prefilter}${r.prefilterCat ? ` (${r.prefilterCat})` : ""}` +
    `   djl: ${r.djl}${r.djlRules ? ` [${r.djlRules}]` : ""}   guard(heuristic): ${r.guard}${r.guardLabel ? ` (${r.guardLabel})` : ""}`);
}
console.log(`\n-- False-positive rate (REVIEW or BLOCK on benign content) --`);
console.log(`  prefilter (32 regex) : ${tally.prefilter}/${n}  ${pct("prefilter")}`);
console.log(`  djl (78 regex)       : ${tally.djl}/${n}  ${pct("djl")}`);
console.log(`  injection-guard heur : ${tally.guard}/${n}  ${pct("guard")}`);
console.log(`  union (any layer)    : ${tally.union}/${n}  ${pct("union")}`);
console.log(`\nNote: all pages are benign by construction → every non-ALLOW is a false positive.`);
console.log(`The REVIEW verdict is the designed mitigation (surface, don't drop). See HONESTY §8.\n`);
