#!/usr/bin/env node
// gap-8 — Measure L3 AlignmentCheck FALSE-BLOCK on the REAL benign security corpus.
//
// After the D5 FP fix, L3 is the ONLY layer (with a qualified L2) that holds BLOCK
// authority. Parity with the L2 FP gate (item 1.2) demands its benign false-BLOCK be
// MEASURED, not assumed. The corpus in test/fixtures/guard-fp-corpus/ is
// describing-NOT-executing by construction (OWASP cheat sheets, a CVE page,
// PortSwigger, security blogs) — pages that DOCUMENT prompt-injection but do not
// attack the reader. Every L3 "BLOCK" here is therefore a false-BLOCK: L3 mistaking
// documentation for an active injection. A good L3 should BLOCK ~0/5.
//
// Usage: node scripts/measure-l3-falseblock.mjs   (needs AIML_API_KEY; else prints "L3 unavailable")
//   set -a; source ~/.config/apohara/secrets.env; set +a
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { alignmentCheck, ALIGNMENT_MODEL_ID } from "../src/classify/alignment-check.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS = join(HERE, "..", "test", "fixtures", "guard-fp-corpus");

const files = readdirSync(CORPUS).filter((f) => f.endsWith(".txt")).sort();
if (files.length === 0) {
  console.error("no corpus fixtures in", CORPUS);
  process.exit(1);
}

const n = files.length;
const KEY = process.env.AIML_API_KEY;
if (!KEY) {
  // fail-honest: no measurement without the model. "unavailable" is NOT a failure —
  // the gate accepts it; L3 stays fail-safe REVIEW-keep until measured.
  console.log(
    `L3 unavailable — AIML_API_KEY not set (source ~/.config/apohara/secrets.env). ` +
      `L3 false-BLOCK NOT measured; L3 stays fail-safe REVIEW-keep.`,
  );
  process.exit(0);
}

console.log(`== L3 AlignmentCheck FALSE-BLOCK · ${n} benign pages · ${ALIGNMENT_MODEL_ID} ==\n`);
let falseBlocks = 0;
let degraded = 0;
const flagged = [];
for (const f of files) {
  const raw = readFileSync(join(CORPUS, f), "utf8")
    .replace(/^URL:.*$/m, "")
    .replace(/^Author:.*$/m, "");
  const v = await alignmentCheck(raw, {});
  if (v.degraded) degraded++;
  const page = f.replace(/\.txt$/, "");
  console.log(`• ${page}: ${v.decision}${v.degraded ? " (degraded)" : ""}  conf=${v.confidence}`);
  if (v.decision === "BLOCK") {
    falseBlocks++;
    flagged.push(page);
  }
}

console.log(`\nL3 false-BLOCK: ${falseBlocks}/${n}  (${((falseBlocks / n) * 100).toFixed(0)}%)`);
if (flagged.length) console.log(`  false-blocked (benign docs L3 wrongly BLOCKED): ${flagged.join(", ")}`);
if (degraded) {
  console.log(`  warn: ${degraded}/${n} degraded (model unreachable on those) → NOT counted as BLOCK`);
}
console.log(
  `\nNote: n=${n} is indicative, NOT statistically robust. Every page is ` +
    `describing-not-executing by construction → any BLOCK is a false positive (§6.3 distinction).`,
);
