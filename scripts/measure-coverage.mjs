#!/usr/bin/env node
// measure-coverage — SC-11 honest metrics sobre las dos capas pre-LLM de Synthex.
//
// Mide qué porcentaje del corpus dispara ≥1 regla de cada capa Y qué porcentaje de
// las reglas de cada capa disparó al menos una vez sobre el corpus.
//
// Corpus por default: los 156 fixtures de Aegis (78 positivos + 78 negativos). NO es
// un corpus de tráfico real Bright Data — es lo más cercano disponible sin scraping
// con secrets. El README cita ambos números con la etiqueta "synthetic Aegis fixture
// corpus" para honestidad (Principle #1).
//
// Uso:
//   node scripts/measure-coverage.mjs                    # corpus default (156 fixtures)
//   node scripts/measure-coverage.mjs path/to/docs.json  # corpus custom: array de strings
import { readFileSync } from "node:fs";
import { evaluate as djlEvaluate, RULES as DJL_RULES } from "../src/forge/djl.js";
import { classify as prefilterClassify, RULES as PREFILTER_RULES } from "../src/forge/prefilter.js";
import { RULE_FIXTURES } from "../test/djl-fixtures.js";

function buildDefaultCorpus() {
  const docs = [];
  for (const { positive, negative } of Object.values(RULE_FIXTURES)) {
    docs.push(positive);
    docs.push(negative);
  }
  return { docs, label: `Aegis fixture corpus (156 docs = 78 positive + 78 negative)` };
}

function loadCorpus(path) {
  const raw = readFileSync(path, "utf8");
  const arr = JSON.parse(raw);
  if (!Array.isArray(arr)) throw new Error("corpus debe ser un JSON array de strings");
  return { docs: arr.map(String), label: `custom corpus from ${path} (${arr.length} docs)` };
}

const arg = process.argv[2];
const { docs, label } = arg ? loadCorpus(arg) : buildDefaultCorpus();

let djlDocsMatched = 0;
const djlRulesFired = new Set();
let prefilterDocsMatched = 0;
const prefilterRulesFired = new Set();

for (const text of docs) {
  const djl = djlEvaluate(text);
  if (djl.matched_rules.length > 0) djlDocsMatched++;
  for (const id of djl.matched_rules) djlRulesFired.add(id);

  const pre = prefilterClassify(text);
  if (pre.matched.length > 0) prefilterDocsMatched++;
  for (const m of pre.matched) prefilterRulesFired.add(m.id);
}

const pct = (n, d) => (d === 0 ? 0 : +(100 * n / d).toFixed(1));

const out = {
  corpus: label,
  total_docs: docs.length,
  djl: {
    docs_with_any_match_pct: pct(djlDocsMatched, docs.length),
    rules_fired_at_least_once_pct: pct(djlRulesFired.size, DJL_RULES.length),
    docs_matched: djlDocsMatched,
    rules_fired: djlRulesFired.size,
    rules_total: DJL_RULES.length,
  },
  prefilter: {
    docs_with_any_match_pct: pct(prefilterDocsMatched, docs.length),
    rules_fired_at_least_once_pct: pct(prefilterRulesFired.size, PREFILTER_RULES.length),
    docs_matched: prefilterDocsMatched,
    rules_fired: prefilterRulesFired.size,
    rules_total: PREFILTER_RULES.length,
  },
  honesty: "Aegis fixture corpus is synthetic (designed positive/negative pairs). Real Bright Data web-scraping coverage will differ — typically lower for prompt-level rules (which target user prompts, not HTML), higher for web-injection rules. Re-run on real corpus with `node scripts/measure-coverage.mjs <path-to-docs.json>`.",
};

console.log(JSON.stringify(out, null, 2));
