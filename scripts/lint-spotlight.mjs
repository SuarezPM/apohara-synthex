#!/usr/bin/env node
// CI lint — Spotlighting envelope gate (item 1.6).
//
// Fails (exit 1) if any source file that sends scraped/untrusted content to an LLM
// does so WITHOUT the per-request nonce envelope (`src/classify/spotlight.js`). The
// static v0.9 delimiter was guessable; the nonce closes that. This lint keeps every
// untrusted→LLM call-site on the shared helper as the codebase grows (classify, L3,
// the Qwen3Guard moderation prompt, and any future redteam/council call-site).
//
// Heuristic (deterministic, fast — runs on every commit gate):
//   A file is an LLM EGRESS site iff it has all of:  fetch(  +  a /completions URL
//   +  a request body field (`messages:` or `prompt:`).  (A bare mention of
//   "/chat/completions" in a comment is NOT egress — tiers.js must not trip.)
//   Such a file PASSES iff it references the spotlight envelope: imports the helper,
//   calls `spotlight(`, or inlines the `<<<UNTRUSTED:` nonce sentinel.
//
// Usage: node scripts/lint-spotlight.mjs   (exit 0 = clean, exit 1 = offender found)
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// Egress requires a real fetch to a completions endpoint with a request body —
// not a comment mentioning the URL. Matches both `fetch(` and an injected
// `fetchImpl(` (the testable-transport pattern in injection-guard.js).
const HAS_FETCH = /\bfetch(?:Impl)?\s*\(/;
const HAS_COMPLETIONS_URL = /\/(?:chat\/)?completions/;
const HAS_LLM_BODY = /\b(?:messages|prompt)\s*:/;

// Envelope present iff the file uses the shared helper or inlines the nonce sentinel.
const ENVELOPE = [
  /from\s+["'][^"']*spotlight(?:\.js)?["']/, // imports the shared helper
  /\bspotlight\s*\(/, // calls it
  /<<<UNTRUSTED:/, // or inlines the nonce sentinel literal
];

/**
 * Audit one file's source. Pure — exported for the negative test.
 * @param {string} content
 * @returns {{llm:boolean, ok:boolean}}
 */
export function auditSource(content) {
  const c = String(content ?? "");
  const isEgress = HAS_FETCH.test(c) && HAS_COMPLETIONS_URL.test(c) && HAS_LLM_BODY.test(c);
  if (!isEgress) return { llm: false, ok: true };
  return { llm: true, ok: ENVELOPE.some((re) => re.test(c)) };
}

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (name.endsWith(".js")) out.push(p);
  }
  return out;
}

// main — run over src/ when invoked directly.
if (import.meta.url === `file://${process.argv[1]}`) {
  const SRC = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
  const offenders = [];
  let llmFiles = 0;
  for (const f of walk(SRC)) {
    const a = auditSource(readFileSync(f, "utf8"));
    if (!a.llm) continue;
    llmFiles++;
    if (!a.ok) offenders.push(f);
  }
  if (offenders.length) {
    console.error(`spotlight-lint: FAIL — ${offenders.length} LLM call-site(s) WITHOUT a nonce envelope:`);
    for (const o of offenders) console.error(`  - ${o}`);
    console.error(`Fix: wrap untrusted content via spotlight() from src/classify/spotlight.js.`);
    process.exit(1);
  }
  console.log(`spotlight-lint: OK — ${llmFiles} LLM call-site(s), all wrap untrusted content in the nonce envelope.`);
  process.exit(0);
}
