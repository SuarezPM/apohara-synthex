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
// Usage: node scripts/measure-guard-fp.mjs                       (L1 + heuristic, offline)
//        node scripts/measure-guard-fp.mjs --provider=featherless (+ L2 Qwen3Guard FP, item 1.2)
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { classify as prefilterClassify } from "../src/forge/prefilter.js";
import { evaluate as djlEvaluate } from "../src/forge/djl.js";
import {
  heuristicScreen,
  renderQwen3GuardPrompt,
  parseQwen3GuardCompletion,
  QWEN3GUARD_MODEL_ID,
} from "../src/forge/injection-guard.js";

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
    text, // kept for the optional Featherless L2 measurement below (item 1.2)
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

// ── Layer-2 MODEL FP · Qwen3Guard-Gen-8B via Featherless (item 1.2) ─────────
//
// The heuristic above is the zero-dep fallback. THIS measures the hosted L2
// model's benign FP — the number that decides whether L2 earns BLOCK authority
// (HONESTY §8.A: "BLOCK is REVIEW-capped until item 1.2 measures FP"). Reuses
// renderQwen3GuardPrompt + parseQwen3GuardCompletion from injection-guard.js
// (NO template duplication — same contract as scripts/probe-featherless.mjs).
//
// DECISION RULE (documented in docs/guard-fp-measurement.md): a guard is GRANTED
// BLOCK authority only if its benign FP ≤ FP_THRESHOLD (same 20% bar as the L1
// heuristic). Computed LIVE from the real model — never hardcoded (D9).
// fail-honest: if the provider doesn't answer, FAIL explicitly (exit ≠ 0); never
// assume a value. n=5 is indicative, NOT statistically robust.
if (process.argv.includes("--provider=featherless")) {
  const FP_THRESHOLD = 0.2; // ≤20% benign FP → BLOCK authority (matches L1 bar)
  const FEATHERLESS_URL = "https://api.featherless.ai/v1/completions";
  const KEY = process.env.FEATHERLESS_API_KEY;
  // Optional extra guards. They use different output formats → likely won't emit
  // the Qwen "Safety:" verdict; if none parse we report an honest FAIL, never a
  // fake 0. Llama-Guard-3-8B is GATED on Featherless → deliberately NOT probed.
  const OPTIONAL = process.argv.includes("--no-optional")
    ? []
    : ["google/shieldgemma-9b", "OpenSafetyLab/MD-Judge-v0.1"];

  const classify = async (model, text) => {
    const res = await fetch(FEATHERLESS_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${KEY}` },
      body: JSON.stringify({ model, prompt: renderQwen3GuardPrompt(text), max_tokens: 1024, temperature: 0 }),
      signal: AbortSignal.timeout(90000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${(await res.text()).slice(0, 120)}`);
    const json = await res.json();
    const raw = json?.choices?.[0]?.text ?? json?.choices?.[0]?.message?.content ?? "";
    return parseQwen3GuardCompletion(raw); // {safety, categories, score, verdict}
  };

  // Measure one model over the benign corpus. fail-honest result shape.
  const measure = async (model) => {
    const out = [];
    for (const r of rows) {
      try {
        const v = await classify(model, r.text);
        out.push({ page: r.page, safety: v.safety, verdict: v.verdict });
      } catch (err) {
        return { ok: false, reason: err.message };
      }
    }
    const unparsed = out.filter((o) => o.safety === null).length;
    // If NOTHING parsed, the model doesn't speak the Qwen3Guard format → we
    // cannot honestly measure FP. FAIL — do NOT count nulls as "safe".
    if (unparsed === out.length) return { ok: false, reason: "no Safety: verdict parsed (wrong format / chatted)" };
    const flagged = out.filter((o) => o.verdict === "review" || o.verdict === "block").map((o) => o.page);
    return { ok: true, fp: flagged.length, n: out.length, unparsed, flagged };
  };

  console.log(`== Layer-2 MODEL FP · Featherless · ${n} benign pages (item 1.2) ==\n`);
  if (!KEY) {
    console.error("qwen3guard-gen: FAIL — FEATHERLESS_API_KEY not set (source ~/.config/apohara/secrets.env)");
    process.exit(1);
  }

  // Primary: Qwen3Guard-Gen-8B — the model that decides BLOCK authority.
  const primary = await measure(QWEN3GUARD_MODEL_ID);
  if (!primary.ok) {
    // fail-honest: the story CANNOT close without a real measurement.
    console.error(`qwen3guard-gen: FAIL — ${primary.reason}`);
    console.error("qwen3guard-gen: NOT MEASURED — BLOCK stays REVIEW-capped (fail-safe)");
    process.exit(1);
  }
  const fpRate = primary.fp / primary.n;
  const qualifies = fpRate <= FP_THRESHOLD;
  console.log(
    `qwen3guard-gen: ${primary.fp}/${primary.n}  ${(fpRate * 100).toFixed(0)}% FP` +
      (primary.unparsed ? `  (warn: ${primary.unparsed}/${primary.n} unparsed → counted as non-flag)` : ""),
  );
  if (primary.flagged.length) console.log(`  flagged (false positives): ${primary.flagged.join(", ")}`);
  console.log(`  threshold: ≤ ${(FP_THRESHOLD * 100).toFixed(0)}%  →  BLOCK authority ${qualifies ? "QUALIFIES" : "DISQUALIFIED"}`);
  console.log(`  → recommended: SYNTHEX_GUARD_BLOCK_ENABLED=${qualifies ? "1" : "0 (leave unset)"} for Qwen3Guard-Gen-8B`);

  // Optional probes (non-fatal, honest FAIL if they don't classify).
  for (const model of OPTIONAL) {
    const short = model.split("/").pop();
    const r = await measure(model);
    if (!r.ok) {
      console.log(`${short}: FAIL — ${r.reason} → NOT MEASURED`);
    } else {
      const rate = r.fp / r.n;
      console.log(`${short}: ${r.fp}/${r.n}  ${(rate * 100).toFixed(0)}% FP  →  BLOCK ${rate <= FP_THRESHOLD ? "QUALIFIES" : "DISQUALIFIED"}`);
    }
  }
  console.log(`\nLlama-Guard-3-8B: NOT ATTEMPTED (gated on Featherless, by design).`);
  console.log(`Note: n=${n} is indicative, NOT statistically robust — a floor, not a precise rate.\n`);
}
