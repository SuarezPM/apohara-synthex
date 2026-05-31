#!/usr/bin/env node
// ============================================================================
// THE EPIC STRESS TEST — harness SKELETON (V2_PLAN P4.1 · mega_prompt_v2
// <the_epic_stress_test>). NOT THE RUN.
//
// This file is the deterministic, one-command STRUCTURE for the capstone proof.
// The six dimensions below are wired into a real flow but each is an explicit
// STUB that returns { status: 'NOT_IMPLEMENTED', dimension } — by design, until
// the pipeline core is green (P0→P2 done). The capstone runs LAST.
//
// HONESTY (the moat): a stub NEVER emits a metric. It says NOT_IMPLEMENTED.
// No number printed by this skeleton is a measurement. When a dimension is
// implemented, replace its stub body with a real measurement that carries its
// own reproduce command — and never fabricate, round, simulate, or cherry-pick.
//
// Usage (skeleton):
//   node scripts/stress/run.mjs --manifest=scripts/stress/corpus.json --limit=100
//
// Flags:
//   --manifest=PATH   corpus manifest (validated against corpus-manifest.schema.json)
//   --limit=N         cap artifacts loaded from the manifest (smoke/dev; default: all)
//   --out=DIR         output dir for results.json (default: out/stress-YYYY-MM-DD)
//   --dimensions=list comma-separated subset to run (default: all six)
//   --live            opt-in flag to allow live external calls in implemented
//                     dimensions. DEFAULT OFF — the skeleton never hits a live
//                     service; live paths stay gated behind this flag.
//
// Full-run docs + the honest reproduce command live in scripts/stress/README.md.
// ============================================================================

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));

// ── arg parsing (matches scripts/measure-guard-recall.mjs convention) ────────
const arg = (k, d) => {
  const m = process.argv.find((a) => a.startsWith(`--${k}=`));
  return m ? m.split("=")[1] : d;
};
const has = (k) => process.argv.includes(`--${k}`);

const MANIFEST_PATH = arg("manifest", join(HERE, "corpus.json"));
const LIMIT = Number(arg("limit", "0")) || 0; // 0 = no cap (load all)
const today = new Date().toISOString().slice(0, 10);
const OUT_DIR = resolve(arg("out", join("out", `stress-${today}`)));
const SCHEMA_PATH = join(HERE, "corpus-manifest.schema.json");
const LIVE = has("live"); // OFF by default — the skeleton never calls a live service.

// The six dimensions, in V2_PLAN P4.1 order. The keys are the contract every
// stub returns under `dimension`; the harness assembles results.json from them.
const DIMENSIONS = [
  "scale_throughput", // (1) total sealed artifacts, throughput, peak concurrency
  "seal_integrity", // (2) % independently verify (Ed25519+TSA+Rekor+C2PA); K tampered → % detected
  "guard_efficacy", // (3) two-axis FP+recall, per-layer L1/L2/L3, layered-vs-single under format-manipulation
  "cost_efficiency", // (4) $/1000 traced to architectural cause (dedup/layered/batching/O(1) seal)
  "latency", // (5) p50/p95/p99 per stage (fetch/screen/classify/seal) + end-to-end
  "determinism", // (6) same input → same content hash → same seal modulo timestamp
];

const DIM_FILTER = String(arg("dimensions", ""))
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Sentinel every stub returns. The harness treats any dimension whose status is
// not exactly 'OK' as not-yet-real, and refuses to print it as a measurement.
const NOT_IMPLEMENTED = "NOT_IMPLEMENTED";
function stub(dimension, detail) {
  // INVARIANT: no metric fields here. Status only + the reproduce TODO.
  return {
    status: NOT_IMPLEMENTED,
    dimension,
    detail, // human note on what implementing this entails (NOT a measurement)
    reproduce: null, // TODO(verify): set the real reproduce command when implemented
  };
}

// ── corpus loader ────────────────────────────────────────────────────────────
// Reads the versioned manifest and returns a frozen artifact list. Validates the
// few invariants the schema also enforces (so a malformed manifest fails fast and
// loudly rather than silently producing a wrong-shaped run). Does NOT mutate input.
function loadCorpus(manifestPath, limit) {
  let raw;
  try {
    raw = readFileSync(manifestPath, "utf8");
  } catch (e) {
    throw new Error(
      `corpus manifest not found at ${manifestPath} — generate it first (see scripts/stress/README.md). Cause: ${e.message}`,
    );
  }
  let manifest;
  try {
    manifest = JSON.parse(raw);
  } catch (e) {
    throw new Error(`corpus manifest is not valid JSON: ${e.message}`);
  }
  if (!manifest || typeof manifest !== "object" || !Array.isArray(manifest.artifacts)) {
    throw new Error("corpus manifest missing required artifacts[] (see corpus-manifest.schema.json)");
  }
  // Surface the schema contract without pulling a JSON-schema validator (zero new
  // deps): the README documents `node scripts/stress/validate-manifest.mjs` as the
  // full check. Here we assert only what the loader itself relies on.
  if (manifest.manifest_version !== "1") {
    throw new Error(`unsupported manifest_version ${manifest.manifest_version} (loader handles "1")`);
  }
  const all = manifest.artifacts;
  const artifacts = limit > 0 ? all.slice(0, limit) : all;
  return {
    manifest: Object.freeze({
      manifest_version: manifest.manifest_version,
      corpus_id: manifest.corpus_id ?? null,
      created_at: manifest.created_at ?? null,
      totals: manifest.totals ?? null,
      schema: SCHEMA_PATH,
    }),
    artifacts: Object.freeze(artifacts.map((a) => Object.freeze({ ...a }))),
    loaded: artifacts.length,
    available: all.length,
    limited: limit > 0 && limit < all.length,
  };
}

// ============================================================================
// DIMENSION STUBS — each is a clearly-marked NOT_IMPLEMENTED stub wired into the
// real flow. They receive the loaded corpus + a context object. When made real,
// each MUST: measure not assert, report every failure, and return a `reproduce`
// command. Until then they return the NOT_IMPLEMENTED sentinel ONLY.
// ============================================================================

// (1) SCALE / THROUGHPUT — total sealed artifacts, throughput (URLs/min), peak
// concurrency. Real impl: run runPipeline (src/pipeline.js) over the corpus at
// concurrency, count successfully sealed artifacts, divide by wall-clock.
async function dimScaleThroughput(corpus, _ctx) {
  // TODO(verify): drive src/pipeline.js runPipeline at concurrency over corpus.artifacts;
  // emit { sealed, throughput_per_min, peak_concurrency } — all MEASURED.
  return stub("scale_throughput", `would seal ${corpus.loaded} artifacts at concurrency and measure throughput`);
}

// (2) SEAL INTEGRITY (the killer metric) — % of artifacts that independently
// verify across Ed25519 + RFC 3161 TSA + Rekor v2 + C2PA (target 100%); then
// inject K deliberately tampered artifacts and report % detected (target 100%,
// 0 false-accepts). Real impl uses the SHIPPED verifiers, do NOT reinvent:
//   src/prove/evidence-report.js verifyEvidence (hash+hmac+Ed25519+TSA)
//   src/prove/rekor.js verifyRekorBundle (offline RFC 6962 + C2SP)
//   src/prove/c2pa.js verifyC2paManifest
//   src/prove/tsa.js verifyTimestamp
async function dimSealIntegrity(corpus, _ctx) {
  // TODO(verify): for each sealed artifact, run all four verifiers; aggregate
  // independent-verify %. Then flip K bytes across K copies and assert detection.
  // NEVER count an unverifiable artifact as verified; report any gap honestly.
  return stub(
    "seal_integrity",
    `would independently verify Ed25519+TSA+Rekor+C2PA on ${corpus.loaded} artifacts via the shipped verifiers, then inject K tampered → measure % detected`,
  );
}

// (3) GUARD EFFICACY (honest two-axis) — measured FP% on benign + recall% on
// labeled injections + describing-vs-executing precision + PER-LAYER L1/L2/L3
// contribution + robustness delta layered-vs-single under format-manipulation
// (cite Bag-of-Tricks arXiv:2510.11570). Real impl reuses the existing two-axis
// harness logic (scripts/measure-guard-recall.mjs) over the corpus's labeled
// subset; live guard calls are gated behind --live (Featherless).
async function dimGuardEfficacy(corpus, ctx) {
  // TODO(verify): score L1 (heuristicScreen, local) always; L2/L3 only when ctx.live.
  // Report FP, recall, per-layer contribution, and the layered-vs-single delta.
  const adversarial = corpus.artifacts.filter((a) => a.label === "adversarial").length;
  const benign = corpus.artifacts.filter((a) => a.label === "benign").length;
  return stub(
    "guard_efficacy",
    `two-axis over ${benign} benign + ${adversarial} adversarial; per-layer L1/L2/L3 + layered-vs-single. Live guard calls require --live (currently ${ctx.live ? "ON" : "OFF"})`,
  );
}

// (4) COST EFFICIENCY BY DESIGN — total $ and $/1000 sealed; LLM calls + tokens
// saved by dedup; batching savings; O(1) seal. Each number TRACED to its
// architectural cause. Real impl reads telemetry token/call counts; BD cost is
// ESTIMATED per-surface (the billing API lags ~30s — see stress-test-judges.mjs),
// so the report MUST label cost as estimated, not BD-billing-actual.
async function dimCostEfficiency(corpus, _ctx) {
  // TODO(verify): aggregate measured LLM calls/tokens + per-surface cost estimate;
  // attribute savings to dedup / layered-on-REVIEW-band / batched-classify / O(1) seal.
  return stub(
    "cost_efficiency",
    `would compute $/1000 over ${corpus.loaded} artifacts (LLM cost measured; BD cost ESTIMATED per-surface, not billing-actual) traced to architectural cause`,
  );
}

// (5) LATENCY — p50/p95/p99 per stage (fetch/screen/classify/seal) + end-to-end.
// Real impl reads per-stage hrtime samples emitted during the run and computes
// percentiles (NOT averages) per stage.
async function dimLatency(corpus, _ctx) {
  // TODO(verify): collect per-stage latency samples during the run; compute
  // p50/p95/p99 per stage + e2e. Report sample n per stage alongside percentiles.
  return stub("latency", `would compute p50/p95/p99 per stage (fetch/screen/classify/seal) + e2e over ${corpus.loaded} artifacts`);
}

// (6) DETERMINISM — same input → same content hash → same seal (modulo the
// timestamp). Real impl runs each artifact twice and asserts contentHash equals
// and the seal pre-image (everything except TSA time/serial + Rekor index) is
// byte-identical. This is the one dimension that can run fully offline today,
// but it still depends on a green pipeline → kept as a stub until P2.
async function dimDeterminism(corpus, _ctx) {
  // TODO(verify): seal each artifact twice with a FIXED key; assert contentHash
  // equality and seal-pre-image equality modulo {tsa.time, tsa.serial, rekor.logIndex}.
  return stub(
    "determinism",
    `would re-seal ${corpus.loaded} artifacts and assert same content hash → same seal modulo timestamp`,
  );
}

const DIM_RUNNERS = {
  scale_throughput: dimScaleThroughput,
  seal_integrity: dimSealIntegrity,
  guard_efficacy: dimGuardEfficacy,
  cost_efficiency: dimCostEfficiency,
  latency: dimLatency,
  determinism: dimDeterminism,
};

// ── results.json assembler ───────────────────────────────────────────────────
// Stable shape so the eventual sealed Stress Test Report + landing can consume it
// the same way whether a dimension is a stub or real. The harness self-hashes the
// dimension results into manifest.results_sha256 so the output is content-addressed.
function assembleResults({ corpus, dimensions, startedAt, finishedAt }) {
  const allReal = Object.values(dimensions).every((d) => d.status === "OK");
  const body = {
    harness: "synthex-stress",
    harness_status: allReal ? "COMPLETE" : "SKELETON",
    skeleton_note:
      "harness skeleton — full run pending pipeline-green (V2_PLAN P4.1). Dimensions marked NOT_IMPLEMENTED are STUBS and carry NO measurements.",
    manifest: corpus.manifest,
    corpus: {
      loaded: corpus.loaded,
      available: corpus.available,
      limited: corpus.limited,
    },
    started_at: startedAt,
    finished_at: finishedAt,
    host: process.env.HOSTNAME ?? null,
    node: process.version,
    live_external_calls: LIVE,
    dimensions,
  };
  const results_sha256 = createHash("sha256")
    .update(JSON.stringify(body.dimensions))
    .digest("hex");
  return { ...body, results_sha256 };
}

// ── summary printer ──────────────────────────────────────────────────────────
function printSummary(results) {
  const line = "─".repeat(72);
  process.stdout.write(`\n${line}\n`);
  process.stdout.write(`  SYNTHEX STRESS TEST — ${results.harness_status}\n`);
  process.stdout.write(`  ${results.skeleton_note}\n`);
  process.stdout.write(`${line}\n`);
  process.stdout.write(
    `  corpus: loaded ${results.corpus.loaded} / available ${results.corpus.available}` +
      `${results.corpus.limited ? " (--limit applied)" : ""}\n`,
  );
  process.stdout.write(`  live external calls: ${results.live_external_calls ? "ON (--live)" : "OFF (skeleton default)"}\n`);
  process.stdout.write(`${line}\n`);
  for (const [name, d] of Object.entries(results.dimensions)) {
    const tag = d.status === "OK" ? "OK " : d.status;
    process.stdout.write(`  [${tag}] ${name}\n`);
    if (d.detail) process.stdout.write(`         ${d.detail}\n`);
  }
  process.stdout.write(`${line}\n`);
  process.stdout.write(`  results_sha256: ${results.results_sha256}\n`);
  process.stdout.write(`${line}\n\n`);
}

// ── main flow ────────────────────────────────────────────────────────────────
async function main() {
  const startedAt = new Date().toISOString();
  const corpus = loadCorpus(MANIFEST_PATH, LIMIT);

  const ctx = { live: LIVE, outDir: OUT_DIR };
  const selected = DIM_FILTER.length ? DIMENSIONS.filter((d) => DIM_FILTER.includes(d)) : DIMENSIONS;

  const dimensions = {};
  for (const name of selected) {
    const runner = DIM_RUNNERS[name];
    if (!runner) {
      // fail-safe: unknown dimension name is surfaced, not silently dropped.
      dimensions[name] = { status: "UNKNOWN_DIMENSION", dimension: name };
      continue;
    }
    try {
      dimensions[name] = await runner(corpus, ctx);
    } catch (e) {
      // A dimension throwing must NOT crash the harness or fake a metric.
      dimensions[name] = { status: "ERROR", dimension: name, error: e.message };
    }
  }

  const finishedAt = new Date().toISOString();
  const results = assembleResults({ corpus, dimensions, startedAt, finishedAt });

  mkdirSync(OUT_DIR, { recursive: true });
  const outPath = join(OUT_DIR, "results.json");
  writeFileSync(outPath, JSON.stringify(results, null, 2) + "\n");

  printSummary(results);
  process.stdout.write(`  results.json → ${outPath}\n\n`);
}

main().catch((err) => {
  process.stderr.write(`[stress] fatal: ${err.stack ?? err.message ?? err}\n`);
  process.exit(1);
});
