#!/usr/bin/env node
// T0.7 — Baseline empírico del RTT de DigiCert TSA antes de prometer SC-3b.
// Hace N=20 requests reales RFC 3161 con hashes sha256 random distintos,
// mide wall clock (POST + parse de respuesta), persiste estadística a
// logs/digicert-rtt-baseline.json para citar honestamente en SLIDES.
//
// Uso:  node scripts/bench-tsa-rtt.mjs [--samples 20] [--out logs/digicert-rtt-baseline.json]
// Gate: si p95 > SC_3B_THRESHOLD_MS, salir con código 1 para que ralph escale.

import { requestTimestamp } from "../src/prove/tsa.js";
import { webcrypto } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { hostname } from "node:os";

const args = process.argv.slice(2);
function flag(name, dflt) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : dflt;
}
const SAMPLES = Number(flag("--samples", 20));
const OUT_PATH = flag("--out", "logs/digicert-rtt-baseline.json");
const SC_3B_THRESHOLD_MS = 1500;

function percentile(sortedAsc, p) {
  if (sortedAsc.length === 0) return null;
  const idx = Math.min(sortedAsc.length - 1, Math.ceil((p / 100) * sortedAsc.length) - 1);
  return sortedAsc[Math.max(0, idx)];
}

async function main() {
  console.log(`[bench-tsa-rtt] sampling N=${SAMPLES} against timestamp.digicert.com`);
  const samplesMs = [];
  const errors = [];

  for (let i = 0; i < SAMPLES; i++) {
    // Hash distinto por sample para que la TSA no pueda cachear/cortocircuitar.
    const hash = webcrypto.getRandomValues(new Uint8Array(32));
    const t0 = process.hrtime.bigint();
    try {
      await requestTimestamp(hash, { timeoutMs: 10000 });
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      samplesMs.push(ms);
      process.stdout.write(`  ${String(i + 1).padStart(2, "0")}/${SAMPLES}: ${ms.toFixed(0)}ms\n`);
    } catch (err) {
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      errors.push({ i, ms, message: err.message });
      process.stdout.write(`  ${String(i + 1).padStart(2, "0")}/${SAMPLES}: ERROR after ${ms.toFixed(0)}ms (${err.message})\n`);
    }
  }

  const sorted = [...samplesMs].sort((a, b) => a - b);
  const p50 = percentile(sorted, 50);
  const p95 = percentile(sorted, 95);
  const p99 = percentile(sorted, 99);
  const max = sorted.length ? sorted[sorted.length - 1] : null;
  const min = sorted.length ? sorted[0] : null;
  const mean = sorted.length ? sorted.reduce((a, b) => a + b, 0) / sorted.length : null;

  const report = {
    bench: "digicert-rtt-baseline",
    target: "http://timestamp.digicert.com",
    samples_requested: SAMPLES,
    samples_succeeded: samplesMs.length,
    samples_failed: errors.length,
    sc_3b_threshold_ms: SC_3B_THRESHOLD_MS,
    p50_ms: p50,
    p95_ms: p95,
    p99_ms: p99,
    min_ms: min,
    max_ms: max,
    mean_ms: mean,
    samples_ms: samplesMs.map((m) => Number(m.toFixed(2))),
    errors,
    network: hostname(),
    captured_at_iso: new Date().toISOString(),
    notes: "Single-host single-network baseline. Cite in SLIDES with 'measured on <host> on <date>', not as universal p95.",
  };

  mkdirSync(dirname(OUT_PATH), { recursive: true });
  writeFileSync(OUT_PATH, JSON.stringify(report, null, 2));

  console.log(`\n[bench-tsa-rtt] p50=${p50?.toFixed(0)}ms p95=${p95?.toFixed(0)}ms p99=${p99?.toFixed(0)}ms max=${max?.toFixed(0)}ms`);
  console.log(`[bench-tsa-rtt] written ${OUT_PATH}`);

  if (p95 !== null && p95 > SC_3B_THRESHOLD_MS) {
    console.error(`[bench-tsa-rtt] ✗ p95 ${p95.toFixed(0)}ms EXCEEDS SC-3b threshold ${SC_3B_THRESHOLD_MS}ms. Escalate to evaluate TSA fallback (Sectigo, GlobalSign).`);
    process.exit(1);
  }
  if (errors.length > samplesMs.length / 2) {
    console.error(`[bench-tsa-rtt] ✗ too many errors (${errors.length}/${SAMPLES}). DigiCert TSA may be degraded.`);
    process.exit(1);
  }
  console.log(`[bench-tsa-rtt] ✓ within SC-3b budget`);
  process.exit(0);
}

main().catch((err) => {
  console.error(`[bench-tsa-rtt] fatal:`, err);
  process.exit(2);
});
