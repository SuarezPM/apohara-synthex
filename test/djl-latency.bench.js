// DJL latency benchmark — `node test/djl-latency.bench.js` (npm run bench:djl).
// Standalone (NO node --test) para no llenar la suite con benchmarks no-deterministas.
//
// Mide tres percentiles separados:
//   1. Random inputs benignos (1000 × [a-zA-Z]{100,2000}) — p50/p95/p99
//   2. Adversarial: para cada regla con cuantificador no anclado sobre clase ancha,
//      input ~2000 chars cerca del match pero sin matchear — p99_adversarial
//
// Output: logs/djl-latency.json con shape:
//   { commit, runtime, count, p50_ms, p95_ms, p99_ms, p99_adversarial_ms, at }
//
// Bloquea (exit 1) si: p95 >= 5ms (random), p99 >= 10ms (random), p99 >= 50ms (adversarial).
// Honestidad: si el subset adversarial no encuentra worst-case, lo dice — no inventa.
import { evaluate, RULES } from "../src/forge/djl.js";
import { writeFileSync, mkdirSync } from "node:fs";
import { execSync } from "node:child_process";

function randomBenignInput(len) {
  let s = "";
  for (let i = 0; i < len; i++) s += String.fromCharCode(97 + Math.floor(Math.random() * 26));
  return s;
}

function percentile(arr, p) {
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * p));
  return sorted[idx];
}

function measure(fn, n) {
  const samples = [];
  // Warmup
  for (let i = 0; i < 20; i++) fn();
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    fn();
    samples.push(performance.now() - t0);
  }
  return samples;
}

// ---------- random benigno ----------
const N = 1000;
const inputs = [];
for (let i = 0; i < N; i++) inputs.push(randomBenignInput(100 + Math.floor(Math.random() * 1900)));
let idx = 0;
const randomSamples = measure(() => evaluate(inputs[idx++ % N]), N);
const p50 = +percentile(randomSamples, 0.50).toFixed(3);
const p95 = +percentile(randomSamples, 0.95).toFixed(3);
const p99 = +percentile(randomSamples, 0.99).toFixed(3);

// ---------- adversarial ----------
// Subset: reglas con cuantificador {N,M}/+/* no-anclado sobre clase ancha (\d, \w, .).
// Worst-case por regla: un input largo cerca del match pero sin matchear, que fuerza backtracking.
const adversarialInputs = [
  // DJL-PII-002 (\b(?:\d[ \-]?){12,18}\d\b) — secuencia larga de dígitos casi-match.
  "1 2 3 4 5 6 7 8 9 0 ".repeat(150) + "x",
  // DJL-PI-009 ([A-Za-z0-9+/]{80,}={0,2}) — base64 corto que no llega a 80.
  ("A1B2C3" + " ").repeat(300),
  // DJL-PI-013 (.{0,40} entre reveal y system prompt) — long-dot fence.
  "reveal " + "x".repeat(2000) + " system prompt",
  // DJL-EXF-001 ([^\n]{0,40} entre dump y database) — long-window fence sin newline.
  "dump " + "x".repeat(2000) + " database",
  // DJL-MIS-003 ([^\n]{0,40} entre transfer y currency).
  "transfer " + "x".repeat(2000) + " $1000",
  // DJL-HARM-015 ([\w\-]+\s+){0,4}? entre verbo y target — backtracking típico.
  "make a app to steal " + "x ".repeat(1000) + " passwords",
];
const advSamples = [];
for (const input of adversarialInputs) {
  // 30 muestras por adversarial input — captura outlier sin saturar.
  for (let i = 0; i < 30; i++) {
    const t0 = performance.now();
    evaluate(input);
    advSamples.push(performance.now() - t0);
  }
}
const p99Adv = +percentile(advSamples, 0.99).toFixed(3);

// ---------- output ----------
let commit = "unknown";
try {
  commit = execSync("git rev-parse HEAD", { encoding: "utf8" }).trim();
} catch { /* not a git repo */ }

const out = {
  commit,
  runtime: process.version,
  rules_loaded: RULES.length,
  count_random: randomSamples.length,
  count_adversarial: advSamples.length,
  p50_ms: p50,
  p95_ms: p95,
  p99_ms: p99,
  p99_adversarial_ms: p99Adv,
  at: new Date().toISOString(),
};

mkdirSync("logs", { recursive: true });
writeFileSync("logs/djl-latency.json", JSON.stringify(out, null, 2) + "\n");
console.log(JSON.stringify(out, null, 2));

// ---------- thresholds ----------
const fails = [];
if (p95 >= 5) fails.push(`p95 ${p95}ms >= 5ms (random)`);
if (p99 >= 10) fails.push(`p99 ${p99}ms >= 10ms (random)`);
if (p99Adv >= 50) fails.push(`p99 adversarial ${p99Adv}ms >= 50ms`);
if (fails.length > 0) {
  console.error("\nDJL latency THRESHOLDS VIOLATED:");
  for (const f of fails) console.error(`  - ${f}`);
  process.exit(1);
}
console.log("\nDJL latency OK: all thresholds met.");
