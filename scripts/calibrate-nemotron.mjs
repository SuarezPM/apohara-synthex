#!/usr/bin/env node
// T0.6 — Calibración severity-delta entre tier=free (nvidia/nemotron-3-nano-omni)
// y tier=oss (deepseek/deepseek-non-thinking-v3.2-exp) sobre 20 fixtures
// representativas (4 lentes × 5 fixtures cada una).
//
// Gate: si abs(severity_oss - severity_free) > 1.5 en > 30% de fixtures
//       → marca free tier como "free-low-quality" para que el playground UI
//         lo etiquete honestamente.
//
// Uso:  node scripts/calibrate-nemotron.mjs [--out out/nemotron-vs-deepseek-calibration.json]
// Requiere: AIML_API_KEY en env.

import { classify } from "../src/classify/aiml-client.js";
import { MODEL_TIERS } from "../src/classify/tiers.js";
import { CALIBRATION_FIXTURES } from "../test/fixtures/calibration-fixtures.js";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const args = process.argv.slice(2);
function flag(name, dflt) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : dflt;
}
const OUT_PATH = flag("--out", "out/nemotron-vs-deepseek-calibration.json");
const DELTA_THRESHOLD = 1.5;
const FAIL_RATE_THRESHOLD = 0.30;

if (!process.env.AIML_API_KEY) {
  console.error("[calibrate] missing AIML_API_KEY in env. Set it from ~/.config/apohara/secrets.env first.");
  process.exit(2);
}

async function classifyTier(text, lens, tierModel) {
  const t0 = process.hrtime.bigint();
  try {
    const res = await classify(text, lens, { model: tierModel, timeoutMs: 45000 });
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    return { ok: true, severity: res.severity, summary: res.summary, signals_count: res.signals.length, latency_ms: ms };
  } catch (err) {
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    return { ok: false, error: err.message, latency_ms: ms };
  }
}

async function main() {
  console.log(`[calibrate] running ${CALIBRATION_FIXTURES.length} fixtures × 2 tiers`);
  console.log(`[calibrate] tier=oss  → ${MODEL_TIERS.oss}`);
  console.log(`[calibrate] tier=free → ${MODEL_TIERS.free}`);

  const results = [];
  for (let i = 0; i < CALIBRATION_FIXTURES.length; i++) {
    const fx = CALIBRATION_FIXTURES[i];
    process.stdout.write(`  ${String(i + 1).padStart(2, "0")}/20 ${fx.id.padEnd(36)} `);

    // Secuencial intencional: no satura el FREE tier rate limit del AIML.
    const oss = await classifyTier(fx.text, fx.lens, MODEL_TIERS.oss);
    const free = await classifyTier(fx.text, fx.lens, MODEL_TIERS.free);

    const delta = (oss.ok && free.ok) ? Math.abs(oss.severity - free.severity) : null;
    const exceeds = delta !== null && delta > DELTA_THRESHOLD;
    process.stdout.write(`oss=${oss.ok ? oss.severity : "✗"} free=${free.ok ? free.severity : "✗"} Δ=${delta?.toFixed(1) ?? "n/a"}${exceeds ? " ⚠" : ""}\n`);

    results.push({
      id: fx.id,
      lens: fx.lens,
      expected_severity_band: fx.expected_severity_band,
      text_preview: fx.text.slice(0, 100) + (fx.text.length > 100 ? "..." : ""),
      oss,
      free,
      severity_delta: delta,
      exceeds_threshold: exceeds,
    });
  }

  const completed = results.filter((r) => r.severity_delta !== null);
  const exceeded = completed.filter((r) => r.exceeds_threshold);
  const failRate = completed.length > 0 ? exceeded.length / completed.length : 1;
  const gate = failRate > FAIL_RATE_THRESHOLD ? "FREE_LOW_QUALITY" : "FREE_ACCEPTABLE";

  const report = {
    bench: "nemotron-vs-deepseek-calibration",
    captured_at_iso: new Date().toISOString(),
    fixtures_total: CALIBRATION_FIXTURES.length,
    fixtures_completed: completed.length,
    fixtures_oss_errors: results.filter((r) => !r.oss.ok).length,
    fixtures_free_errors: results.filter((r) => !r.free.ok).length,
    delta_threshold: DELTA_THRESHOLD,
    fail_rate_threshold: FAIL_RATE_THRESHOLD,
    exceeded_count: exceeded.length,
    fail_rate: Number(failRate.toFixed(3)),
    gate,
    free_tier_label: gate === "FREE_LOW_QUALITY" ? "free-low-quality" : "free",
    models: {
      oss: MODEL_TIERS.oss,
      free: MODEL_TIERS.free,
    },
    results,
  };

  mkdirSync(dirname(OUT_PATH), { recursive: true });
  writeFileSync(OUT_PATH, JSON.stringify(report, null, 2));

  console.log(`\n[calibrate] completed=${completed.length}/${CALIBRATION_FIXTURES.length}`);
  console.log(`[calibrate] exceeded threshold (Δ>${DELTA_THRESHOLD}) on ${exceeded.length}/${completed.length} = ${(failRate * 100).toFixed(1)}%`);
  console.log(`[calibrate] GATE: ${gate} → label "${report.free_tier_label}"`);
  console.log(`[calibrate] written ${OUT_PATH}`);

  process.exit(0);
}

main().catch((err) => {
  console.error("[calibrate] fatal:", err);
  process.exit(2);
});
