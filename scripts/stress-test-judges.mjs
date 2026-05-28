#!/usr/bin/env node
// T2.1+T2.2 — Stress test SHOW-OFF para el deck del hackathon.
// Corre `runPipeline` sobre N URLs reales mixed-sectorial usando el router
// multi-surface ya existente (src/fetch/router.js). Aplica un BUDGET CAP duro
// (estimación por surface, recalculada en vivo), persiste telemetría
// append-only y emite un report.json agregado.
//
// Uso:
//   node scripts/stress-test-judges.mjs --urls=50 --budget=5 --surfaces=unlocker
//   node scripts/stress-test-judges.mjs --urls=500 --budget=50 --surfaces=unlocker,serp
//
// Flags:
//   --urls=N           cantidad max a procesar (default 50)
//   --budget=USD       cap presupuesto Bright Data (default 5)
//   --surfaces=list    coma-separado: unlocker,browser,crawl,serp (default unlocker,serp)
//   --concurrency=N    requests en paralelo (default 4)
//   --out=DIR          directorio de output (default out/stress-YYYY-MM-DD)
//   --urls-file=PATH   archivo .txt con 1 URL por línea (override STRESS_URLS)
//
// Telemetría:
//   .omc/state/v060-telemetry.jsonl  (append-only por run)
//   out/stress-YYYY-MM-DD/evidence-NNN.json  (1 por URL)
//   out/stress-YYYY-MM-DD/report.json        (agregado: counts, latencies, cost)

import { runPipeline } from "../src/pipeline.js";
import { smartFetcher } from "../src/fetch/router.js";
import { STRESS_URLS } from "./stress-urls.js";
import { readFileSync, writeFileSync, mkdirSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { hostname } from "node:os";

const args = process.argv.slice(2);
function flag(name, dflt) {
  const i = args.indexOf(name);
  if (i >= 0) return args[i + 1];
  for (const a of args) {
    if (a.startsWith(name + "=")) return a.slice(name.length + 1);
  }
  return dflt;
}
const URLS = Number(flag("--urls", 50));
const BUDGET_USD = Number(flag("--budget", 5));
const SURFACES = String(flag("--surfaces", "unlocker,serp")).split(",").map((s) => s.trim()).filter(Boolean);
const CONCURRENCY = Number(flag("--concurrency", 4));
const URLS_FILE = flag("--urls-file", null);
const today = new Date().toISOString().slice(0, 10);
const OUT_DIR = flag("--out", `out/stress-${today}`);
const TELEMETRY = ".omc/state/v060-telemetry.jsonl";

// Estimación de cost-per-request por surface (USD). Reales según Bright Data
// pricing 2026; el header billing real llega con ~30s de lag → este estimate
// es lo único defensivo que tenemos en tiempo real.
const COST_ESTIMATE = {
  unlocker: 0.0015,
  serp: 0.001,
  browser: 0.05,   // estimate alto: por GB de tráfico; conservador.
  crawl: 0.005,
};

function pickSurface(url) {
  // Si el caller pidió varias surfaces, rotamos: priorizamos unlocker para HTML,
  // serp si no es URL (búsqueda), browser para SPAs/JS-heavy (manual gate).
  if (!url.startsWith("http")) return "serp";
  return SURFACES.includes("unlocker") ? "unlocker" : SURFACES[0];
}

async function processUrl(url, ctx) {
  const surface = pickSurface(url);
  const t0 = process.hrtime.bigint();
  let result = null;
  let err = null;
  let evidenceFile = null;
  try {
    const fetcher = smartFetcher({ mode: surface === "unlocker" ? null : surface });
    result = await runPipeline(url, {
      lens: "security",
      fetcher,
      requestTsa: false, // stress no necesita TSA real — saturaría DigiCert
    });
    evidenceFile = `evidence-${String(ctx.processed).padStart(4, "0")}.json`;
    writeFileSync(join(OUT_DIR, evidenceFile), JSON.stringify(result, null, 2));
  } catch (e) {
    err = e.message ?? String(e);
  }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const costEstimate = COST_ESTIMATE[surface] ?? 0.002;
  ctx.spentEstimate += costEstimate;

  const telemetry = {
    ts: new Date().toISOString(),
    url,
    surface,
    latency_ms: +ms.toFixed(0),
    cost_estimate_usd: +costEstimate.toFixed(4),
    spent_so_far_usd: +ctx.spentEstimate.toFixed(4),
    success: !err,
    error: err,
    evidence_file: evidenceFile,
    content_hash: result?.contentHash ?? null,
    tsa_serial: result?.seal?.rfc3161Tsa?.serial ?? null,
    blocked_count: result?.payload?.blocked?.length ?? 0,
    findings_count: result?.payload?.findings?.length ?? 0,
    delta_added: result?.payload?.delta_chain?.diff_summary?.added ?? null,
  };
  appendFileSync(TELEMETRY, JSON.stringify(telemetry) + "\n");

  return telemetry;
}

async function runBatch(urls, concurrency) {
  const ctx = { processed: 0, spentEstimate: 0, results: [] };
  const queue = urls.slice();
  const workers = Array.from({ length: concurrency }, async () => {
    while (queue.length > 0) {
      if (ctx.spentEstimate >= BUDGET_USD) {
        console.warn(`[stress] BUDGET CAP $${BUDGET_USD} reached, stopping workers.`);
        break;
      }
      const url = queue.shift();
      if (!url) break;
      ctx.processed++;
      process.stdout.write(`  ${String(ctx.processed).padStart(3, "0")}/${urls.length} ${url.slice(0, 60).padEnd(60)} ... `);
      const t = await processUrl(url, ctx);
      process.stdout.write(`${t.success ? "✓" : "✗"} ${t.latency_ms}ms $${ctx.spentEstimate.toFixed(3)}\n`);
      ctx.results.push(t);
    }
  });
  await Promise.all(workers);
  return ctx.results;
}

async function main() {
  mkdirSync(OUT_DIR, { recursive: true });
  mkdirSync(".omc/state", { recursive: true });

  let urlList = STRESS_URLS;
  if (URLS_FILE) {
    urlList = readFileSync(URLS_FILE, "utf8").split("\n").map((s) => s.trim()).filter((s) => s && !s.startsWith("#"));
  }
  // Repeat allowlist hasta alcanzar URLS (para show-off > 60).
  while (urlList.length < URLS) urlList = urlList.concat(urlList);
  urlList = urlList.slice(0, URLS);

  console.log(`[stress] target=${URLS} URLs · budget=$${BUDGET_USD} · surfaces=${SURFACES.join(",")} · concurrency=${CONCURRENCY}`);
  console.log(`[stress] out=${OUT_DIR}, telemetry=${TELEMETRY}`);

  const tStart = Date.now();
  const results = await runBatch(urlList, CONCURRENCY);
  const totalMs = Date.now() - tStart;

  const ok = results.filter((r) => r.success);
  const fail = results.filter((r) => !r.success);
  const latencies = ok.map((r) => r.latency_ms).sort((a, b) => a - b);
  const p50 = latencies[Math.floor(latencies.length * 0.5)] ?? null;
  const p95 = latencies[Math.floor(latencies.length * 0.95)] ?? null;
  const totalSpent = results.length ? results[results.length - 1].spent_so_far_usd : 0;

  const report = {
    bench: "stress-test-judges",
    target_urls: URLS,
    processed: results.length,
    succeeded: ok.length,
    failed: fail.length,
    success_rate: results.length ? +(ok.length / results.length).toFixed(3) : 0,
    p50_latency_ms: p50,
    p95_latency_ms: p95,
    total_wall_clock_ms: totalMs,
    cost_estimate_usd: +totalSpent.toFixed(4),
    cost_per_url_usd: ok.length ? +(totalSpent / ok.length).toFixed(5) : null,
    budget_usd: BUDGET_USD,
    budget_used_pct: +((totalSpent / BUDGET_USD) * 100).toFixed(1),
    surfaces_used: SURFACES,
    concurrency: CONCURRENCY,
    host: hostname(),
    captured_at_iso: new Date().toISOString(),
    note: "cost is estimated per-surface, NOT the BD billing API actual. Verify in BD dashboard.",
  };

  writeFileSync(join(OUT_DIR, "report.json"), JSON.stringify(report, null, 2));
  console.log(`\n[stress] processed=${results.length} ok=${ok.length} fail=${fail.length}`);
  console.log(`[stress] p50=${p50}ms p95=${p95}ms total=${(totalMs / 1000).toFixed(1)}s`);
  console.log(`[stress] cost_estimate=$${totalSpent.toFixed(4)} (${report.budget_used_pct}% of budget) per_url=$${report.cost_per_url_usd}`);
  console.log(`[stress] report.json written → ${join(OUT_DIR, "report.json")}`);
}

main().catch((err) => {
  console.error("[stress] fatal:", err);
  process.exit(1);
});
