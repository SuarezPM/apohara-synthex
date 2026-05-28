#!/usr/bin/env node
// T0.4 — Warmup del Cognee MCP local antes de un demo o de un stress test.
// El primer connect carga uv + MiniMax + lancedb + kuzu (12-25s en CachyOS Pablo).
// Este script ejecuta el ciclo connect → recall("warmup") → close, mide tiempo,
// y emite exit 0 si pasa, exit 1 si excede el timeout (default 30s).
//
// Uso:  node scripts/warmup-cognee.mjs [--timeout-ms 30000]
//
// Mitigación PM-1 del PRD v0.6.0: la demo D3 debe tener el cognee caliente.
// También sirve para detectar regresiones de cold-start tras cambios en ~/.cognee/.

import { CogneeClient } from "../src/memory/cognee-client.js";

const args = process.argv.slice(2);
const timeoutFlag = args.indexOf("--timeout-ms");
const TIMEOUT_MS = timeoutFlag >= 0 ? Number(args[timeoutFlag + 1]) : 30000;

async function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timeout after ${ms}ms`)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

async function main() {
  const cli = new CogneeClient();
  const t0 = process.hrtime.bigint();
  console.log(`[warmup-cognee] connecting (timeout ${TIMEOUT_MS}ms)...`);

  try {
    await withTimeout(cli.connect(), TIMEOUT_MS, "connect");
    const connectMs = Number(process.hrtime.bigint() - t0) / 1e6;
    console.log(`[warmup-cognee] connect ok in ${connectMs.toFixed(0)}ms`);

    const t1 = process.hrtime.bigint();
    await withTimeout(cli.recall("warmup ping"), TIMEOUT_MS, "recall");
    const recallMs = Number(process.hrtime.bigint() - t1) / 1e6;
    console.log(`[warmup-cognee] recall ok in ${recallMs.toFixed(0)}ms`);

    await cli.close();
    const totalMs = Number(process.hrtime.bigint() - t0) / 1e6;
    console.log(`[warmup-cognee] ✓ ready (total ${totalMs.toFixed(0)}ms)`);
    process.exit(0);
  } catch (err) {
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    console.error(`[warmup-cognee] ✗ failed after ${ms.toFixed(0)}ms: ${err.message}`);
    try { await cli.close(); } catch {}
    process.exit(1);
  }
}

main();
