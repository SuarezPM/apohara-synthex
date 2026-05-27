// Tests del watch loop always-on (con runner y store inyectados — sin red).
import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmSync } from "node:fs";
import { MemoryStore } from "../src/memory/index.js";
import { watchTarget } from "../src/watch.js";

function tmpStore() {
  return new MemoryStore({ path: join(tmpdir(), `synthex-watch-${Date.now()}-${Math.random().toString(36).slice(2)}.json`) });
}
const ev = (hash, sev, signals) => ({ contentHash: hash, sealedAt: new Date().toISOString(), payload: { findings: [{ severity: sev, signals }] } });

test("watch: primera corrida con señales => alerta (isFirstRun)", async () => {
  const store = tmpStore();
  try {
    const runner = async () => ev("h1", 7, ["price-cut"]);
    const { alert, isFirstRun } = await watchTarget("acme", { lens: "gtm", store, runner });
    assert.equal(isFirstRun, true);
    assert.ok(alert);
    assert.deepEqual(alert.newSignals, ["price-cut"]);
  } finally { rmSync(store.path, { force: true }); }
});

test("watch: segunda corrida sin cambios => sin alerta", async () => {
  const store = tmpStore();
  try {
    const runner = async () => ev("h1", 7, ["price-cut"]);
    await watchTarget("acme", { lens: "gtm", store, runner });
    const { alert } = await watchTarget("acme", { lens: "gtm", store, runner });
    assert.equal(alert, null);
  } finally { rmSync(store.path, { force: true }); }
});

test("watch: señal nueva en 2da corrida => alerta con newSignals", async () => {
  const store = tmpStore();
  try {
    await watchTarget("acme", { lens: "gtm", store, runner: async () => ev("h1", 5, ["price-cut"]) });
    const { alert } = await watchTarget("acme", { lens: "gtm", store, runner: async () => ev("h2", 5, ["price-cut", "layoffs"]) });
    assert.ok(alert);
    assert.deepEqual(alert.newSignals, ["layoffs"]);
  } finally { rmSync(store.path, { force: true }); }
});

test("watch: escalada de severidad => alerta escalated", async () => {
  const store = tmpStore();
  try {
    await watchTarget("vendor", { lens: "security", store, runner: async () => ev("h1", 4, ["cve"]) });
    const { alert } = await watchTarget("vendor", { lens: "security", store, runner: async () => ev("h2", 9, ["cve"]) });
    assert.ok(alert);
    assert.equal(alert.escalated, true);
    assert.equal(alert.maxSeverity, 9);
  } finally { rmSync(store.path, { force: true }); }
});

test("watch: invoca los sinks con la inteligencia (Cognee/webhook)", async () => {
  const store = tmpStore();
  try {
    const seen = [];
    const sink = async (ctx) => seen.push(ctx);
    await watchTarget("acme", { lens: "gtm", store, runner: async () => ev("h1", 7, ["s1"]), sinks: [sink] });
    assert.equal(seen.length, 1);
    assert.equal(seen[0].target, "acme");
    assert.equal(seen[0].maxSeverity, 7);
    assert.ok(seen[0].evidence);
  } finally { rmSync(store.path, { force: true }); }
});

test("watch: soporta evidence tri-lens (lens='all') — extrae señales y maxSeverity", async () => {
  const store = tmpStore();
  try {
    // evidence con findings tri-lens (shape de lens='all')
    const triEv = {
      contentHash: "ht1", sealedAt: new Date().toISOString(),
      payload: { findings: [{ trilens: {
        gtm: { severity: 7, signals: ["price-cut"] },
        finance: { severity: 4, signals: ["vendor-risk"] },
        security: { severity: 9, signals: ["breach"] },
      } }] },
    };
    const { alert, maxSeverity } = await watchTarget("acme", { lens: "all", store, runner: async () => triEv });
    assert.equal(maxSeverity, 9); // toma el máximo entre las 3 lentes
    assert.ok(alert);
    assert.deepEqual(alert.newSignals.sort(), ["breach", "price-cut", "vendor-risk"]);
  } finally { rmSync(store.path, { force: true }); }
});

test("watch: sinks:[] explícito desactiva los defaults (no arranca Cognee aunque haya COGNEE_LIVE)", async () => {
  const store = tmpStore();
  const prev = process.env.COGNEE_LIVE;
  process.env.COGNEE_LIVE = "1"; // si watch ignorara el [] explícito, intentaría conectar el MCP real
  try {
    const r = await watchTarget("acme", { lens: "gtm", store, runner: async () => ev("h1", 7, ["s1"]), sinks: [] });
    assert.ok(r.evidence); // no intentó conectar Cognee: el [] explícito ganó
  } finally {
    if (prev === undefined) delete process.env.COGNEE_LIVE; else process.env.COGNEE_LIVE = prev;
    rmSync(store.path, { force: true });
  }
});

test("watch: un sink que falla no rompe el watch (best-effort)", async () => {
  const store = tmpStore();
  try {
    const boom = async () => { throw new Error("sink down"); };
    const r = await watchTarget("acme", { lens: "gtm", store, runner: async () => ev("h1", 7, ["s1"]), sinks: [boom] });
    assert.ok(r.evidence); // no tiró pese al sink roto
  } finally { rmSync(store.path, { force: true }); }
});
