// Tests de TRIGGER. Monitor (cron) con pipeline mock. TriggerWareClient: unit + red opt-in.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Monitor, TriggerWareClient } from "../src/trigger/index.js";

const twLive = !!process.env.TRIGGERWARE_LIVE; // opt-in para el test de red real

test("monitor: dispara alerta cuando severity >= threshold", async () => {
  const pipeline = async () => ({ contentHash: "h1", payload: { findings: [{ severity: 9 }, { severity: 2 }] } });
  const alerts = [];
  const m = new Monitor({ pipeline, threshold: 7, onAlert: (a) => alerts.push(a) });
  m.watch("acme.com");
  const out = await m.runOnce();
  assert.equal(out.length, 1);
  assert.equal(out[0].severity, 9);
  assert.equal(alerts.length, 1);
});

test("monitor: NO alerta por debajo del threshold", async () => {
  const pipeline = async () => ({ contentHash: "h2", payload: { findings: [{ severity: 3 }] } });
  const m = new Monitor({ pipeline, threshold: 7 });
  m.watch("x.com");
  assert.equal((await m.runOnce()).length, 0);
});

test("monitor: requiere un pipeline", () => {
  assert.throws(() => new Monitor({}), /pipeline/);
});

test("triggerware: error claro sin API key", async () => {
  const c = new TriggerWareClient({ apiKey: null });
  await assert.rejects(() => c.listTriggers(), /TRIGGERWARE_API_KEY/);
});

test("triggerware: expone los métodos de triggers y query", () => {
  const c = new TriggerWareClient({ apiKey: "k" });
  for (const fn of ["listTriggers", "createTrigger", "poll", "deleteTrigger", "query"]) {
    assert.equal(typeof c[fn], "function");
  }
});

test("triggerware: GET /triggers real devuelve una lista (requiere TRIGGERWARE_LIVE=1)", { skip: !twLive }, async () => {
  const c = new TriggerWareClient();
  const triggers = await c.listTriggers();
  assert.ok(Array.isArray(triggers), "GET /triggers debe devolver un array");
});
