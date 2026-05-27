// Tests de TRIGGER. Monitor (cron) se testea con pipeline mock. TriggerWare = stub honesto.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Monitor, TriggerWareClient } from "../src/trigger/index.js";

test("monitor: dispara alerta cuando severity >= threshold", async () => {
  const pipeline = async () => ({ contentHash: "h1", payload: { findings: [{ severity: 9 }, { severity: 2 }] } });
  const alerts = [];
  const m = new Monitor({ pipeline, threshold: 7, onAlert: (a) => alerts.push(a) });
  m.watch("acme.com");
  const out = await m.runOnce();
  assert.equal(out.length, 1);
  assert.equal(out[0].severity, 9);
  assert.equal(out[0].target, "acme.com");
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

test("triggerware: stub honesto — no fabrica endpoints, falla claro sin config confirmada", async () => {
  const c = new TriggerWareClient({ apiKey: "k" }); // sin baseUrl confirmado
  assert.equal(c.configured, false);
  await assert.rejects(() => c.registerWorkflow(), /no configurado|pendiente de confirmar/);
});
