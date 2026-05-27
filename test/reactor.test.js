// Tests del loop react→act (Triggerware poll → pipeline → act). tw y runner inyectados.
import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmSync } from "node:fs";
import { MemoryStore } from "../src/memory/index.js";
import { react } from "../src/reactor.js";

const tmpStore = () => new MemoryStore({ path: join(tmpdir(), `synthex-react-${Date.now()}-${Math.random().toString(36).slice(2)}.json`) });
const ev = (hash, sev) => ({ contentHash: hash, sealedAt: new Date().toISOString(), payload: { findings: [{ severity: sev, signals: ["s"] }] } });

test("react: poll con deltas dispara el pipeline por cada fila nueva y actúa", async () => {
  const store = tmpStore();
  try {
    const tw = { poll: async () => ({ added: [["acme.com"], ["globex.com"]], deleted: [] }) };
    const runner = async (t) => ev("h_" + t, 8); // severity 8 > threshold 7 => alerta
    const { addedCount, results, alerts } = await react("comp_watch", {
      tw, store, runner, lens: "security", deriveTarget: (row) => row[0],
    });
    assert.equal(addedCount, 2);
    assert.equal(results.length, 2);
    assert.equal(results[0].target, "acme.com");
    assert.equal(alerts.length, 2); // ambas alertan (first-run con señales + severity alta)
  } finally { rmSync(store.path, { force: true }); }
});

test("react: sin deltas => sin acciones", async () => {
  const tw = { poll: async () => ({ added: [], deleted: [] }) };
  const { addedCount, results, alerts } = await react("t", { tw });
  assert.equal(addedCount, 0);
  assert.equal(results.length, 0);
  assert.equal(alerts.length, 0);
});

test("react: deriveTarget por defecto toma row[0] de filas array", async () => {
  const store = tmpStore();
  try {
    const tw = { poll: async () => ({ added: [["https://vendor.com", "extra"]], deleted: [] }) };
    const runner = async (t) => ev("h", 3); // baja severidad
    const { results } = await react("t", { tw, store, runner });
    assert.equal(results[0].target, "https://vendor.com");
  } finally { rmSync(store.path, { force: true }); }
});
