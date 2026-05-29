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

// ── Audit-2026-05-29 expansion: end-to-end loop coverage per finding #2 ──
// (visibility test of reactor.js + watch.js + sinks.js as one system)

test("react: deriveTarget hook mapea filas objeto a target arbitrario", async () => {
  const store = tmpStore();
  try {
    const tw = { poll: async () => ({
      added: [{ domain: "acme.com", note: "pricing" }, { domain: "globex.com", note: "careers" }],
      deleted: [],
    }) };
    const runner = async (t) => ev("h_" + t, 4);
    const { results } = await react("OBJECTS", {
      tw, store, runner,
      deriveTarget: (row) => row.domain,
      sinks: [],
    });
    assert.equal(results[0].target, "acme.com");
    assert.equal(results[1].target, "globex.com");
  } finally { rmSync(store.path, { force: true }); }
});

test("react: cada fila nueva invoca los sinks (act side del loop)", async () => {
  const store = tmpStore();
  try {
    const seen = [];
    const sink = async (ctx) => seen.push({ target: ctx.target, maxSeverity: ctx.maxSeverity });
    const tw = { poll: async () => ({ added: [["a.com"], ["b.com"], ["c.com"]], deleted: [] }) };
    const runner = async (t) => ev("h_" + t, 8, ["s-" + t]);
    await react("FANOUT", { tw, store, runner, sinks: [sink] });
    assert.equal(seen.length, 3, "sink fired once per added row");
    assert.deepEqual(seen.map((s) => s.target).sort(), ["a.com", "b.com", "c.com"]);
  } finally { rmSync(store.path, { force: true }); }
});

test("react: segunda corrida sobre la misma fila sin cambios => sin alerta nueva (delta detection)", async () => {
  const store = tmpStore();
  try {
    const tw = { poll: async () => ({ added: [["acme.com"]], deleted: [] }) };
    const runner = async () => ev("h1", 5, ["price-cut"]);
    const first = await react("DELTAS", { tw, store, runner, sinks: [] });
    assert.equal(first.alerts.length, 1, "first run on unseen target => alert");
    const second = await react("DELTAS", { tw, store, runner, sinks: [] });
    assert.equal(second.alerts.length, 0, "same row + same signals + no escalation => no alert");
  } finally { rmSync(store.path, { force: true }); }
});

test("react: escalada de severidad entre polls => alert.escalated true", async () => {
  const store = tmpStore();
  try {
    const tw = { poll: async () => ({ added: [["vendor.io"]], deleted: [] }) };
    await react("ESC", { tw, store, runner: async () => ev("h1", 3), sinks: [] });
    const r = await react("ESC", { tw, store, runner: async () => ev("h2", 9), sinks: [] });
    assert.equal(r.alerts.length, 1);
    assert.equal(r.alerts[0].escalated, true);
    assert.equal(r.alerts[0].maxSeverity, 9);
  } finally { rmSync(store.path, { force: true }); }
});

test("react: sink roto NO bloquea el loop (best-effort vía watch.js)", async () => {
  const store = tmpStore();
  try {
    const boom = async () => { throw new Error("sink down"); };
    const tw = { poll: async () => ({ added: [["a.com"], ["b.com"]], deleted: [] }) };
    const r = await react("RESILIENT", {
      tw, store,
      runner: async (t) => ev("h_" + t, 6),
      sinks: [boom],
    });
    assert.equal(r.results.length, 2, "loop completed despite sink throwing");
    assert.ok(r.alerts.length >= 1, "alerts still fired for the row(s) that warranted them");
  } finally { rmSync(store.path, { force: true }); }
});
