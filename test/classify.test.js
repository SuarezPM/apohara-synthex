// Tests de CLASSIFY. La lógica de parseo se testea sin red; el test de red se skipea sin key.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseClassification,
  parseBatchedClassification,
  classify,
  classifyBatched,
  classifyTriLens,
  LENSES,
} from "../src/classify/aiml-client.js";

// Opt-in: el test de red real requiere AIML_LIVE=1 Y saldo en AI/ML API (evita falsos fallos por fondos).
const live = !!process.env.AIML_LIVE;

test("parse: JSON válido → estructura normalizada", () => {
  const r = parseClassification('{"lens":"security","severity":8,"summary":"CVE crítico","signals":["CVE-2026-x"]}', "security");
  assert.equal(r.lens, "security");
  assert.equal(r.severity, 8);
  assert.equal(r.summary, "CVE crítico");
  assert.deepEqual(r.signals, ["CVE-2026-x"]);
});

test("parse: severity fuera de rango se clampa a 0-10", () => {
  assert.equal(parseClassification('{"severity":99}', "gtm").severity, 10);
  assert.equal(parseClassification('{"severity":-5}', "gtm").severity, 0);
});

test("parse: JSON inválido → fallback seguro (no tira)", () => {
  const r = parseClassification("esto no es json", "finance");
  assert.equal(r.lens, "finance");
  assert.equal(r.severity, 0);
  assert.deepEqual(r.signals, []);
});

test("classify: lanza error claro sin AIML_API_KEY", async () => {
  await assert.rejects(() => classify("x", "security", { apiKey: null }), /AIML_API_KEY/);
});

test("LENSES expone las 4 lentes", () => {
  assert.deepEqual(Object.keys(LENSES).sort(), ["finance", "gtm", "security", "supply-chain"]);
});

test("classify: red real AI/ML API clasifica (requiere AIML_LIVE=1 + saldo)", { skip: !live }, async () => {
  const r = await classify("Competidor X bajó precios 15% y abrió 3 vacantes de ventas enterprise.", "gtm");
  assert.equal(r.lens, "gtm");
  assert.ok(r.severity >= 0 && r.severity <= 10);
  assert.ok(typeof r.summary === "string");
});

// ── BATCHED 4-lens (item 1.4) ────────────────────────────────────────────────

test("parseBatchedClassification: shape de 4 sub-objetos → mapa validado por lente", () => {
  const lenses = ["gtm", "finance", "security", "supply-chain"];
  const raw = JSON.stringify({
    gtm: { lens: "gtm", severity: 4, summary: "pricing move", signals: ["price cut"] },
    finance: { lens: "finance", severity: 99, summary: "earnings", signals: ["beat", 7] },
    security: { lens: "security", summary: "leak", signals: ["cred"] }, // severity faltante
    "supply-chain": { lens: "supply-chain", severity: 2, summary: "delay", signals: [] },
  });
  const out = parseBatchedClassification(raw, lenses);
  assert.deepEqual(Object.keys(out), lenses);
  assert.equal(out.gtm.severity, 4);
  assert.equal(out.finance.severity, 10, "severity fuera de rango se clampa");
  assert.deepEqual(out.finance.signals, ["beat"], "señales no-string descartadas");
  assert.equal(out.security.severity, 0, "severity faltante → 0 (neutro)");
  assert.equal(out["supply-chain"].summary, "delay");
});

test("parseBatchedClassification: lente faltante en la respuesta → shape neutro", () => {
  const out = parseBatchedClassification(JSON.stringify({ gtm: { severity: 5, summary: "x", signals: [] } }), ["gtm", "finance"]);
  assert.equal(out.gtm.severity, 5);
  assert.equal(out.finance.severity, 0);
  assert.equal(out.finance.lens, "finance");
  assert.deepEqual(out.finance.signals, []);
});

test("parseBatchedClassification: JSON inválido no rompe (todas las lentes neutras)", () => {
  const out = parseBatchedClassification("no soy json", ["security"]);
  assert.equal(out.security.severity, 0);
  assert.equal(out.security.lens, "security");
});

test("parseBatchedClassification: refusal por lente neutralizado (no leak del refusal)", () => {
  const raw = JSON.stringify({ security: { severity: 0, summary: "I cannot help with that", signals: [] } });
  const out = parseBatchedClassification(raw, ["security"]);
  assert.equal(out.security.summary, "model declined to classify");
});

test("parseClassification per-lens NO se rompe con el shape batched presente (regresión)", () => {
  // el shape per-lens sigue siendo {severity,summary,signals} — sin cambios.
  const out = parseClassification(JSON.stringify({ severity: 7, summary: "ok", signals: ["a"] }), "gtm");
  assert.equal(out.severity, 7);
  assert.deepEqual(out.signals, ["a"]);
});

test("classifyBatched: UNA sola llamada para las 4 lentes (paga input 1×)", async () => {
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls++;
    const body = JSON.stringify({
      gtm: { lens: "gtm", severity: 1, summary: "g", signals: [] },
      finance: { lens: "finance", severity: 2, summary: "f", signals: [] },
      security: { lens: "security", severity: 3, summary: "s", signals: [] },
      "supply-chain": { lens: "supply-chain", severity: 4, summary: "sc", signals: [] },
    });
    return {
      ok: true,
      status: 200,
      json: async () => ({ choices: [{ message: { content: body } }], usage: { total_tokens: 42 } }),
      text: async () => body,
    };
  };
  try {
    let usageCalls = 0;
    const out = await classifyBatched("some scraped text", undefined, {
      apiKey: "test-key",
      onUsage: () => { usageCalls++; },
    });
    assert.equal(calls, 1, "exactamente 1 fetch para las 4 lentes");
    assert.equal(usageCalls, 1, "1 registro de usage (input pagado una vez)");
    assert.deepEqual(Object.keys(out), ["gtm", "finance", "security", "supply-chain"]);
    assert.equal(out.security.severity, 3);
    assert.equal(out.gtm.charsSeen, "some scraped text".length, "emit-metadata charsSeen presente");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("classifyBatched: sin apiKey lanza", async () => {
  await assert.rejects(() => classifyBatched("x", undefined, { apiKey: null }), /AIML_API_KEY/);
});
