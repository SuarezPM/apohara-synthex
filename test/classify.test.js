// Tests de CLASSIFY. La lógica de parseo se testea sin red; el test de red se skipea sin key.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseClassification, classify, classifyTriLens, LENSES } from "../src/classify/aiml-client.js";

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
