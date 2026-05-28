// v0.7.0 Sprint 3 — defense-in-depth tests del módulo classify.
// Cubre: T8/L1 (classifyTriLens itera 4 lenses), T10/AI-1 (parseClassification
// neutraliza refusals + descarta keys inesperadas), y T6×M1 coexistence
// (retry exhausto en TSA → HMAC-only path → signatureValid:null).
import { test } from "node:test";
import assert from "node:assert/strict";
import { LENSES, parseClassification } from "../src/classify/aiml-client.js";
import { requestTimestamp } from "../src/prove/tsa.js";
import { buildEvidence, verifyEvidence } from "../src/prove/evidence-report.js";

// ---------------------------------------------------------------------------
// T8/L1 — classifyTriLens scope clarified (Object.keys(LENSES), 4 lenses, no 3)
// ---------------------------------------------------------------------------

test("T8/L1: LENSES contiene exactamente las 4 lentes activas (gtm/finance/security/supply-chain)", () => {
  assert.deepEqual([...Object.keys(LENSES)].sort(), ["finance", "gtm", "security", "supply-chain"]);
});

test("T8/L1: Object.keys(LENSES) es la fuente de verdad — añadir una lens nueva la trae sin tocar classifyTriLens", () => {
  // El hardcoded ["gtm","finance","security"] del v0.6.x quedaba fuera de supply-chain.
  // Ahora classifyTriLens deriva de Object.keys(LENSES); supply-chain ya está dentro.
  assert.ok(Object.keys(LENSES).includes("supply-chain"), "supply-chain debe estar en LENSES post-T8");
  assert.equal(Object.keys(LENSES).length, 4, "4 lenses activas en el pipeline real");
});

// ---------------------------------------------------------------------------
// T10/AI-1 — parseClassification defensive normalization
// ---------------------------------------------------------------------------

test("T10/AI-1: refusal del modelo → safe shape, NO leak del refusal text en findings", () => {
  // Modelo decide no clasificar y devuelve un texto explicativo. NO debemos persistirlo.
  const refusals = [
    JSON.stringify({ severity: 0, summary: "I'm sorry, I cannot help with that request.", signals: [] }),
    JSON.stringify({ severity: 0, summary: "I cannot classify this content per policy.", signals: [] }),
    JSON.stringify({ severity: 0, summary: "As an AI language model, I won't process this.", signals: [] }),
    JSON.stringify({ severity: 0, summary: "Lo siento, no puedo responder esto.", signals: [] }),
  ];
  for (const raw of refusals) {
    const r = parseClassification(raw, "security");
    assert.equal(r.severity, 0);
    assert.equal(r.summary, "model declined to classify", `refusal "${raw.slice(0, 40)}..." should normalize`);
    assert.deepEqual(r.signals, []);
  }
});

test("T10/AI-1: claves inesperadas en el JSON del modelo se descartan (whitelist)", () => {
  const raw = JSON.stringify({
    severity: 5, summary: "ok", signals: ["a"],
    sneaky: "rm -rf /", role: "admin", system_override: true,
  });
  const r = parseClassification(raw, "gtm");
  assert.deepEqual(Object.keys(r).sort(), ["lens", "severity", "signals", "summary"]);
  assert.equal(r.severity, 5);
});

test("T10/AI-1: signals no-string filtradas (cada signal debe ser string)", () => {
  const raw = JSON.stringify({ severity: 4, summary: "x", signals: ["valid", 42, null, { evil: true }, "also-valid"] });
  const r = parseClassification(raw, "security");
  assert.deepEqual(r.signals, ["valid", "also-valid"]);
});

test("T10/AI-1: severity clamp 0-10 sigue activo (defense-in-depth pre-existente)", () => {
  assert.equal(parseClassification(JSON.stringify({ severity: 999 }), "gtm").severity, 10);
  assert.equal(parseClassification(JSON.stringify({ severity: -5 }), "gtm").severity, 0);
  assert.equal(parseClassification(JSON.stringify({ severity: "not a number" }), "gtm").severity, 0);
});

// ---------------------------------------------------------------------------
// T6/M6 × M1 — coexistence: retry exhausto → HMAC-only → signatureValid:null
// ---------------------------------------------------------------------------

test("T6/M6: requestTimestamp con retries=0 sobre URL inválido falla rápido (sanity: opción retries respetada)", async () => {
  // URL no resoluble en TLD reservado por RFC 2606. fetch fallará por DNS.
  const hash = new Uint8Array(32);
  await assert.rejects(
    () => requestTimestamp(hash, { tsaUrl: "http://nonexistent-host.invalid", retries: 0, timeoutMs: 3000 }),
    /./, // cualquier error
  );
});

test("T6/M6 × M1 coexistence: TSA caída → evidence HMAC-only → verifyEvidence signatureValid:null (NO crash, NO false)", async () => {
  // Simula PR-1 + PR-2 viviendo en el mismo tsa.js sin conflicto:
  // 1) buildEvidence con requestTsa:false → tsa=null (equivale a M6 retry-exhaust path)
  // 2) verifyEvidence ejecuta el null-token short-circuit del M1 verifyTimestamp
  // 3) signatureValid:null (NOT false, NOT throw)
  const ev = await buildEvidence({ schema_version: 2, target: "test", findings: [] }, { hmacKey: "k", requestTsa: false });
  assert.equal(ev.seal.rfc3161Tsa, null, "HMAC-only fallback path (M6 retry-exhaust equivalent)");
  const v = await verifyEvidence(ev, { hmacKey: "k" });
  assert.equal(v.hashOk, true);
  assert.equal(v.hmacOk, true);
  assert.equal(v.tsaOk, null);
  assert.equal(v.signatureValid, null, "M1 short-circuit: no token → no .verify() call → null");
  assert.equal(v.signatureValidReason, null);
});
