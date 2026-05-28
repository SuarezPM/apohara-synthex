// Test T1.6 — HMAC_EXCLUDED_KEYS garantiza determinism cross-run.
// Dos runs sobre el MISMO URL con distinto kg_status / surface_status / kg_latency_ms
// deben producir el MISMO contentHash. Sin esto, el chain delta_chain reporta cambios
// fantasma cuando solo cambia la disponibilidad de Cognee, no el contenido real.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildEvidence, verifyEvidence, HMAC_EXCLUDED_KEYS } from "../../src/prove/evidence-report.js";

test("HMAC_EXCLUDED_KEYS contiene exactamente kg_status, kg_latency_ms, surface_status", () => {
  assert.deepEqual([...HMAC_EXCLUDED_KEYS].sort(), ["kg_latency_ms", "kg_status", "surface_status"]);
});

test("contentHash es idéntico cuando solo kg_status difiere", async () => {
  const base = {
    schema_version: 2,
    target: "https://example.com",
    lens: "gtm",
    findings: [{ severity: 6, summary: "x" }],
    delta_chain: {
      previous_tsa_serial: null,
      current_tsa_serial: null,
      diff_summary: { added: 1, removed: 0, changed: 0 },
    },
  };
  const a = await buildEvidence({ ...base, delta_chain: { ...base.delta_chain, kg_status: "ingested" } }, { hmacKey: "k", requestTsa: false });
  const b = await buildEvidence({ ...base, delta_chain: { ...base.delta_chain, kg_status: "unreachable" } }, { hmacKey: "k", requestTsa: false });
  assert.equal(a.contentHash, b.contentHash, "contentHash debe ser igual aunque kg_status difiera");
  assert.equal(a.seal.hmacSha256, b.seal.hmacSha256, "HMAC también debe ser igual");
});

test("contentHash es idéntico cuando kg_latency_ms cambia entre runs", async () => {
  const base = { schema_version: 2, target: "x", findings: [] };
  const a = await buildEvidence({ ...base, kg_latency_ms: 123 }, { hmacKey: "k", requestTsa: false });
  const b = await buildEvidence({ ...base, kg_latency_ms: 9999 }, { hmacKey: "k", requestTsa: false });
  assert.equal(a.contentHash, b.contentHash);
});

test("contentHash es idéntico cuando surface_status cambia", async () => {
  const base = { schema_version: 2, target: "x", findings: [] };
  const a = await buildEvidence({ ...base, surface_status: "ok" }, { hmacKey: "k", requestTsa: false });
  const b = await buildEvidence({ ...base, surface_status: "fallback" }, { hmacKey: "k", requestTsa: false });
  assert.equal(a.contentHash, b.contentHash);
});

test("contentHash CAMBIA cuando un campo non-excluded difiere (contraprueba)", async () => {
  const a = await buildEvidence({ schema_version: 2, target: "x", findings: [{ severity: 5 }] }, { hmacKey: "k", requestTsa: false });
  const b = await buildEvidence({ schema_version: 2, target: "x", findings: [{ severity: 6 }] }, { hmacKey: "k", requestTsa: false });
  assert.notEqual(a.contentHash, b.contentHash, "cambios reales SÍ deben mover el hash");
});

test("strip es recursivo: kg_status nested en delta_chain también se excluye", async () => {
  const a = await buildEvidence({
    schema_version: 2,
    target: "x",
    delta_chain: { kg_status: "ingested", diff_summary: { added: 0 } },
  }, { hmacKey: "k", requestTsa: false });
  const b = await buildEvidence({
    schema_version: 2,
    target: "x",
    delta_chain: { kg_status: "skipped", diff_summary: { added: 0 } },
  }, { hmacKey: "k", requestTsa: false });
  assert.equal(a.contentHash, b.contentHash, "strip debe llegar a delta_chain.kg_status nested");
});

test("verifier acepta evidence con kg_status modificado post-sellado (chain robusta)", async () => {
  // Simula que el operador inspecciona la evidence y kg_status cambió (porque
  // el sealer no lo persistió, o porque alguien lo escribió manualmente). El hash
  // y HMAC deben seguir validando porque la key está excluida.
  const ev = await buildEvidence({
    schema_version: 2,
    target: "x",
    delta_chain: { kg_status: "ingested" },
  }, { hmacKey: "k", requestTsa: false });
  // Mutar post-sellado.
  ev.payload.delta_chain.kg_status = "unreachable";
  const v = verifyEvidence(ev, { hmacKey: "k" });
  assert.equal(v.hashOk, true, "hash debe seguir OK tras cambiar kg_status");
  assert.equal(v.hmacOk, true, "HMAC debe seguir OK");
});

test("verifier sobre report v0.5.0 legacy (sin kg_status) sigue funcionando (back-compat 100%)", async () => {
  // Simula un report v0.5.0 sin nada de las keys excluidas. _stripExcludedKeys es noop.
  const ev = await buildEvidence({
    schema_version: 2,
    target: "x",
    findings: [{ severity: 7 }],
  }, { hmacKey: "k", requestTsa: false });
  const v = verifyEvidence(ev, { hmacKey: "k" });
  assert.equal(v.hashOk, true);
  assert.equal(v.hmacOk, true);
});
