// Tests del módulo PROVE. `node --test`.
// Cubren: HMAC sella+verifica, detección de tampering, TSA real contra DigiCert (red),
// y schema_v2 (canonicalize + auto-detect en verify + edge cases + back-compat v1).
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildEvidence, verifyEvidence } from "../src/prove/evidence-report.js";
import { sha256, hmacSign, hmacVerify } from "../src/prove/hmac.js";
import { canonicalize } from "../src/prove/canonicalize.js";

test("hmac: firma y verifica", () => {
  const sig = hmacSign("hello", "key");
  assert.equal(hmacVerify("hello", "key", sig), true);
  assert.equal(hmacVerify("hello", "wrong", sig), false);
  assert.equal(hmacVerify("tampered", "key", sig), false);
});

test("sha256: 32 bytes deterministas", () => {
  assert.deepEqual(sha256("x"), sha256("x"));
  assert.equal(sha256("x").length, 32);
});

test("evidence: HMAC sella y verifica (sin red)", async () => {
  const key = "synthex-test-key";
  const ev = await buildEvidence({ target: "example.com", findings: [1, 2, 3] }, { hmacKey: key, requestTsa: false });
  assert.equal(ev.contentHash.length, 64);
  assert.ok(ev.seal.hmacSha256);
  assert.equal(ev.seal.rfc3161Tsa, null);
  assert.equal(ev.seal.method, "HMAC-SHA256");
  const v = await verifyEvidence(ev, { hmacKey: key });
  assert.equal(v.hashOk, true);
  assert.equal(v.hmacOk, true);
  assert.equal(v.tsaOk, null); // no se pidió TSA
});

test("evidence: detecta tampering del payload", async () => {
  const key = "k";
  const ev = await buildEvidence({ a: 1 }, { hmacKey: key, requestTsa: false });
  ev.payload.a = 2; // tamper
  const v = await verifyEvidence(ev, { hmacKey: key });
  assert.equal(v.hashOk, false);
});

// ---------------------------------------------------------------------------
// CANONICALIZE — RFC 8785-like JCS minimalist (Commit C Synthex v4, T3 AC#N1)
// ---------------------------------------------------------------------------

test("canonicalize: orden de claves no afecta output (propiedad principal)", () => {
  const a = canonicalize({ b: 2, a: 1, c: 3 });
  const b = canonicalize({ c: 3, a: 1, b: 2 });
  const c = canonicalize({ a: 1, b: 2, c: 3 });
  assert.equal(a, b);
  assert.equal(b, c);
  assert.equal(a, '{"a":1,"b":2,"c":3}');
});

test("canonicalize: objetos anidados se ordenan recursivamente", () => {
  const a = canonicalize({ outer: { z: 1, a: 2 }, key: "val" });
  const b = canonicalize({ key: "val", outer: { a: 2, z: 1 } });
  assert.equal(a, b);
  assert.equal(a, '{"key":"val","outer":{"a":2,"z":1}}');
});

test("canonicalize edge: undefined → omite la clave (consistente JSON.stringify)", () => {
  assert.equal(canonicalize({ a: 1, b: undefined, c: 3 }), '{"a":1,"c":3}');
});

test("canonicalize edge: Date object → TypeError (serializar ISO antes)", () => {
  assert.throws(() => canonicalize({ at: new Date() }), TypeError);
});

test("canonicalize edge: BigInt → TypeError", () => {
  assert.throws(() => canonicalize({ n: 1n }), TypeError);
});

test("canonicalize edge: NaN/Infinity → RangeError", () => {
  assert.throws(() => canonicalize({ x: NaN }), RangeError);
  assert.throws(() => canonicalize({ x: Infinity }), RangeError);
  assert.throws(() => canonicalize({ x: -Infinity }), RangeError);
});

test("canonicalize edge: circular ref → TypeError", () => {
  const o = { a: 1 };
  o.self = o;
  assert.throws(() => canonicalize(o), TypeError);
});

test("canonicalize: arrays preservan orden (no se ordenan)", () => {
  assert.equal(canonicalize([3, 1, 2]), "[3,1,2]");
  assert.equal(canonicalize([{ b: 1, a: 2 }]), '[{"a":2,"b":1}]');
});

test("canonicalize: undefined dentro de array → null (igual que JSON.stringify)", () => {
  assert.equal(canonicalize([1, undefined, 3]), "[1,null,3]");
});

// ---------------------------------------------------------------------------
// T3.A — payload v2 cross-build HMAC consistency
// ---------------------------------------------------------------------------

test("T3.A: payload v2 con claves en orden distinto produce mismo HMAC", async () => {
  const key = "synthex-test-key";
  const a = await buildEvidence(
    { schema_version: 2, target: "x", findings: [], policy_bundle_version: { djl: "djl-v1-aaa", prefilter: "prefilter-v3-bbb" } },
    { hmacKey: key, requestTsa: false },
  );
  const b = await buildEvidence(
    { policy_bundle_version: { prefilter: "prefilter-v3-bbb", djl: "djl-v1-aaa" }, findings: [], target: "x", schema_version: 2 },
    { hmacKey: key, requestTsa: false },
  );
  assert.equal(a.contentHash, b.contentHash, "contentHash debe ser idéntico sin importar orden");
  assert.equal(a.seal.hmacSha256, b.seal.hmacSha256, "HMAC debe ser idéntico sin importar orden");
});

// ---------------------------------------------------------------------------
// T3.N3 — verifier auto-detecta schema_version (back-compat con v1 legacy)
// ---------------------------------------------------------------------------

test("T3.N3: verifier verifica Evidence Report v1 legacy (sin schema_version)", async () => {
  // Construye un Evidence v1 con JSON.stringify legacy (sin schema_version).
  const key = "k";
  const ev = await buildEvidence({ target: "legacy", findings: [{ a: 1 }] }, { hmacKey: key, requestTsa: false });
  // Sanity: el payload v1 no tiene schema_version
  assert.equal(ev.payload.schema_version, undefined);
  // El verifier detecta v1 → usa JSON.stringify legacy → verifica correctamente
  const v = await verifyEvidence(ev, { hmacKey: key });
  assert.equal(v.hashOk, true);
  assert.equal(v.hmacOk, true);
});

test("T3.N3: verifier verifica payload v2 (con schema_version >= 2)", async () => {
  const key = "k";
  const ev = await buildEvidence({ schema_version: 2, target: "v2", findings: [] }, { hmacKey: key, requestTsa: false });
  assert.equal(ev.payload.schema_version, 2);
  const v = await verifyEvidence(ev, { hmacKey: key });
  assert.equal(v.hashOk, true);
  assert.equal(v.hmacOk, true);
});

test("T3.N3: verifier rechaza tampering tanto en v1 como en v2", async () => {
  const key = "k";
  const evV1 = await buildEvidence({ a: 1 }, { hmacKey: key, requestTsa: false });
  evV1.payload.a = 999;
  assert.equal((await verifyEvidence(evV1, { hmacKey: key })).hashOk, false);

  const evV2 = await buildEvidence({ schema_version: 2, a: 1 }, { hmacKey: key, requestTsa: false });
  evV2.payload.a = 999;
  assert.equal((await verifyEvidence(evV2, { hmacKey: key })).hashOk, false);
});

test("evidence: TSA real DigiCert sella el hash (requiere red)", async () => {
  const ev = await buildEvidence({ evt: "tsa-itest", ts: Date.now() }, { hmacKey: "k", requestTsa: true });
  if (ev.seal.rfc3161Tsa) {
    assert.equal(ev.seal.method, "HMAC-SHA256 + RFC 3161 TSA");
    assert.ok(ev.seal.rfc3161Tsa.token);
    assert.ok(ev.seal.rfc3161Tsa.genTime);
    const v = await verifyEvidence(ev, { hmacKey: "k" });
    assert.equal(v.tsaOk, true);
  } else {
    // Fallback honesto: sin red, el sello es HMAC-only y el método lo declara.
    assert.equal(ev.seal.method, "HMAC-SHA256");
    console.log("  (sin TSA en este run: fallback HMAC-only — red no disponible)");
  }
});
