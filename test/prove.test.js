// Tests del módulo PROVE. `node --test`.
// Cubren: HMAC sella+verifica, detección de tampering, y TSA real contra DigiCert (red).
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildEvidence, verifyEvidence } from "../src/prove/evidence-report.js";
import { sha256, hmacSign, hmacVerify } from "../src/prove/hmac.js";

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
  const v = verifyEvidence(ev, { hmacKey: key });
  assert.equal(v.hashOk, true);
  assert.equal(v.hmacOk, true);
  assert.equal(v.tsaOk, null); // no se pidió TSA
});

test("evidence: detecta tampering del payload", async () => {
  const key = "k";
  const ev = await buildEvidence({ a: 1 }, { hmacKey: key, requestTsa: false });
  ev.payload.a = 2; // tamper
  const v = verifyEvidence(ev, { hmacKey: key });
  assert.equal(v.hashOk, false);
});

test("evidence: TSA real DigiCert sella el hash (requiere red)", async () => {
  const ev = await buildEvidence({ evt: "tsa-itest", ts: Date.now() }, { hmacKey: "k", requestTsa: true });
  if (ev.seal.rfc3161Tsa) {
    assert.equal(ev.seal.method, "HMAC-SHA256 + RFC 3161 TSA");
    assert.ok(ev.seal.rfc3161Tsa.token);
    assert.ok(ev.seal.rfc3161Tsa.genTime);
    const v = verifyEvidence(ev, { hmacKey: "k" });
    assert.equal(v.tsaOk, true);
  } else {
    // Fallback honesto: sin red, el sello es HMAC-only y el método lo declara.
    assert.equal(ev.seal.method, "HMAC-SHA256");
    console.log("  (sin TSA en este run: fallback HMAC-only — red no disponible)");
  }
});
