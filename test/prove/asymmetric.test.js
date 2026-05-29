// v0.8.0 Commit 2 — Ed25519 asymmetric signature module unit tests.
// Round-trip + tamper detection + key-mismatch + malformed-input handling.
// Zero network; pure node:crypto via webcrypto.subtle (native, Node ≥24).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, sign, verify, keyIdOf, resolveSigningKey } from "../../src/prove/asymmetric.js";

test("generateKeyPair · returns pkcs8 PEM + spki PEM + 32-hex keyId + 88-char SPKI b64", () => {
  const kp = generateKeyPair();
  assert.match(kp.privateKeyPem, /-----BEGIN PRIVATE KEY-----/);
  assert.match(kp.privateKeyPem, /-----END PRIVATE KEY-----/);
  assert.match(kp.publicKeyPem, /-----BEGIN PUBLIC KEY-----/);
  assert.match(kp.keyId, /^[0-9a-f]{32}$/);
  // Ed25519 SPKI DER is exactly 44 bytes → base64 ~60 chars (with padding)
  const spkiDerBytes = Buffer.from(kp.publicKeySpkiB64, "base64").length;
  assert.equal(spkiDerBytes, 44, "Ed25519 SPKI DER must be exactly 44 bytes");
});

test("generateKeyPair · two calls produce different keys (no static seed leak)", () => {
  const a = generateKeyPair();
  const b = generateKeyPair();
  assert.notEqual(a.keyId, b.keyId);
  assert.notEqual(a.privateKeyPem, b.privateKeyPem);
  assert.notEqual(a.publicKeySpkiB64, b.publicKeySpkiB64);
});

test("keyIdOf · derives 32-hex-char fingerprint from SPKI DER (stable across forms)", () => {
  const kp = generateKeyPair();
  const fromB64 = keyIdOf(kp.publicKeySpkiB64);
  const fromBytes = keyIdOf(Buffer.from(kp.publicKeySpkiB64, "base64"));
  assert.equal(fromB64, kp.keyId);
  assert.equal(fromBytes, kp.keyId);
});

test("sign + verify · round-trip on canonical string returns ok:true", async () => {
  const kp = generateKeyPair();
  const canonical = JSON.stringify({ a: 1, b: 2, c: "hello" });
  const sig = await sign(canonical, kp.privateKeyPem);
  assert.equal(sig.alg, "Ed25519");
  assert.equal(sig.publicKey, kp.publicKeySpkiB64);
  assert.equal(sig.keyId, kp.keyId);
  assert.match(sig.value, /^[A-Za-z0-9+/=]+$/);
  assert.equal(Buffer.from(sig.value, "base64").length, 64, "Ed25519 sig must be 64 bytes raw");
  assert.match(sig.signedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  const r = await verify(canonical, sig);
  assert.deepEqual(r, { ok: true, reason: null });
});

test("verify · tampered canonical → bad-signature (NOT throw)", async () => {
  const kp = generateKeyPair();
  const canonical = JSON.stringify({ a: 1 });
  const sig = await sign(canonical, kp.privateKeyPem);
  const r = await verify(canonical + "tampered", sig);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "bad-signature");
});

test("verify · null / undefined sig block → no-signature", async () => {
  assert.deepEqual(await verify("x", null), { ok: false, reason: "no-signature" });
  assert.deepEqual(await verify("x", undefined), { ok: false, reason: "no-signature" });
});

test("verify · malformed sig block → malformed-signature (NEVER throws)", async () => {
  // Missing fields
  assert.equal((await verify("x", {})).reason, "malformed-signature");
  // Wrong alg
  assert.equal((await verify("x", { alg: "ES256", publicKey: "x", value: "y" })).reason, "malformed-signature");
  // Non-string publicKey
  assert.equal((await verify("x", { alg: "Ed25519", publicKey: 42, value: "y" })).reason, "malformed-signature");
  // Non-string value
  assert.equal((await verify("x", { alg: "Ed25519", publicKey: "x", value: 42 })).reason, "malformed-signature");
});

test("verify · keyId in seal mismatches embedded SPKI → malformed-signature (anti-spoof)", async () => {
  const kp = generateKeyPair();
  const canonical = JSON.stringify({ a: 1 });
  const sig = await sign(canonical, kp.privateKeyPem);
  const spoofed = { ...sig, keyId: "0".repeat(32) };  // wrong keyId vs the embedded pubkey
  const r = await verify(canonical, spoofed);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "malformed-signature");
});

test("verify · A's signature verified with B's embedded pubkey → bad-signature", async () => {
  const a = generateKeyPair();
  const b = generateKeyPair();
  const canonical = JSON.stringify({ a: 1 });
  const sigA = await sign(canonical, a.privateKeyPem);
  // Replace embedded pubkey with B's pubkey — keyId is recomputed from SPKI inside verify so the
  // embedded keyId check still passes IF we also swap it. The sig math then fails against B's key.
  const spoofed = { ...sigA, publicKey: b.publicKeySpkiB64, keyId: b.keyId };
  const r = await verify(canonical, spoofed);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "bad-signature");
});

// ─── resolveSigningKey · disk-backed paths (NO fs injection) ───────────────
// These exercise the REAL filesystem path that production uses. The pre-existing
// tests all injected `fs` or used inline PEM, hiding the ESM `require("node:fs")`
// crash on the file-path and XDG-default branches (the "recommended" modes).

test("resolveSigningKey · SYNTHEX_SIGNING_KEY inline → normalized pkcs8 PEM (no disk)", () => {
  const kp = generateKeyPair();
  const k = resolveSigningKey({ env: { SYNTHEX_SIGNING_KEY: kp.privateKeyPem } });
  assert.match(k, /-----BEGIN PRIVATE KEY-----/);
  assert.equal(k.trim(), kp.privateKeyPem.trim());
});

test("resolveSigningKey · SYNTHEX_SIGNING_KEY_FILE reads real file off disk (no fs injection)", (t) => {
  const kp = generateKeyPair();
  const dir = mkdtempSync(join(tmpdir(), "synthex-keyfile-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const keyPath = join(dir, "synthex-ed25519.key");
  writeFileSync(keyPath, kp.privateKeyPem, { mode: 0o600 });
  // fs defaults to null → must use node:fs internally without crashing.
  const k = resolveSigningKey({ env: { SYNTHEX_SIGNING_KEY_FILE: keyPath } });
  assert.equal(k.trim(), kp.privateKeyPem.trim());
});

test("resolveSigningKey · XDG default ('recommended') reads real file off disk (no fs injection)", (t) => {
  const kp = generateKeyPair();
  const xdgHome = mkdtempSync(join(tmpdir(), "synthex-xdg-"));
  t.after(() => rmSync(xdgHome, { recursive: true, force: true }));
  mkdirSync(join(xdgHome, "apohara", "synthex"), { recursive: true });
  writeFileSync(join(xdgHome, "apohara", "synthex", "synthex-ed25519.key"), kp.privateKeyPem, { mode: 0o600 });
  // The crash here was SILENT: require() throw was swallowed by the catch → null,
  // so the seal degraded to symmetric-only without warning. Must load the key.
  const k = resolveSigningKey({ env: { XDG_CONFIG_HOME: xdgHome } });
  assert.equal(k.trim(), kp.privateKeyPem.trim());
});

test("resolveSigningKey · XDG default with no key file present → null (no throw)", (t) => {
  const xdgHome = mkdtempSync(join(tmpdir(), "synthex-xdg-empty-"));
  t.after(() => rmSync(xdgHome, { recursive: true, force: true }));
  const k = resolveSigningKey({ env: { XDG_CONFIG_HOME: xdgHome } });
  assert.equal(k, null);
});

test("resolveSigningKey · no env configured → null", () => {
  assert.equal(resolveSigningKey({ env: {} }), null);
});
