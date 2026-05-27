// Tests del guard del endpoint público (SSRF + allowlist + rate-limit).
import { test } from "node:test";
import assert from "node:assert/strict";
import { assertSafeTarget, rateLimit, clientIp, isUrlTarget, _resetRateLimit } from "../src/guard.js";

test("guard: permite URL pública y término de búsqueda", () => {
  assert.doesNotThrow(() => assertSafeTarget("https://en.wikipedia.org/wiki/Bright_Data"));
  assert.doesNotThrow(() => assertSafeTarget("competidor X precios"));
});

test("guard: bloquea SSRF (localhost, loopback, metadata, rangos privados)", () => {
  for (const bad of [
    "http://localhost/admin", "http://127.0.0.1:8080", "http://169.254.169.254/latest/meta-data",
    "http://10.0.0.5", "http://192.168.1.1", "http://172.16.0.1", "https://foo.local",
  ]) {
    assert.throws(() => assertSafeTarget(bad), /SSRF|privado|interno/i, `debería bloquear ${bad}`);
  }
});

test("guard: bloquea IPs ofuscadas (decimal/hex) e IPv6 privado", () => {
  for (const bad of ["http://2130706433/", "http://0x7f000001/", "http://[fe80::1]/", "http://[fc00::1]/"]) {
    assert.throws(() => assertSafeTarget(bad), /SSRF/i, `debería bloquear ${bad}`);
  }
});

test("guard: rechaza protocolos no http/https y target vacío", () => {
  assert.throws(() => assertSafeTarget("ftp://x.com"), /http/i); // isUrlTarget=false → cae como término... validamos URL real
  assert.throws(() => assertSafeTarget(""), /vac/i);
});

test("guard: allowlist por env restringe dominios", () => {
  const prev = process.env.SYNTHEX_ALLOWED_DOMAINS;
  process.env.SYNTHEX_ALLOWED_DOMAINS = "wikipedia.org, example.com";
  try {
    assert.doesNotThrow(() => assertSafeTarget("https://en.wikipedia.org/wiki/X"));
    assert.throws(() => assertSafeTarget("https://evil.com"), /allowlist/i);
  } finally {
    if (prev === undefined) delete process.env.SYNTHEX_ALLOWED_DOMAINS; else process.env.SYNTHEX_ALLOWED_DOMAINS = prev;
  }
});

test("guard: rate-limit corta tras el máximo por IP", () => {
  _resetRateLimit();
  const ip = "1.2.3.4";
  for (let i = 0; i < 8; i++) assert.equal(rateLimit(ip, { max: 8 }).ok, true, `req ${i + 1} debe pasar`);
  assert.equal(rateLimit(ip, { max: 8 }).ok, false); // la 9na corta
});

test("guard: clientIp lee x-forwarded-for", () => {
  assert.equal(clientIp({ headers: { "x-forwarded-for": "9.9.9.9, 10.0.0.1" } }), "9.9.9.9");
  assert.equal(clientIp({ headers: {} }), "unknown");
});

test("guard: isUrlTarget distingue URL de término", () => {
  assert.equal(isUrlTarget("https://x.com"), true);
  assert.equal(isUrlTarget("hola mundo"), false);
});
