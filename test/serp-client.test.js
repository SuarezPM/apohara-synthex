// Tests del SERP client (Bright Data SERP API REST).
// Unit: shape sin red (fetch stubbeado). Live: opt-in con BD_LIVE=1 + secrets.
import { test } from "node:test";
import assert from "node:assert/strict";
import { BrightDataSerpClient, serpSearch } from "../src/fetch/serp-client.js";

test("serp-client: sin token lanza error claro", async () => {
  const c = new BrightDataSerpClient({ apiToken: null });
  await assert.rejects(() => c.search("algo"), /Falta BRIGHT_DATA_TOKEN/);
});

test("serp-client: sin query lanza error claro", async () => {
  const c = new BrightDataSerpClient({ apiToken: "tok" });
  await assert.rejects(() => c.search(""), /falta el query/);
});

test("serp-client: arma el request correcto (zone+url+brd_json) con fetch stubbeado", async () => {
  const orig = globalThis.fetch;
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, text: async () => JSON.stringify({ organic: [{ title: "r1" }] }) };
  };
  try {
    const c = new BrightDataSerpClient({ apiToken: "tok", zone: "serpZ" });
    const out = await c.search("competidor X");
    assert.deepEqual(out, { organic: [{ title: "r1" }] });
    assert.equal(captured.url, "https://api.brightdata.com/request");
    assert.equal(captured.init.headers.Authorization, "Bearer tok");
    const body = JSON.parse(captured.init.body);
    assert.equal(body.zone, "serpZ");
    assert.equal(body.format, "raw");
    assert.match(body.url, /google\.com\/search\?q=competidor%20X/);
    assert.match(body.url, /brd_json=1/);
  } finally { globalThis.fetch = orig; }
});

test("serp-client: json=false no agrega brd_json y devuelve HTML crudo", async () => {
  const orig = globalThis.fetch;
  let bodyUrl;
  globalThis.fetch = async (_u, init) => { bodyUrl = JSON.parse(init.body).url; return { ok: true, text: async () => "<html>serp</html>" }; };
  try {
    const out = await new BrightDataSerpClient({ apiToken: "tok" }).search("x", { json: false });
    assert.equal(out, "<html>serp</html>");
    assert.doesNotMatch(bodyUrl, /brd_json/);
  } finally { globalThis.fetch = orig; }
});

test("serp-client: HTTP no-ok lanza con status", async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: false, status: 401, text: async () => "unauthorized" });
  try {
    await assert.rejects(() => new BrightDataSerpClient({ apiToken: "tok" }).search("x"), /SERP HTTP 401/);
  } finally { globalThis.fetch = orig; }
});

test("serp-client: serpSearch helper usa el cliente", async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: true, text: async () => JSON.stringify({ organic: [] }) });
  try {
    const out = await serpSearch("q", { apiToken: "tok", zone: "z" });
    assert.deepEqual(out, { organic: [] });
  } finally { globalThis.fetch = orig; }
});

test("serp-client LIVE: búsqueda real devuelve JSON (opt-in)", { skip: process.env.BD_LIVE !== "1" }, async () => {
  const serp = await new BrightDataSerpClient().search("bright data", { json: true });
  assert.equal(typeof serp, "object");
});
