// Tests del fetcher HTTP serverless (Bright Data Web Unlocker REST).
// Unit: shape sin red (fetch stubbeado). Live: opt-in con BRIGHTDATA_LIVE=1 + secrets.
import { test } from "node:test";
import assert from "node:assert/strict";
import { BrightDataHttpClient, httpFetcher } from "../src/fetch/http-client.js";

test("http-client: sin token lanza error claro", async () => {
  const c = new BrightDataHttpClient({ apiToken: null });
  await assert.rejects(() => c.scrape("https://example.com"), /Falta BRIGHT_DATA_TOKEN/);
});

test("http-client: arma el request correcto (zone+url+data_format) con fetch stubbeado", async () => {
  const orig = globalThis.fetch;
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, text: async () => "# contenido markdown" };
  };
  try {
    const c = new BrightDataHttpClient({ apiToken: "tok", zone: "z1" });
    const out = await c.scrape("https://acme.com");
    assert.equal(out, "# contenido markdown");
    assert.equal(captured.url, "https://api.brightdata.com/request");
    assert.equal(captured.init.headers.Authorization, "Bearer tok");
    const body = JSON.parse(captured.init.body);
    assert.equal(body.zone, "z1");
    assert.equal(body.url, "https://acme.com");
    assert.equal(body.data_format, "markdown");
  } finally { globalThis.fetch = orig; }
});

test("http-client: httpFetcher devuelve [{url, content}] para una URL", async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: true, text: async () => "contenido" });
  try {
    const fetcher = httpFetcher({ apiToken: "tok", zone: "z1" });
    const docs = await fetcher("https://acme.com");
    assert.equal(docs.length, 1);
    assert.equal(docs[0].url, "https://acme.com");
    assert.equal(docs[0].content, "contenido");
  } finally { globalThis.fetch = orig; }
});

test("http-client: término no-URL scrapea la SERP de Google", async () => {
  const orig = globalThis.fetch;
  let bodyUrl;
  globalThis.fetch = async (_u, init) => { bodyUrl = JSON.parse(init.body).url; return { ok: true, text: async () => "serp" }; };
  try {
    const docs = await httpFetcher({ apiToken: "tok" })("competidor X");
    assert.match(bodyUrl, /google\.com\/search\?q=/);
    assert.equal(docs[0].content, "serp");
  } finally { globalThis.fetch = orig; }
});

test("http-client LIVE: scrape real (opt-in)", { skip: process.env.BRIGHTDATA_LIVE !== "1" }, async () => {
  const c = new BrightDataHttpClient();
  const md = await c.scrape("https://example.com");
  assert.match(md, /Example Domain/i);
});
