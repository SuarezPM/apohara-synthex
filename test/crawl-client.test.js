// Tests del Crawl client (Bright Data Crawl API REST, async).
// Unit: shape sin red (fetch stubbeado). Live: opt-in con BD_LIVE=1 + secrets + dataset de crawl.
import { test } from "node:test";
import assert from "node:assert/strict";
import { BrightDataCrawlClient } from "../src/fetch/crawl-client.js";

test("crawl-client: sin token lanza error claro", async () => {
  const c = new BrightDataCrawlClient({ apiToken: null, datasetId: "gd_x" });
  await assert.rejects(() => c.trigger("https://x.com"), /Falta BRIGHT_DATA_TOKEN/);
});

test("crawl-client: sin dataset de crawl lanza error claro (honesto, no finge)", async () => {
  const c = new BrightDataCrawlClient({ apiToken: "tok", datasetId: null });
  await assert.rejects(() => c.trigger("https://x.com"), /BRIGHT_DATA_CRAWL_DATASET_ID/);
});

test("crawl-client: trigger arma URL+query+body y devuelve snapshot_id", async () => {
  const orig = globalThis.fetch;
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, json: async () => ({ snapshot_id: "snap_123" }) };
  };
  try {
    const c = new BrightDataCrawlClient({ apiToken: "tok", datasetId: "gd_crawl" });
    const id = await c.trigger("https://acme.com", { outputFields: "markdown" });
    assert.equal(id, "snap_123");
    assert.match(captured.url, /^https:\/\/api\.brightdata\.com\/datasets\/v3\/trigger\?/);
    assert.match(captured.url, /dataset_id=gd_crawl/);
    assert.match(captured.url, /custom_output_fields=markdown/);
    assert.match(captured.url, /include_errors=true/);
    assert.equal(captured.init.headers.Authorization, "Bearer tok");
    const body = JSON.parse(captured.init.body);
    assert.deepEqual(body, [{ url: "https://acme.com" }]);
  } finally { globalThis.fetch = orig; }
});

test("crawl-client: trigger sin snapshot_id en respuesta lanza", async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: true, json: async () => ({ foo: "bar" }) });
  try {
    const c = new BrightDataCrawlClient({ apiToken: "tok", datasetId: "gd_crawl" });
    await assert.rejects(() => c.trigger("https://x.com"), /sin snapshot_id/);
  } finally { globalThis.fetch = orig; }
});

test("crawl-client: progress consulta GET con el snapshot_id", async () => {
  const orig = globalThis.fetch;
  let url;
  globalThis.fetch = async (u) => { url = u; return { ok: true, json: async () => ({ status: "running" }) }; };
  try {
    const c = new BrightDataCrawlClient({ apiToken: "tok", datasetId: "gd_crawl" });
    const p = await c.progress("snap_123");
    assert.equal(p.status, "running");
    assert.match(url, /\/datasets\/v3\/progress\/snap_123$/);
  } finally { globalThis.fetch = orig; }
});

test("crawl-client: HTTP no-ok en trigger lanza con status", async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: false, status: 400, text: async () => "bad" });
  try {
    const c = new BrightDataCrawlClient({ apiToken: "tok", datasetId: "gd_crawl" });
    await assert.rejects(() => c.trigger("https://x.com"), /Crawl trigger HTTP 400/);
  } finally { globalThis.fetch = orig; }
});

// LIVE: solo corre si hay dataset de crawl configurado además de BD_LIVE=1 (si no, skip honesto).
test("crawl-client LIVE: trigger real devuelve snapshot_id (opt-in)", {
  skip: process.env.BD_LIVE !== "1" || !process.env.BRIGHT_DATA_CRAWL_DATASET_ID,
}, async () => {
  const id = await new BrightDataCrawlClient().trigger("https://example.com", { outputFields: "markdown" });
  assert.equal(typeof id, "string");
});
