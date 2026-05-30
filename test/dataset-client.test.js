// Tests del Dataset client (Bright Data Web Scraper / Datasets API REST, async).
// Unit: shape sin red (fetch stubbeado). Live: opt-in con BD_LIVE=1 + secrets.
// CUIDADO: el LIVE dispara 1 input facturable y NO poolea el snapshot.
import { test } from "node:test";
import assert from "node:assert/strict";
import { BrightDataDatasetClient } from "../src/fetch/dataset-client.js";

test("dataset-client: sin token lanza error claro", async () => {
  const c = new BrightDataDatasetClient({ apiToken: null, datasetId: "gd_x" });
  await assert.rejects(() => c.scrape("https://x.com"), /Falta BRIGHT_DATA_TOKEN/);
});

test("dataset-client: sin datasetId lanza error claro", async () => {
  const c = new BrightDataDatasetClient({ apiToken: "tok", datasetId: null });
  await assert.rejects(() => c.scrape("https://x.com"), /Falta BRIGHT_DATA_DATASET_ID/);
});

test("dataset-client: límite duro de 2 inputs (facturación)", async () => {
  const c = new BrightDataDatasetClient({ apiToken: "tok", datasetId: "gd_x" });
  await assert.rejects(
    () => c.scrape(["https://a.com", "https://b.com", "https://c.com"]),
    /límite de seguridad de 2 inputs/,
  );
});

test("dataset-client: arma URL+query+body {input:[{url}]} y devuelve la respuesta", async () => {
  const orig = globalThis.fetch;
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, json: async () => ({ snapshot_id: "snap_77" }) };
  };
  try {
    const c = new BrightDataDatasetClient({ apiToken: "tok", datasetId: "gd_ds" });
    const res = await c.scrape("https://acme.com");
    assert.deepEqual(res, { snapshot_id: "snap_77" });
    assert.match(captured.url, /^https:\/\/api\.brightdata\.com\/datasets\/v3\/scrape\?/);
    assert.match(captured.url, /dataset_id=gd_ds/);
    assert.match(captured.url, /notify=false/);
    assert.match(captured.url, /include_errors=true/);
    assert.equal(captured.init.headers.Authorization, "Bearer tok");
    const body = JSON.parse(captured.init.body);
    assert.deepEqual(body, { input: [{ url: "https://acme.com" }] });
  } finally { globalThis.fetch = orig; }
});

test("dataset-client: acepta hasta 2 inputs", async () => {
  const orig = globalThis.fetch;
  let body;
  globalThis.fetch = async (_u, init) => { body = JSON.parse(init.body); return { ok: true, json: async () => ({ snapshot_id: "s" }) }; };
  try {
    await new BrightDataDatasetClient({ apiToken: "tok", datasetId: "gd_ds" }).scrape(["https://a.com", "https://b.com"]);
    assert.deepEqual(body.input, [{ url: "https://a.com" }, { url: "https://b.com" }]);
  } finally { globalThis.fetch = orig; }
});

test("dataset-client: HTTP no-ok lanza con status", async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: false, status: 402, text: async () => "payment required" });
  try {
    await assert.rejects(() => new BrightDataDatasetClient({ apiToken: "tok", datasetId: "gd_ds" }).scrape("https://x.com"), /Dataset HTTP 402/);
  } finally { globalThis.fetch = orig; }
});

// ─── Async flow: trigger → poll → collect (item 2.7) ──────────────────────────

test("dataset-client: triggerDiscoverNew arma type=discover_new + devuelve snapshot_id", async () => {
  let captured;
  const fetchImpl = async (url, init) => { captured = { url, init }; return { ok: true, json: async () => ({ snapshot_id: "snap_dn" }) }; };
  const c = new BrightDataDatasetClient({ apiToken: "tok", datasetId: "gd_ds", fetchImpl });
  const res = await c.triggerDiscoverNew({ keyword: "acme" }, { discoverBy: "keyword" });
  assert.equal(res.snapshot_id, "snap_dn");
  assert.match(captured.url, /^https:\/\/api\.brightdata\.com\/datasets\/v3\/trigger\?/);
  assert.match(captured.url, /type=discover_new/);
  assert.match(captured.url, /discover_by=keyword/);
  assert.match(captured.url, /dataset_id=gd_ds/);
  assert.deepEqual(JSON.parse(captured.init.body), { input: [{ keyword: "acme" }] });
});

test("dataset-client: trigger respeta MAX_INPUTS=2 (facturación)", async () => {
  const c = new BrightDataDatasetClient({ apiToken: "tok", datasetId: "gd_ds", fetchImpl: async () => ({ ok: true, json: async () => ({}) }) });
  await assert.rejects(() => c.trigger([{ url: "a" }, { url: "b" }, { url: "c" }]), /límite de seguridad de 2 inputs/);
});

test("dataset-client: pollProgress devuelve {status}", async () => {
  const fetchImpl = async (url) => { assert.match(url, /datasets\/v3\/progress\/snap_1$/); return { ok: true, json: async () => ({ status: "running" }) }; };
  const c = new BrightDataDatasetClient({ apiToken: "tok", datasetId: "gd_ds", fetchImpl });
  assert.equal((await c.pollProgress("snap_1")).status, "running");
});

test("dataset-client: collect poolea running→ready, baja el snapshot y SELLA los 4 campos", async () => {
  let progressCalls = 0;
  const fetchImpl = async (url) => {
    if (url.includes("/progress/")) {
      progressCalls++;
      return { ok: true, json: async () => ({ status: progressCalls < 2 ? "running" : "ready" }) };
    }
    if (url.includes("/snapshot/")) return { ok: true, json: async () => ([{ url: "https://x", title: "t" }]) };
    throw new Error("unexpected url " + url);
  };
  const c = new BrightDataDatasetClient({ apiToken: "tok", datasetId: "gd_DS", fetchImpl });
  const out = await c.collect("snap_42", { intervalMs: 0, sleep: async () => {} });
  // 4 campos sellables: surface + dataset_id + snapshot_id + fetched-at
  assert.equal(out.snapshotId, "snap_42");
  assert.equal(out.datasetId, "gd_DS");
  assert.match(out.surface, /discover_new/);
  assert.equal(typeof out.fetchedAt, "string");
  assert.ok(Array.isArray(out.rows) && out.rows.length === 1);
  assert.ok(progressCalls >= 2, "debe haber pooleado hasta ready");
});

test("dataset-client: collect es BOUNDED — nunca poolea infinito (cost cap)", async () => {
  const fetchImpl = async (url) => url.includes("/progress/")
    ? { ok: true, json: async () => ({ status: "running" }) } // nunca lista
    : { ok: true, json: async () => ([]) };
  const c = new BrightDataDatasetClient({ apiToken: "tok", datasetId: "gd_ds", fetchImpl });
  await assert.rejects(() => c.collect("snap_stuck", { maxAttempts: 3, intervalMs: 0, sleep: async () => {} }), /not ready after 3 polls/);
});

test("dataset-client: collect lanza si el snapshot falla", async () => {
  const fetchImpl = async (url) => url.includes("/progress/")
    ? { ok: true, json: async () => ({ status: "failed" }) }
    : { ok: true, json: async () => ([]) };
  const c = new BrightDataDatasetClient({ apiToken: "tok", datasetId: "gd_ds", fetchImpl });
  await assert.rejects(() => c.collect("snap_bad", { intervalMs: 0, sleep: async () => {} }), /failed/);
});

test("dataset-client LIVE: trigger real (1 input, sin poll) — opt-in", { skip: process.env.BD_LIVE !== "1" }, async () => {
  const res = await new BrightDataDatasetClient().scrape("https://example.com");
  assert.equal(typeof res, "object");
});
