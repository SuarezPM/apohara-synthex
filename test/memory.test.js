// Tests de MEMORY. MemoryStore (local) testeado con archivos temporales. Cognee = stub honesto.
import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmSync } from "node:fs";
import { MemoryStore, CogneeClient, CogneeCloudClient } from "../src/memory/index.js";

function tmpPath() { return join(tmpdir(), `synthex-mem-${Date.now()}-${Math.random().toString(36).slice(2)}.json`); }

test("memory: remember + recall por campos", () => {
  const path = tmpPath();
  try {
    const m = new MemoryStore({ path });
    m.remember({ target: "acme", lens: "gtm", evidenceHash: "h1" });
    m.remember({ target: "acme", lens: "security", evidenceHash: "h2" });
    m.remember({ target: "other", lens: "gtm", evidenceHash: "h3" });
    assert.equal(m.recall({ target: "acme" }).length, 2);
    assert.equal(m.recall({ lens: "gtm" }).length, 2);
    assert.equal(m.recall({ target: "acme", lens: "security" }).length, 1);
  } finally { rmSync(path, { force: true }); }
});

test("memory: persiste entre instancias", () => {
  const path = tmpPath();
  try {
    new MemoryStore({ path }).remember({ target: "x", v: 1 });
    assert.equal(new MemoryStore({ path }).all().length, 1);
  } finally { rmSync(path, { force: true }); }
});

test("cognee: cliente expone connect/remember/recall/close (tools reales del MCP)", () => {
  const c = new CogneeClient();
  for (const fn of ["connect", "remember", "recall", "forget", "close"]) {
    assert.equal(typeof c[fn], "function");
  }
});

test("cognee: conecta al MCP local y lista tools (requiere COGNEE_LIVE=1)", { skip: !process.env.COGNEE_LIVE }, async () => {
  const c = new CogneeClient();
  await c.connect();
  const tools = await c.listTools();
  assert.ok(Array.isArray(tools) && tools.length > 0, "el cognee MCP debe exponer tools");
  await c.close();
});

// ─── CogneeCloudClient (R6) — REST cloud backend, offline con fetchImpl inyectado ───────────

const cloudCfg = { apiUrl: "https://tenant-x.aws.cognee.ai", tenantId: "tenant-x", apiKey: "k" };
// fetchImpl que captura requests y responde JSON ok.
function captureFetch(responses = {}) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
    const key = Object.keys(responses).find((k) => url.includes(k));
    const body = key ? responses[key] : { ok: true };
    return { ok: true, status: 200, headers: { get: () => "application/json" }, json: async () => body, text: async () => JSON.stringify(body) };
  };
  return { fetchImpl, calls };
}

test("cognee-cloud: misma interfaz que el local (connect/remember/recall/forget/close)", () => {
  const c = new CogneeCloudClient(cloudCfg);
  for (const fn of ["connect", "remember", "recall", "forget", "close"]) assert.equal(typeof c[fn], "function");
});

test("cognee-cloud: assertReady lanza claro sin apiUrl/apiKey/tenantId", async () => {
  await assert.rejects(() => new CogneeCloudClient({ apiKey: "k", tenantId: "t" }).datasets(), /COGNEE_API_URL/);
  await assert.rejects(() => new CogneeCloudClient({ apiUrl: "u", tenantId: "t" }).datasets(), /COGNEE_API_KEY/);
  await assert.rejects(() => new CogneeCloudClient({ apiUrl: "u", apiKey: "k" }).datasets(), /COGNEE_TENANT_ID/);
});

test("cognee-cloud: headers X-Api-Key + X-Tenant-Id en cada request", async () => {
  const { fetchImpl, calls } = captureFetch();
  await new CogneeCloudClient({ ...cloudCfg, fetchImpl }).datasets();
  assert.equal(calls[0].headers["X-Api-Key"], "k");
  assert.equal(calls[0].headers["X-Tenant-Id"], "tenant-x");
});

test("cognee-cloud: remember → add_text {textData,datasetName} + cognify {datasets,runInBackground}", async () => {
  const { fetchImpl, calls } = captureFetch({ add_text: { status: "PipelineRunCompleted" }, cognify: { status: "PipelineRunStarted" } });
  const c = new CogneeCloudClient({ ...cloudCfg, dataset: "synthex", fetchImpl });
  const r = await c.remember("Competitor X cut prices 20%.", { runInBackground: true });
  const add = calls.find((c) => c.url.includes("/add_text"));
  const cog = calls.find((c) => c.url.includes("/cognify"));
  assert.deepEqual(add.body, { textData: ["Competitor X cut prices 20%."], datasetName: "synthex" });
  assert.deepEqual(cog.body, { datasets: ["synthex"], runInBackground: true });
  assert.equal(r.cognify.status, "PipelineRunStarted");
});

test("cognee-cloud: remember skipCognify → solo add_text, sin cognify", async () => {
  const { fetchImpl, calls } = captureFetch({ add_text: { status: "ok" } });
  await new CogneeCloudClient({ ...cloudCfg, fetchImpl }).remember("x", { skipCognify: true });
  assert.ok(calls.some((c) => c.url.includes("/add_text")));
  assert.ok(!calls.some((c) => c.url.includes("/cognify")), "skipCognify NO debe llamar cognify");
});

test("cognee-cloud: recall → POST search {query,searchType,datasets}", async () => {
  const { fetchImpl, calls } = captureFetch({ search: [{ result: "r" }] });
  const c = new CogneeCloudClient({ ...cloudCfg, dataset: "synthex", fetchImpl });
  const out = await c.recall("what changed?", { searchType: "CHUNKS" });
  const s = calls.find((c) => c.url.includes("/search"));
  assert.equal(s.method, "POST");
  assert.deepEqual(s.body, { query: "what changed?", searchType: "CHUNKS", datasets: ["synthex"] });
  assert.equal(out[0].result, "r");
});

test("cognee-cloud: forget → DELETE /datasets/{id}; sin id lanza", async () => {
  const { fetchImpl, calls } = captureFetch();
  const c = new CogneeCloudClient({ ...cloudCfg, fetchImpl });
  await c.forget({ datasetId: "ds-1" });
  assert.equal(calls[0].method, "DELETE");
  assert.match(calls[0].url, /\/api\/v1\/datasets\/ds-1$/);
  await assert.rejects(() => c.forget({}), /datasetId requerido/);
});

test("cognee-cloud: HTTP no-ok lanza con status", async () => {
  const fetchImpl = async () => ({ ok: false, status: 401, text: async () => "unauthorized", headers: { get: () => "application/json" } });
  await assert.rejects(() => new CogneeCloudClient({ ...cloudCfg, fetchImpl }).datasets(), /HTTP 401/);
});

test("cognee-cloud: el guard COGNEE_REMOTE_URL del cliente LOCAL sigue intacto (no lo negamos)", async () => {
  const prev = process.env.COGNEE_REMOTE_URL;
  process.env.COGNEE_REMOTE_URL = "http://x";
  try {
    await assert.rejects(() => new CogneeClient().connect(), /strictly local/);
  } finally {
    if (prev === undefined) delete process.env.COGNEE_REMOTE_URL; else process.env.COGNEE_REMOTE_URL = prev;
  }
});
