// Tests del ROUTER multi-API (src/fetch/router.js).
// Sin red: fetch stubbeado (serp/unlocker/dataset van por globalThis.fetch). El path browser se
// verifica vía su guard honesto (sin WSS lanza) para confirmar que el router enruta ahí.
import { test } from "node:test";
import assert from "node:assert/strict";
import { smartFetcher } from "../src/fetch/router.js";

test("router: término (no-URL) → SERP, concatena title+snippet de organic[]", async () => {
  const orig = globalThis.fetch;
  let bodyUrl;
  globalThis.fetch = async (_u, init) => {
    bodyUrl = JSON.parse(init.body).url;
    return { ok: true, text: async () => JSON.stringify({ organic: [
      { title: "Acme baja precios", snippet: "20% menos" },
      { title: "Acme contrata", snippet: "5 vendedores" },
    ] }) };
  };
  try {
    const docs = await smartFetcher({ apiToken: "tok", zone: "serpZ" })("competidor acme");
    assert.equal(docs.length, 1);
    assert.equal(docs[0].url, "serp:competidor acme");
    assert.match(docs[0].content, /Acme baja precios — 20% menos/);
    assert.match(docs[0].content, /Acme contrata — 5 vendedores/);
    assert.match(bodyUrl, /google\.com\/search\?q=/); // fue a la SERP API
  } finally { globalThis.fetch = orig; }
});

test("router: URL default → Web Unlocker (httpFetcher)", async () => {
  const orig = globalThis.fetch;
  let body;
  globalThis.fetch = async (_u, init) => { body = JSON.parse(init.body); return { ok: true, text: async () => "# markdown" }; };
  try {
    const docs = await smartFetcher({ apiToken: "tok", zone: "z1" })("https://acme.com");
    assert.equal(docs.length, 1);
    assert.equal(docs[0].url, "https://acme.com");
    assert.equal(docs[0].content, "# markdown");
    assert.equal(body.url, "https://acme.com"); // scrape directo, no SERP
    assert.equal(body.data_format, "markdown");
  } finally { globalThis.fetch = orig; }
});

test("router: mode 'serp' fuerza SERP aunque el target sea URL", async () => {
  const orig = globalThis.fetch;
  let bodyUrl;
  globalThis.fetch = async (_u, init) => { bodyUrl = JSON.parse(init.body).url; return { ok: true, text: async () => JSON.stringify({ organic: [{ title: "t", snippet: "s" }] }) }; };
  try {
    const docs = await smartFetcher({ apiToken: "tok", mode: "serp" })("https://acme.com");
    assert.equal(docs[0].url, "serp:https://acme.com");
    assert.match(docs[0].content, /t — s/);
    assert.match(bodyUrl, /google\.com\/search/);
  } finally { globalThis.fetch = orig; }
});

test("router: mode 'dataset' → Datasets API, mapea markdown a {url, content}", async () => {
  const orig = globalThis.fetch;
  let url;
  globalThis.fetch = async (u) => { url = u; return { ok: true, json: async () => [{ url: "https://acme.com", markdown: "## dataset md" }] }; };
  try {
    const docs = await smartFetcher({ apiToken: "tok", datasetId: "gd_ds", mode: "dataset" })("https://acme.com");
    assert.equal(docs.length, 1);
    assert.equal(docs[0].url, "https://acme.com");
    assert.equal(docs[0].content, "## dataset md");
    assert.match(url, /\/datasets\/v3\/scrape\?/);
  } finally { globalThis.fetch = orig; }
});

test("router: mode 'dataset' sin markdown cae a JSON del row", async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: true, json: async () => [{ url: "https://x.com", price: 42 }] });
  try {
    const docs = await smartFetcher({ apiToken: "tok", datasetId: "gd_ds", mode: "dataset" })("https://x.com");
    assert.equal(docs[0].url, "https://x.com");
    assert.match(docs[0].content, /"price":42/);
  } finally { globalThis.fetch = orig; }
});

test("router: mode 'browser' enruta a browserFetch (sin WSS lanza error honesto)", async () => {
  const saved = process.env.BRIGHT_DATA_BROWSER_WSS;
  delete process.env.BRIGHT_DATA_BROWSER_WSS;
  try {
    await assert.rejects(
      () => smartFetcher({ mode: "browser", wssEndpoint: undefined })("https://acme.com"),
      /Falta BRIGHT_DATA_BROWSER_WSS/,
    );
  } finally {
    if (saved !== undefined) process.env.BRIGHT_DATA_BROWSER_WSS = saved;
  }
});

test("router: mode 'crawl' sin dataset de crawl propaga error honesto", async () => {
  await assert.rejects(
    () => smartFetcher({ apiToken: "tok", datasetId: null, mode: "crawl" })("https://acme.com"),
    /BRIGHT_DATA_CRAWL_DATASET_ID/,
  );
});

test("router: mode 'crawl' trigger→ready→snapshot devuelve [{url, content}]", async () => {
  const orig = globalThis.fetch;
  const urls = [];
  globalThis.fetch = async (u) => {
    urls.push(String(u));
    if (String(u).includes("/trigger")) return { ok: true, json: async () => ({ snapshot_id: "snap_1" }) };
    if (String(u).includes("/progress/")) return { ok: true, json: async () => ({ status: "ready" }) };
    if (String(u).includes("/snapshot/")) return { ok: true, json: async () => [{ url: "https://acme.com", markdown: "crawl md" }] };
    throw new Error(`URL inesperada: ${u}`);
  };
  try {
    const docs = await smartFetcher({ apiToken: "tok", datasetId: "gd_crawl", mode: "crawl" })("https://acme.com");
    assert.equal(docs.length, 1);
    assert.equal(docs[0].url, "https://acme.com");
    assert.equal(docs[0].content, "crawl md");
    assert.ok(urls.some((u) => u.includes("/trigger")));
    assert.ok(urls.some((u) => u.includes("/progress/")));
    assert.ok(urls.some((u) => u.includes("/snapshot/")));
  } finally { globalThis.fetch = orig; }
});

test("router: fetcher es compatible con runPipeline (devuelve [{url, content}])", async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: true, text: async () => "contenido" });
  try {
    const fetcher = smartFetcher({ apiToken: "tok" });
    const docs = await fetcher("https://acme.com");
    assert.ok(Array.isArray(docs));
    assert.ok(docs.every((d) => typeof d.url === "string" && typeof d.content === "string"));
  } finally { globalThis.fetch = orig; }
});
