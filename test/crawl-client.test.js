// Tests del Crawl client. Modo default: crawl multi-página sobre Web Unlocker (fetch stubbeado).
// Helpers puros (extractLinks/sameHostLinks). Path nativo opt-in (trigger) con dataset de crawl.
import { test } from "node:test";
import assert from "node:assert/strict";
import { BrightDataCrawlClient, crawlSite, extractLinks, sameHostLinks } from "../src/fetch/crawl-client.js";

test("crawl: extractLinks saca links [txt](url) y <url> del markdown", () => {
  const md = "ver [docs](https://a.com/docs) y <https://a.com/api> y [x](/rel) y [y](https://b.com)";
  const links = extractLinks(md);
  assert.ok(links.includes("https://a.com/docs"));
  assert.ok(links.includes("https://a.com/api"));
  assert.ok(links.includes("https://b.com"));
  assert.ok(!links.includes("/rel")); // relativos se ignoran (sin http)
});

test("crawl: sameHostLinks filtra mismo host, sin assets ni el propio seed", () => {
  const out = sameHostLinks("https://a.com/start", ["https://a.com/p1", "https://a.com/img.png", "https://b.com/x", "https://a.com/start", "https://a.com/p2?q=1"]);
  assert.deepEqual(out, ["https://a.com/p1", "https://a.com/p2"]); // mismo host, sin png, sin seed, query strip
});

test("crawl: sin token lanza error claro", async () => {
  await assert.rejects(() => new BrightDataCrawlClient({ apiToken: null }).crawl("https://x.com"), /Falta BRIGHT_DATA_TOKEN/);
});

test("crawl: seed no-URL lanza error claro", async () => {
  await assert.rejects(() => new BrightDataCrawlClient({ apiToken: "tok" }).crawl("no-es-url"), /seed debe ser una URL/);
});

test("crawl: multi-página vía Web Unlocker → [{url, content}] del mismo host", async () => {
  const orig = globalThis.fetch;
  const pages = {
    "https://acme.com/": "home [a](https://acme.com/a) [b](https://acme.com/b) [ext](https://other.com/z)",
    "https://acme.com/a": "página A contenido",
    "https://acme.com/b": "página B contenido",
  };
  globalThis.fetch = async (_u, init) => ({ ok: true, text: async () => pages[JSON.parse(init.body).url] ?? "?" });
  try {
    const docs = await crawlSite("https://acme.com/", { apiToken: "tok", zone: "z", maxPages: 3 });
    assert.equal(docs[0].url, "https://acme.com/");        // seed primero
    assert.equal(docs.length, 3);                          // seed + 2 internas (other.com excluido)
    assert.deepEqual(docs.map((d) => d.url).sort(), ["https://acme.com/", "https://acme.com/a", "https://acme.com/b"]);
    assert.equal(docs[1].content, "página A contenido");
  } finally { globalThis.fetch = orig; }
});

test("crawl: una página interna que falla no rompe el crawl (best-effort)", async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = async (_u, init) => {
    const url = JSON.parse(init.body).url;
    if (url === "https://acme.com/") return { ok: true, text: async () => "[a](https://acme.com/a)" };
    return { ok: false, status: 500, text: async () => "boom" }; // la interna falla
  };
  try {
    const docs = await crawlSite("https://acme.com/", { apiToken: "tok", maxPages: 3 });
    assert.equal(docs.length, 1); // solo el seed; la interna falló y se omitió
    assert.equal(docs[0].url, "https://acme.com/");
  } finally { globalThis.fetch = orig; }
});

test("crawl nativo (opt-in): trigger sin dataset de crawl lanza error claro", async () => {
  await assert.rejects(() => new BrightDataCrawlClient({ apiToken: "tok", datasetId: null }).trigger("https://x.com"), /BRIGHT_DATA_CRAWL_DATASET_ID/);
});

test("crawl nativo (opt-in): trigger con dataset arma query+body y devuelve snapshot_id", async () => {
  const orig = globalThis.fetch; let captured;
  globalThis.fetch = async (url, init) => { captured = { url, init }; return { ok: true, json: async () => ({ snapshot_id: "snap_123" }) }; };
  try {
    const id = await new BrightDataCrawlClient({ apiToken: "tok", datasetId: "gd_crawl" }).trigger("https://acme.com", { outputFields: "markdown" });
    assert.equal(id, "snap_123");
    assert.match(captured.url, /dataset_id=gd_crawl/);
    assert.deepEqual(JSON.parse(captured.init.body), [{ url: "https://acme.com" }]);
  } finally { globalThis.fetch = orig; }
});

test("crawl LIVE: multi-página real (opt-in)", { skip: process.env.BD_LIVE !== "1" }, async () => {
  const docs = await crawlSite("https://en.wikipedia.org/wiki/Bright_Data", { maxPages: 2 });
  assert.ok(docs.length >= 1 && docs[0].content.length > 100);
});
