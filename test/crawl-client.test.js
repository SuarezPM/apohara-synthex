// Tests del Crawl client. Modo default: crawl multi-página sobre Web Unlocker (fetch stubbeado).
// Helpers puros (extractLinks/sameHostLinks). Path nativo opt-in (trigger) con dataset de crawl.
import { test } from "node:test";
import assert from "node:assert/strict";
import { BrightDataCrawlClient, crawlSite, extractLinks, sameHostLinks, parseScrapeNdjson } from "../src/fetch/crawl-client.js";

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

test("crawl nativo: parseScrapeNdjson saca [{url,content}] y omite dead pages", () => {
  const ndjson = [
    JSON.stringify({ input: { url: "https://x.com/dead" }, warning: "dead page", warning_code: "dead_page" }),
    JSON.stringify({ markdown: "# Home", url: "https://x.com/", page_title: "Home" }),
  ].join("\n");
  assert.deepEqual(parseScrapeNdjson(ndjson), [{ url: "https://x.com/", content: "# Home" }]);
});

test("crawl nativo: parseScrapeNdjson también acepta JSON array", () => {
  const arr = JSON.stringify([{ markdown: "# A", url: "https://x.com/a" }, { warning_code: "dead_page", input: { url: "https://x.com/b" } }]);
  assert.deepEqual(parseScrapeNdjson(arr), [{ url: "https://x.com/a", content: "# A" }]);
});

test("crawl nativo: scrapeBatch sin dataset lanza error claro", async () => {
  await assert.rejects(() => new BrightDataCrawlClient({ apiToken: "tok", datasetId: null }).scrapeBatch(["https://x.com"]), /BRIGHT_DATA_CRAWL_DATASET_ID/);
});

test("crawl nativo: scrapeBatch arma /scrape?dataset_id + body {input:[...]} y parsea NDJSON", async () => {
  const orig = globalThis.fetch; let captured;
  globalThis.fetch = async (url, init) => { captured = { url, init }; return { ok: true, text: async () => JSON.stringify({ markdown: "# A", url: "https://acme.com/a" }) }; };
  try {
    const docs = await new BrightDataCrawlClient({ apiToken: "tok", datasetId: "gd_crawl" }).scrapeBatch(["https://acme.com/a"]);
    assert.match(captured.url, /\/datasets\/v3\/scrape\?/);
    assert.match(captured.url, /dataset_id=gd_crawl/);
    assert.deepEqual(JSON.parse(captured.init.body), { input: [{ url: "https://acme.com/a" }] });
    assert.deepEqual(docs, [{ url: "https://acme.com/a", content: "# A" }]);
  } finally { globalThis.fetch = orig; }
});

test("crawl nativo: crawlNative scrapea seed, descubre links internos y devuelve [{url,content}]", async () => {
  const orig = globalThis.fetch;
  const md = {
    "https://acme.com/": "# Home [a](https://acme.com/a) [b](https://acme.com/b) [ext](https://other.com/z)",
    "https://acme.com/a": "# A",
    "https://acme.com/b": "# B",
  };
  globalThis.fetch = async (_url, init) => {
    const urls = JSON.parse(init.body).input.map((i) => i.url);
    return { ok: true, text: async () => urls.map((u) => JSON.stringify({ markdown: md[u] ?? "", url: u })).join("\n") };
  };
  try {
    const docs = await new BrightDataCrawlClient({ apiToken: "tok", datasetId: "gd_crawl" }).crawlNative("https://acme.com/", { maxPages: 3 });
    assert.equal(docs[0].url, "https://acme.com/");                 // seed primero
    assert.deepEqual(docs.map((d) => d.url).sort(), ["https://acme.com/", "https://acme.com/a", "https://acme.com/b"]); // other.com excluido
    assert.equal(docs.find((d) => d.url === "https://acme.com/a").content, "# A");
  } finally { globalThis.fetch = orig; }
});

test("crawl LIVE: multi-página real (opt-in)", { skip: process.env.BD_LIVE !== "1" }, async () => {
  const docs = await crawlSite("https://en.wikipedia.org/wiki/Bright_Data", { maxPages: 2 });
  assert.ok(docs.length >= 1 && docs[0].content.length > 100);
});
