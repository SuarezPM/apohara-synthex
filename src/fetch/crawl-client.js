// CRAWL — recorre un sitio (seed → links internos → N páginas) y lo devuelve como markdown.
// Dos modos:
//  - DEFAULT (sin dataset extra): crawl multi-página REAL sobre el Web Unlocker REST de Bright Data
//    — scrapea el seed, extrae links internos del markdown, y scrapea hasta `maxPages` páginas del
//    mismo host. Funciona con BRIGHT_DATA_TOKEN + WEB_UNLOCKER_ZONE (lo que ya tenemos), serverless.
//  - NATIVO (opt-in): si hay BRIGHT_DATA_CRAWL_DATASET_ID (dataset gd_... de Crawl), usa la Crawl API
//    asíncrona (trigger → progress → snapshot). Preferido cuando esté configurado.
// HONESTIDAD: el modo default es "multi-page crawl vía Web Unlocker", no la Crawl API nativa —
// se etiqueta así. Ambos modos devuelven [{url, content}] para el pipeline.
import { BrightDataHttpClient } from "./http-client.js";

const TRIGGER_URL = "https://api.brightdata.com/datasets/v3/trigger";
const PROGRESS_URL = "https://api.brightdata.com/datasets/v3/progress";
const SNAPSHOT_URL = "https://api.brightdata.com/datasets/v3/snapshot";

/** Extrae links http(s) de un markdown: `[txt](url)` y `<url>`. */
export function extractLinks(markdown) {
  const out = new Set();
  for (const m of String(markdown ?? "").matchAll(/\]\((https?:\/\/[^)\s]+)\)/g)) out.add(m[1]);
  for (const m of String(markdown ?? "").matchAll(/<(https?:\/\/[^>\s]+)>/g)) out.add(m[1]);
  return [...out];
}

const ASSET = /\.(png|jpe?g|gif|svg|webp|css|js|ico|pdf|zip|mp4|woff2?)(\?|#|$)/i;

/** Filtra links al mismo host del seed, sin assets ni anchors duplicados. */
export function sameHostLinks(seedUrl, links) {
  let host;
  try { host = new URL(seedUrl).host; } catch { return []; }
  const seen = new Set(), out = [];
  for (const l of links) {
    try {
      const u = new URL(l);
      const clean = u.origin + u.pathname; // sin query/hash para dedup
      if (u.host !== host || ASSET.test(u.pathname) || seen.has(clean) || clean === new URL(seedUrl).origin + new URL(seedUrl).pathname) continue;
      seen.add(clean); out.push(clean);
    } catch { /* link inválido */ }
  }
  return out;
}

export class BrightDataCrawlClient {
  constructor({ apiToken, zone, datasetId } = {}) {
    this.apiToken = apiToken ?? process.env.BRIGHT_DATA_TOKEN ?? process.env.API_TOKEN ?? null;
    this.datasetId = datasetId ?? process.env.BRIGHT_DATA_CRAWL_DATASET_ID ?? null;
    this.http = new BrightDataHttpClient({ apiToken: this.apiToken, zone });
  }

  /**
   * Crawl multi-página vía Web Unlocker REST. Scrapea el seed, sigue links internos y devuelve
   * hasta `maxPages` documentos {url, content} del mismo host (el seed primero).
   * @param {string} seedUrl
   * @param {{maxPages?:number, dataFormat?:string, timeoutMs?:number}} opts
   * @returns {Promise<Array<{url:string, content:string}>>}
   */
  async crawl(seedUrl, { maxPages = 5, dataFormat = "markdown", timeoutMs = 40000 } = {}) {
    if (!this.apiToken) throw new Error("Falta BRIGHT_DATA_TOKEN para el crawl (Web Unlocker).");
    if (!/^https?:\/\//i.test(seedUrl)) throw new Error("Crawl: el seed debe ser una URL http(s).");
    const seed = await this.http.scrape(seedUrl, { dataFormat, timeoutMs });
    const docs = [{ url: seedUrl, content: seed }];
    const targets = sameHostLinks(seedUrl, extractLinks(seed)).slice(0, Math.max(0, maxPages - 1));
    for (const url of targets) {
      try { docs.push({ url, content: await this.http.scrape(url, { dataFormat, timeoutMs }) }); }
      catch { /* página individual falló → se omite, el crawl sigue (best-effort) */ }
    }
    return docs;
  }

  // ── Crawl API NATIVA (opt-in, requiere BRIGHT_DATA_CRAWL_DATASET_ID) ──
  async trigger(url, { includeErrors = true, outputFields = "markdown", timeoutMs = 40000 } = {}) {
    if (!this.datasetId) throw new Error("Falta BRIGHT_DATA_CRAWL_DATASET_ID para la Crawl API nativa.");
    const qs = new URLSearchParams({ dataset_id: this.datasetId, include_errors: String(includeErrors), custom_output_fields: outputFields });
    const res = await fetch(`${TRIGGER_URL}?${qs}`, {
      method: "POST", headers: { Authorization: `Bearer ${this.apiToken}`, "Content-Type": "application/json" },
      body: JSON.stringify([{ url }]), signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Bright Data Crawl trigger HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    const data = await res.json();
    const snapshotId = data?.snapshot_id ?? data?.id;
    if (!snapshotId) throw new Error(`Crawl: respuesta sin snapshot_id. ${JSON.stringify(data).slice(0, 200)}`);
    return snapshotId;
  }
  async progress(snapshotId, { timeoutMs = 20000 } = {}) {
    const res = await fetch(`${PROGRESS_URL}/${snapshotId}`, { headers: { Authorization: `Bearer ${this.apiToken}` }, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new Error(`Bright Data Crawl progress HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return res.json();
  }
  async snapshot(snapshotId, { format = "json", timeoutMs = 40000 } = {}) {
    const res = await fetch(`${SNAPSHOT_URL}/${snapshotId}?format=${encodeURIComponent(format)}`, { headers: { Authorization: `Bearer ${this.apiToken}` }, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new Error(`Bright Data Crawl snapshot HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return format === "json" ? res.json() : res.text();
  }
}

/** Helper: crawl multi-página → [{url, content}]. Espejo de la forma de los otros fetchers. */
export function crawlSite(seedUrl, opts = {}) {
  return new BrightDataCrawlClient(opts).crawl(seedUrl, opts);
}
