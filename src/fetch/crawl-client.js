// CRAWL — recorre un sitio (seed → links internos → N páginas) y lo devuelve como markdown.
// Dos modos, ambos devuelven [{url, content}] para el pipeline:
//  - DEFAULT (Web Unlocker): scrapea el seed, extrae links internos del markdown y scrapea hasta
//    `maxPages` páginas del mismo host vía Web Unlocker REST. Solo necesita BRIGHT_DATA_TOKEN
//    (+ WEB_UNLOCKER_ZONE). Serverless.
//  - NATIVO (opt-in, preferido): si hay BRIGHT_DATA_CRAWL_DATASET_ID, la extracción de contenido
//    usa la Crawl API REAL de Bright Data (POST /datasets/v3/scrape, síncrono → markdown). El
//    descubrimiento de links internos sigue siendo nuestro (sobre el markdown del seed).
// HONESTIDAD: en modo nativo el contenido SÍ sale del Crawl API de Bright Data (no Web Unlocker);
// el discovery del dominio es nuestro. El modo default se etiqueta como "crawl vía Web Unlocker".
import { BrightDataHttpClient } from "./http-client.js";

const SCRAPE_URL = "https://api.brightdata.com/datasets/v3/scrape";

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

/**
 * Parsea la respuesta del Crawl API (/scrape) → [{url, content}], quedándose solo con las páginas
 * que trajeron markdown. La API responde NDJSON (una línea JSON por URL) o, a veces, un JSON array;
 * las páginas muertas vuelven como objeto con `warning_code` (sin markdown) y se omiten.
 */
export function parseScrapeNdjson(text) {
  const out = [];
  const push = (o) => {
    if (o && typeof o.markdown === "string" && o.markdown) out.push({ url: o.url ?? o.input?.url ?? "", content: o.markdown });
  };
  const trimmed = String(text ?? "").trim();
  if (!trimmed) return out;
  try {
    const parsed = JSON.parse(trimmed); // ¿array u objeto único?
    if (Array.isArray(parsed)) { parsed.forEach(push); return out; }
    if (parsed && typeof parsed === "object") { push(parsed); return out; }
  } catch { /* no es un JSON único → tratar como NDJSON línea-por-línea */ }
  for (const line of trimmed.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try { push(JSON.parse(t)); } catch { /* línea no-JSON → omitir */ }
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

  // ── Crawl API NATIVA de Bright Data (opt-in, requiere BRIGHT_DATA_CRAWL_DATASET_ID) ──

  /**
   * Scrapea un batch de URLs vía POST /datasets/v3/scrape (síncrono) → [{url, content:markdown}].
   * include_errors=true: las páginas muertas vuelven como warning (sin markdown) y parseScrapeNdjson
   * las omite. Best-effort: devuelve lo que haya traído markdown.
   */
  async scrapeBatch(urls, { timeoutMs = 60000 } = {}) {
    if (!this.datasetId) throw new Error("Falta BRIGHT_DATA_CRAWL_DATASET_ID para la Crawl API nativa.");
    if (!this.apiToken) throw new Error("Falta BRIGHT_DATA_TOKEN para la Crawl API nativa.");
    const qs = new URLSearchParams({ dataset_id: this.datasetId, notify: "false", include_errors: "true" });
    const res = await fetch(`${SCRAPE_URL}?${qs}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.apiToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ input: urls.map((url) => ({ url })) }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Bright Data Crawl scrape HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return parseScrapeNdjson(await res.text());
  }

  /**
   * Crawl nativo: scrapea el seed vía Crawl API, descubre links internos del markdown del seed y
   * scrapea el resto en un solo batch. Devuelve [{url, content}] (el seed primero), mismo shape
   * que crawl(). Se usa cuando hay BRIGHT_DATA_CRAWL_DATASET_ID configurado.
   */
  async crawlNative(seedUrl, { maxPages = 5, timeoutMs = 60000 } = {}) {
    if (!/^https?:\/\//i.test(seedUrl)) throw new Error("Crawl: el seed debe ser una URL http(s).");
    const seedDocs = await this.scrapeBatch([seedUrl], { timeoutMs });
    const seedMd = seedDocs.find((d) => d.url === seedUrl)?.content ?? seedDocs[0]?.content ?? "";
    const targets = sameHostLinks(seedUrl, extractLinks(seedMd)).slice(0, Math.max(0, maxPages - 1));
    const rest = targets.length ? await this.scrapeBatch(targets, { timeoutMs }) : [];
    const seen = new Set(), docs = [];
    for (const d of [...seedDocs, ...rest]) {
      if (d.content && !seen.has(d.url)) { seen.add(d.url); docs.push(d); }
    }
    return docs;
  }
}

/** Helper: crawl multi-página (Web Unlocker) → [{url, content}]. Espejo de los otros fetchers. */
export function crawlSite(seedUrl, opts = {}) {
  return new BrightDataCrawlClient(opts).crawl(seedUrl, opts);
}
