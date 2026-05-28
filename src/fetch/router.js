// ROUTER multi-API — un fetcher único, compatible con runPipeline, que decide QUÉ API de Bright
// Data usar para cada target. Devuelve siempre [{url, content}] (el shape que el pipeline espera).
//
// Routing por opts.mode explícito; si no, heurística:
//   · término (no-URL)          → SERP API (búsqueda en Google, JSON estructurado → texto)
//   · URL + mode "browser"      → Scraping Browser (CDP) — sitios JS-heavy / SPAs
//   · URL + mode "crawl"        → crawl multi-página sobre Web Unlocker (seed → links internos → N)
//   · URL + mode "dataset"      → Datasets API (scraper estructurado)
//   · URL (default)             → Web Unlocker REST (httpFetcher)
import { serpSearch } from "./serp-client.js";
import { browserFetch } from "./browser-client.js";
import { httpFetcher } from "./http-client.js";
import { BrightDataCrawlClient } from "./crawl-client.js";
import { BrightDataDatasetClient } from "./dataset-client.js";

const isUrl = (s) => /^https?:\/\//i.test(s);

/** SERP JSON estructurado → texto clasificable (title + snippet de cada resultado orgánico). */
function serpToText(serp) {
  const organic = Array.isArray(serp?.organic) ? serp.organic : [];
  return organic
    .map((r) => [r?.title, r?.snippet].filter(Boolean).join(" — "))
    .filter(Boolean)
    .join("\n");
}

/**
 * Crea un fetcher(target) → [{url, content}] que enruta a la API de Bright Data adecuada.
 * @param {{mode?:"serp"|"browser"|"crawl"|"dataset"|"http", jsHeavy?:boolean, [k:string]:any}} opts
 *   `mode` fuerza el routing; el resto de opts se propaga al cliente elegido.
 * @returns {(target:string)=>Promise<Array<{url:string,content:string}>>}
 */
export function smartFetcher(opts = {}) {
  return async (target) => {
    const mode = opts.mode;

    // 1. Término (no-URL) o mode "serp" explícito → SERP API.
    if (mode === "serp" || (!mode && !isUrl(target))) {
      const serp = await serpSearch(target, opts);
      return [{ url: `serp:${target}`, content: serpToText(serp) }];
    }

    // 2. URL + browser (mode explícito o jsHeavy) → Scraping Browser (CDP).
    if (mode === "browser" || (!mode && opts.jsHeavy)) {
      const { url, content } = await browserFetch(target, opts);
      return [{ url, content }];
    }

    // 3. URL + crawl → crawl multi-página sobre Web Unlocker (seed → links internos → N páginas).
    if (mode === "crawl") {
      return new BrightDataCrawlClient(opts).crawl(target, opts); // [{url, content}] del mismo host
    }

    // 4. URL + dataset → Datasets API (scraper estructurado).
    if (mode === "dataset") {
      const client = new BrightDataDatasetClient(opts); // sin datasetId → lanza error honesto
      const res = await client.scrape([target], opts);
      const rows = Array.isArray(res) ? res : [res];
      return rows.map((row) => ({
        url: row?.url ?? target,
        content: typeof row?.markdown === "string" ? row.markdown : JSON.stringify(row),
      }));
    }

    // 5. Default URL → Web Unlocker REST.
    return httpFetcher(opts)(target);
  };
}
