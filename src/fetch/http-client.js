// FETCH (serverless) — scrape vía la API REST de Bright Data Web Unlocker (HTTP puro, sin
// proceso MCP-stdio). Misma simbiosis ("sin Bright Data, no hay datos") pero por el endpoint
// REST en vez del MCP local: así el pipeline COMPLETO corre en Vercel/serverless, donde no se
// puede spawnear el brightdata-mcp. Para CLI/MCP local seguimos usando BrightDataClient (stdio).
const API_URL = "https://api.brightdata.com/request";

export class BrightDataHttpClient {
  constructor({ apiToken, zone } = {}) {
    this.apiToken = apiToken ?? process.env.BRIGHT_DATA_TOKEN ?? process.env.API_TOKEN ?? null;
    this.zone = zone ?? process.env.WEB_UNLOCKER_ZONE ?? "web_unlocker1";
  }

  /** Scrapea una URL vía Web Unlocker REST. data_format="markdown" devuelve texto limpio. */
  async scrape(url, { dataFormat = "markdown", timeoutMs = 40000 } = {}) {
    if (!this.apiToken) throw new Error("Falta BRIGHT_DATA_TOKEN para el fetch HTTP de Bright Data.");
    const body = { zone: this.zone, url, format: "raw" };
    if (dataFormat) body.data_format = dataFormat;
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.apiToken}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Bright Data REST HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return res.text();
  }
}

/**
 * Fetcher compatible con runPipeline (serverless). Si el target es URL → scrape directo;
 * si es término → scrapea la SERP de Google vía Web Unlocker (un doc con los resultados).
 * @param {{apiToken?:string, zone?:string, dataFormat?:string, timeoutMs?:number}} opts
 */
export function httpFetcher(opts = {}) {
  const client = new BrightDataHttpClient(opts);
  return async (target) => {
    if (/^https?:\/\//i.test(target)) {
      return [{ url: target, content: await client.scrape(target, opts) }];
    }
    const serp = `https://www.google.com/search?q=${encodeURIComponent(target)}`;
    return [{ url: serp, content: await client.scrape(serp, opts) }];
  };
}
