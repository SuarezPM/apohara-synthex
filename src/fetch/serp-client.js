// SERP (serverless) — búsqueda en Google vía la SERP API REST de Bright Data (HTTP puro, sin
// proceso MCP-stdio). Mismo endpoint que Web Unlocker (/request) pero con una zona dedicada de
// SERP y `brd_json=1` en la URL para obtener el SERP estructurado en JSON en vez del HTML crudo.
// Espejo de src/fetch/http-client.js: corre en Vercel/serverless, sin spawnear el brightdata-mcp.
const API_URL = "https://api.brightdata.com/request";

export class BrightDataSerpClient {
  constructor({ apiToken, zone } = {}) {
    this.apiToken = apiToken ?? process.env.BRIGHT_DATA_TOKEN ?? process.env.API_TOKEN ?? null;
    this.zone = zone ?? process.env.BRIGHT_DATA_SERP_ZONE ?? "serp_api1";
  }

  /**
   * Busca `query` en Google y devuelve el SERP. Por defecto JSON estructurado (brd_json=1);
   * con json=false devuelve el HTML crudo de la página de resultados.
   * @param {string} query
   * @param {{json?:boolean, country?:string, timeoutMs?:number}} opts
   * @returns {Promise<object|string>} JSON parseado (json=true) o HTML (json=false)
   */
  async search(query, { json = true, country, timeoutMs = 40000 } = {}) {
    if (!this.apiToken) throw new Error("Falta BRIGHT_DATA_TOKEN para la SERP API de Bright Data.");
    if (!query) throw new Error("SERP: falta el query de búsqueda.");
    let searchUrl = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
    if (country) searchUrl += `&gl=${encodeURIComponent(country)}`;
    if (json) searchUrl += "&brd_json=1";
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.apiToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ zone: this.zone, url: searchUrl, format: "raw" }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Bright Data SERP HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    const text = await res.text();
    if (!json) return text;
    try {
      return JSON.parse(text);
    } catch {
      throw new Error(`SERP: respuesta no es JSON (brd_json=1). Primeros 200: ${text.slice(0, 200)}`);
    }
  }
}

/**
 * Helper directo: instancia el cliente y busca. Espejo de la forma `serpSearch(query, opts)`.
 * @param {string} query
 * @param {{apiToken?:string, zone?:string, json?:boolean, country?:string, timeoutMs?:number}} opts
 */
export function serpSearch(query, opts = {}) {
  return new BrightDataSerpClient(opts).search(query, opts);
}
