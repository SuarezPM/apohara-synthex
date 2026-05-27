// CRAWL (serverless) — Bright Data Crawl API: mapea/extrae un sitio entero a markdown vía REST.
// Es ASÍNCRONA: POST a /datasets/v3/trigger con un dataset_id de Crawl → devuelve snapshot_id;
// luego se monitorea con GET /datasets/v3/progress/{id} y se baja con GET /datasets/v3/snapshot/{id}.
// Ref: https://docs.brightdata.com/scraping-automation/crawl-api/quick-start
//
// HONESTIDAD VERIFICABLE: el Crawl API necesita un dataset_id de Crawl propio (gd_...), distinto
// del BRIGHT_DATA_DATASET_ID del scraper. Si no está configurado (BRIGHT_DATA_CRAWL_DATASET_ID),
// el cliente lanza error claro en vez de fingir que funciona. El check de scripts/ reporta FAIL.
const TRIGGER_URL = "https://api.brightdata.com/datasets/v3/trigger";
const PROGRESS_URL = "https://api.brightdata.com/datasets/v3/progress";
const SNAPSHOT_URL = "https://api.brightdata.com/datasets/v3/snapshot";

export class BrightDataCrawlClient {
  constructor({ apiToken, datasetId } = {}) {
    this.apiToken = apiToken ?? process.env.BRIGHT_DATA_TOKEN ?? process.env.API_TOKEN ?? null;
    this.datasetId = datasetId ?? process.env.BRIGHT_DATA_CRAWL_DATASET_ID ?? null;
  }

  #assertReady() {
    if (!this.apiToken) throw new Error("Falta BRIGHT_DATA_TOKEN para la Crawl API de Bright Data.");
    if (!this.datasetId) throw new Error("Falta BRIGHT_DATA_CRAWL_DATASET_ID (dataset gd_... de Crawl) para la Crawl API.");
  }

  /**
   * Dispara un crawl de `url` y devuelve el snapshot_id (no espera a que termine).
   * @param {string} url
   * @param {{includeErrors?:boolean, outputFields?:string, timeoutMs?:number}} opts
   * @returns {Promise<string>} snapshot_id
   */
  async trigger(url, { includeErrors = true, outputFields = "markdown", timeoutMs = 40000 } = {}) {
    this.#assertReady();
    if (!url) throw new Error("Crawl: falta la URL a crawlear.");
    const qs = new URLSearchParams({
      dataset_id: this.datasetId,
      include_errors: String(includeErrors),
      custom_output_fields: outputFields,
    });
    const res = await fetch(`${TRIGGER_URL}?${qs}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.apiToken}`, "Content-Type": "application/json" },
      body: JSON.stringify([{ url }]),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Bright Data Crawl trigger HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    const data = await res.json();
    const snapshotId = data?.snapshot_id ?? data?.id;
    if (!snapshotId) throw new Error(`Crawl: respuesta sin snapshot_id. ${JSON.stringify(data).slice(0, 200)}`);
    return snapshotId;
  }

  /** Consulta el estado de un snapshot. Devuelve { status, ... } (ej. running|ready|failed). */
  async progress(snapshotId, { timeoutMs = 20000 } = {}) {
    this.#assertReady();
    const res = await fetch(`${PROGRESS_URL}/${snapshotId}`, {
      headers: { Authorization: `Bearer ${this.apiToken}` },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Bright Data Crawl progress HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return res.json();
  }

  /** Baja los resultados de un snapshot ya listo (array de filas con el campo markdown). */
  async snapshot(snapshotId, { format = "json", timeoutMs = 40000 } = {}) {
    this.#assertReady();
    const res = await fetch(`${SNAPSHOT_URL}/${snapshotId}?format=${encodeURIComponent(format)}`, {
      headers: { Authorization: `Bearer ${this.apiToken}` },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Bright Data Crawl snapshot HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return format === "json" ? res.json() : res.text();
  }
}
