// DATASET (serverless) — Bright Data Web Scraper / Datasets API: corre un scraper estructurado
// (dataset_id gd_...) sobre URLs y devuelve datos estructurados. Endpoint síncrono-ish
// /datasets/v3/scrape: dispara la colección y devuelve los resultados (o un snapshot_id a poolear).
//
// CUIDADO FACTURACIÓN: cada input es un scrape facturado. Límite duro MAX_INPUTS=2 y, en el path
// de poll, NO se hace espera larga (POLL por defecto desactivado) para no acumular costo en checks.
const SCRAPE_URL = "https://api.brightdata.com/datasets/v3/scrape";
const SNAPSHOT_URL = "https://api.brightdata.com/datasets/v3/snapshot";

const MAX_INPUTS = 2; // tope de seguridad de facturación

export class BrightDataDatasetClient {
  constructor({ apiToken, datasetId } = {}) {
    this.apiToken = apiToken ?? process.env.BRIGHT_DATA_TOKEN ?? process.env.API_TOKEN ?? null;
    this.datasetId = datasetId ?? process.env.BRIGHT_DATA_DATASET_ID ?? null;
  }

  #assertReady() {
    if (!this.apiToken) throw new Error("Falta BRIGHT_DATA_TOKEN para la Datasets API de Bright Data.");
    if (!this.datasetId) throw new Error("Falta BRIGHT_DATA_DATASET_ID para la Datasets API.");
  }

  /**
   * Dispara el scraper estructurado sobre `urls` (máx 2 por facturación). La API responde async:
   * o bien devuelve { snapshot_id } o bien los datos directamente, según el dataset.
   * @param {string|string[]} urls una URL o array de URLs (máx 2)
   * @param {{notify?:boolean, includeErrors?:boolean, timeoutMs?:number}} opts
   * @returns {Promise<object>} respuesta cruda (snapshot_id para poolear, o filas)
   */
  async scrape(urls, { notify = false, includeErrors = true, timeoutMs = 60000 } = {}) {
    this.#assertReady();
    const list = Array.isArray(urls) ? urls : [urls];
    if (list.length === 0) throw new Error("Dataset: hace falta al menos una URL.");
    if (list.length > MAX_INPUTS) {
      throw new Error(`Dataset: límite de seguridad de ${MAX_INPUTS} inputs (facturación). Recibidos: ${list.length}.`);
    }
    const qs = new URLSearchParams({
      dataset_id: this.datasetId,
      notify: String(notify),
      include_errors: String(includeErrors),
    });
    const res = await fetch(`${SCRAPE_URL}?${qs}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.apiToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ input: list.map((url) => ({ url })) }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Bright Data Dataset HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return res.json();
  }

  /** Baja un snapshot ya listo. Sin poll largo a propósito (el caller decide cuándo). */
  async snapshot(snapshotId, { format = "json", timeoutMs = 40000 } = {}) {
    this.#assertReady();
    const res = await fetch(`${SNAPSHOT_URL}/${snapshotId}?format=${encodeURIComponent(format)}`, {
      headers: { Authorization: `Bearer ${this.apiToken}` },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Bright Data Dataset snapshot HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return format === "json" ? res.json() : res.text();
  }
}
