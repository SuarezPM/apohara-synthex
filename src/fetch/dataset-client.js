// DATASET (serverless) — Bright Data Web Scraper / Datasets API: corre un scraper estructurado
// (dataset_id gd_...) sobre URLs y devuelve datos estructurados. Endpoint síncrono-ish
// /datasets/v3/scrape: dispara la colección y devuelve los resultados (o un snapshot_id a poolear).
//
// CUIDADO FACTURACIÓN: cada input es un scrape facturado. Límite duro MAX_INPUTS=2 y, en el path
// de poll, NO se hace espera larga (POLL por defecto desactivado) para no acumular costo en checks.
const SCRAPE_URL = "https://api.brightdata.com/datasets/v3/scrape";
const SNAPSHOT_URL = "https://api.brightdata.com/datasets/v3/snapshot";
const TRIGGER_URL = "https://api.brightdata.com/datasets/v3/trigger"; // async collect (item 2.7)
const PROGRESS_URL = "https://api.brightdata.com/datasets/v3/progress"; // snapshot status (item 2.7)

const MAX_INPUTS = 2; // tope de seguridad de facturación

export class BrightDataDatasetClient {
  constructor({ apiToken, datasetId, fetchImpl } = {}) {
    this.apiToken = apiToken ?? process.env.BRIGHT_DATA_TOKEN ?? process.env.API_TOKEN ?? null;
    this.datasetId = datasetId ?? process.env.BRIGHT_DATA_DATASET_ID ?? null;
    // Inyectable para tests sin red ni facturación (default: fetch global).
    this.fetchImpl = fetchImpl ?? fetch;
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
    const res = await this.fetchImpl(`${SCRAPE_URL}?${qs}`, {
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
    const res = await this.fetchImpl(`${SNAPSHOT_URL}/${snapshotId}?format=${encodeURIComponent(format)}`, {
      headers: { Authorization: `Bearer ${this.apiToken}` },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Bright Data Dataset snapshot HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return format === "json" ? res.json() : res.text();
  }

  // ─── Async collect: trigger → poll progress → fetch snapshot (item 2.7, D8) ──────────
  //
  // The /scrape path above is the synchronous-ish call. The Web Scraper API's real async flow is
  // trigger (returns snapshot_id) → poll progress until "ready" → fetch the snapshot. This path
  // also supports `type=discover_new` (a pre-built discovery collector finds NEW items from a
  // seed instead of scraping fixed URLs) — the watchlist→discover_new→delta source for the react
  // loop (2.4) and Scene 3. MAX_INPUTS is a hard BILLING cap; the poll is bounded (no infinite loop).

  /**
   * Trigger an async dataset collection. `type:"discover_new"` runs the dataset's discovery
   * collector over the seed input(s); otherwise it's a normal URL trigger. Returns {snapshot_id}.
   * @param {object|object[]} input  seed input object(s) for the collector (máx MAX_INPUTS).
   * @param {{type?:string, discoverBy?:string, notify?:boolean, includeErrors?:boolean, timeoutMs?:number}} opts
   * @returns {Promise<{snapshot_id:string}>}
   */
  async trigger(input, { type, discoverBy, notify = false, includeErrors = true, timeoutMs = 60000 } = {}) {
    this.#assertReady();
    const list = Array.isArray(input) ? input : [input];
    if (list.length === 0) throw new Error("Dataset trigger: hace falta al menos un input.");
    if (list.length > MAX_INPUTS) {
      throw new Error(`Dataset trigger: límite de seguridad de ${MAX_INPUTS} inputs (facturación). Recibidos: ${list.length}.`);
    }
    const qs = new URLSearchParams({ dataset_id: this.datasetId, notify: String(notify), include_errors: String(includeErrors) });
    if (type) qs.set("type", type); // e.g. "discover_new"
    if (discoverBy) qs.set("discover_by", discoverBy);
    const res = await this.fetchImpl(`${TRIGGER_URL}?${qs}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.apiToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ input: list }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Bright Data Dataset trigger HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return res.json();
  }

  /** triggerDiscoverNew — convenience wrapper for the discovery collector path. */
  triggerDiscoverNew(input, opts = {}) {
    return this.trigger(input, { ...opts, type: "discover_new" });
  }

  /** GET progress of a snapshot → {status:"running"|"ready"|"failed", ...}. Single check, no wait. */
  async pollProgress(snapshotId, { timeoutMs = 20000 } = {}) {
    this.#assertReady();
    const res = await this.fetchImpl(`${PROGRESS_URL}/${snapshotId}`, {
      headers: { Authorization: `Bearer ${this.apiToken}` },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Bright Data Dataset progress HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return res.json();
  }

  /**
   * Poll until the snapshot is "ready" (BOUNDED — never infinite; cost-capped), then fetch it.
   * Returns the sealed-ready envelope: {snapshotId, surface, datasetId, fetchedAt, rows}.
   * @param {string} snapshotId
   * @param {{maxAttempts?:number, intervalMs?:number, format?:string, sleep?:Function}} opts
   */
  async collect(snapshotId, { maxAttempts = 10, intervalMs = 3000, format = "json", sleep } = {}) {
    const wait = sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms))); // injectable for tests
    let status = null;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const p = await this.pollProgress(snapshotId);
      status = String(p?.status ?? "").toLowerCase();
      if (status === "ready") {
        const rows = await this.snapshot(snapshotId, { format });
        return {
          snapshotId,
          surface: "datasets/v3/discover_new",
          datasetId: this.datasetId,
          fetchedAt: new Date().toISOString(),
          rows,
        };
      }
      if (status === "failed" || status === "error") {
        throw new Error(`Bright Data Dataset snapshot ${snapshotId} failed (status="${status}").`);
      }
      if (attempt < maxAttempts - 1) await wait(intervalMs);
    }
    throw new Error(`Bright Data Dataset snapshot ${snapshotId} not ready after ${maxAttempts} polls (status="${status}"). Bounded by cost cap.`);
  }
}
