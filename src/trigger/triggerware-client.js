// TriggerWare — cliente de la API real (verificada: GET /triggers → 200).
// Triggerware es un motor de "base de datos virtual" sobre connectors externos, con
// TRIGGERS: queries en schedule que acumulan deltas (added/deleted) y se consumen por poll.
// Eso es el monitoreo continuo de Synthex: creás un trigger en lenguaje natural, hacés poll
// y disparás el pipeline cuando aparecen filas nuevas.
//
// Auth: header `Api-Key: <key>`. Base: https://api.triggerware.com
const DEFAULT_BASE = process.env.TRIGGERWARE_BASE_URL || "https://api.triggerware.com";

export class TriggerWareClient {
  constructor({ apiKey = process.env.TRIGGERWARE_API_KEY, baseUrl = DEFAULT_BASE } = {}) {
    this.apiKey = apiKey ?? null;
    this.baseUrl = baseUrl;
    this.configured = Boolean(this.apiKey);
  }

  async _req(method, path, body) {
    if (!this.apiKey) throw new Error("Falta TRIGGERWARE_API_KEY.");
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: { "Api-Key": this.apiKey, ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) throw new Error(`Triggerware HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  }

  // --- Triggers (verificados en la doc) ---
  /** GET /triggers → lista de triggers. (Verificado: 200.) */
  listTriggers() { return this._req("GET", "/triggers"); }

  /** POST /triggers — crea un trigger desde lenguaje natural. body p.ej. {description, schedule}.
   *  NOTA: la doc muestra la respuesta (name/query/schedule/status) pero no el shape exacto del
   *  request; se envía el objeto tal cual para no fabricar nombres de campos. */
  createTrigger(body) { return this._req("POST", "/triggers", body); }

  /** POST /triggers/{name}/poll → {added:[...], deleted:[...]}. Cada poll limpia la cola. */
  poll(name) { return this._req("POST", `/triggers/${encodeURIComponent(name)}/poll`); }

  /** PATCH /triggers/{name} — actualiza query/schedule/status. */
  updateTrigger(name, patch) { return this._req("PATCH", `/triggers/${encodeURIComponent(name)}`, patch); }

  /** DELETE /triggers/{name}. */
  deleteTrigger(name) { return this._req("DELETE", `/triggers/${encodeURIComponent(name)}`); }

  // --- Query (English→SQL o SQL directo sobre connectors instalados) ---
  /** POST /query → {sql, signature, rows}. language: "english" (default) | "sql". */
  query(text, { language = "english" } = {}) { return this._req("POST", "/query", { query: text, language }); }

  /** GET /connectors/installed → connectors instalados en la instancia. */
  listConnectors() { return this._req("GET", "/connectors/installed"); }
}
