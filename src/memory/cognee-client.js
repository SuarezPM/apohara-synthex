// Cognee — memoria/knowledge-graph (OSS self-hosted) consumido vía su MCP server local.
// Synthex (JS) habla con el cognee MCP como cliente stdio, igual que con brightdata-mcp.
// Cumple el challenge "Best Use of Agent Memory with Cognee" usando Cognee OSS (no la cloud
// de pago). Comando del MCP: uv run --directory ~/.cognee/cognee-mcp cognee-mcp --transport stdio
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { homedir } from "node:os";
import { join } from "node:path";

const DEFAULT_COGNEE_DIR = process.env.COGNEE_MCP_DIR || join(homedir(), ".cognee/cognee-mcp");

export class CogneeClient {
  constructor({ cogneeDir = DEFAULT_COGNEE_DIR, env = {} } = {}) {
    this.cogneeDir = cogneeDir;
    this.extraEnv = env;
    this.client = null;
    this.transport = null;
  }

  /** Arranca el cognee MCP local y conecta. NOTA: la primera conexión es lenta (uv + carga de modelos).
   *  PM-2 guard (T0.4): si COGNEE_REMOTE_URL está set, abort — el cliente es estrictamente local
   *  para que el stress test nunca filtre contenido scrapeado a un endpoint remoto por accidente. */
  async connect() {
    if (process.env.COGNEE_REMOTE_URL) {
      throw new Error(
        `COGNEE_REMOTE_URL is set ("${process.env.COGNEE_REMOTE_URL}"). ` +
        `Synthex CogneeClient is strictly local (stdio MCP). ` +
        `Unset the variable, or use a separate cloud client explicitly.`,
      );
    }
    this.transport = new StdioClientTransport({
      command: "uv",
      args: ["run", "--directory", this.cogneeDir, "cognee-mcp", "--transport", "stdio"],
      // El cognee MCP necesita su config (LLM MiniMax, embeddings, DBs) del entorno del usuario.
      env: { ...getDefaultEnvironment(), ...process.env, ...this.extraEnv },
    });
    this.client = new Client({ name: "apohara-synthex", version: "0.1.0" }, { capabilities: {} });
    await this.client.connect(this.transport);
    return this;
  }

  async listTools() { return (await this.client.listTools()).tools; }
  async call(name, args = {}) { return this.client.callTool({ name, arguments: args }); }

  // Tools reales del cognee MCP (verificadas live + en su server.py): remember/recall/forget.
  /** Ingerir datos al knowledge graph (tool MCP: remember(data, dataset_name?, session_id?)). */
  remember(data, opts = {}) { return this.call("remember", { data, ...opts }); }
  /** Consultar la memoria/grafo (tool MCP: recall(query, search_type?, datasets?)). */
  recall(query, opts = {}) { return this.call("recall", { query, ...opts }); }
  /** Olvidar del grafo (tool MCP: forget). */
  forget(args = {}) { return this.call("forget", args); }

  async close() {
    await this.client?.close?.();
    await this.transport?.close?.();
  }
}

// ─── Cognee CLOUD client (opt-in, roadmap R6) ──────────────────────────────
//
// Local OSS (above) stays the DEFAULT. The cloud backend is an EXPLICIT opt-in (COGNEE_CLOUD=1)
// and is a SEPARATE, distinct path from the COGNEE_REMOTE_URL guard on the local client — that
// guard is preserved verbatim (the local CogneeClient still hard-aborts if COGNEE_REMOTE_URL is
// set; this class does not negate it). Gate-before-trust (probed live 2026-05-30): the tenant REST
// API `https://tenant-<id>.aws.cognee.ai` answers JSON with `X-Api-Key` + `X-Tenant-Id`
// (/api/v1/{add_text,cognify,search,datasets}). Same remember/recall/forget interface as the local
// client so callers (sinks.js) are backend-agnostic. The CaMeL gate in sinks.js still decides
// WHETHER to ingest — a REVIEW'd source is never sent to ANY backend, cloud included. No backend is
// part of the sealed evidence (memory is a graph index over it, never the attestation).
const DEFAULT_COGNEE_DATASET = process.env.COGNEE_DATASET || "synthex";

export class CogneeCloudClient {
  constructor({ apiUrl, tenantId, apiKey, dataset, fetchImpl } = {}) {
    this.apiUrl = (apiUrl ?? process.env.COGNEE_API_URL ?? "").replace(/\/+$/, "");
    this.tenantId = tenantId ?? process.env.COGNEE_TENANT_ID ?? null;
    this.apiKey = apiKey ?? process.env.COGNEE_API_KEY ?? null;
    this.dataset = dataset ?? DEFAULT_COGNEE_DATASET;
    this.fetchImpl = fetchImpl ?? fetch;
  }

  #assertReady() {
    if (!this.apiUrl) throw new Error("CogneeCloudClient: falta COGNEE_API_URL (tenant base, p.ej. https://tenant-<id>.aws.cognee.ai).");
    if (!this.apiKey) throw new Error("CogneeCloudClient: falta COGNEE_API_KEY.");
    if (!this.tenantId) throw new Error("CogneeCloudClient: falta COGNEE_TENANT_ID.");
  }

  #headers(json = true) {
    const h = { "X-Api-Key": this.apiKey, "X-Tenant-Id": this.tenantId };
    if (json) h["Content-Type"] = "application/json";
    return h;
  }

  async #req(method, path, body, { timeoutMs = 30000 } = {}) {
    this.#assertReady();
    const res = await this.fetchImpl(`${this.apiUrl}${path}`, {
      method,
      headers: this.#headers(body !== undefined),
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Cognee cloud HTTP ${res.status} on ${method} ${path}: ${(await res.text()).slice(0, 200)}`);
    const ct = res.headers?.get?.("content-type") || "";
    return ct.includes("json") ? res.json() : res.text();
  }

  /** Health/auth check (parity with the local connect()). Returns this. */
  async connect() {
    await this.#req("GET", "/api/health");
    return this;
  }

  /** List datasets (read-only) — also the cheapest live auth probe. */
  datasets() { return this.#req("GET", "/api/v1/datasets/"); }

  /**
   * Ingest text into the knowledge graph (add_text → cognify). cognify builds the graph (LLM cost);
   * runInBackground:true (default) returns without blocking on the build. Mirrors local remember().
   * @param {string} data
   * @param {{dataset?:string, runInBackground?:boolean, skipCognify?:boolean}} [opts]
   */
  async remember(data, opts = {}) {
    const datasetName = opts.dataset ?? this.dataset;
    const add = await this.#req("POST", "/api/v1/add_text", { textData: [String(data ?? "")], datasetName });
    if (opts.skipCognify) return { add, cognify: null };
    const cognify = await this.#req("POST", "/api/v1/cognify", {
      datasets: [datasetName],
      runInBackground: opts.runInBackground ?? true,
    });
    return { add, cognify };
  }

  /**
   * Query the graph (search). Mirrors local recall().
   * @param {string} query
   * @param {{searchType?:string, datasets?:string[]}} [opts]
   */
  recall(query, opts = {}) {
    return this.#req("POST", "/api/v1/search", {
      query: String(query ?? ""),
      searchType: opts.searchType ?? "GRAPH_COMPLETION",
      datasets: opts.datasets ?? [this.dataset],
    });
  }

  /** Delete a dataset from the graph (forget). Mirrors local forget(). async so a bad-input
   *  throw surfaces as a rejected promise (consistent async contract). */
  async forget({ datasetId } = {}) {
    if (!datasetId) throw new Error("CogneeCloudClient.forget: datasetId requerido.");
    return this.#req("DELETE", `/api/v1/datasets/${encodeURIComponent(datasetId)}`);
  }

  async close() { /* REST is stateless — nothing to close (parity with local client). */ }
}
