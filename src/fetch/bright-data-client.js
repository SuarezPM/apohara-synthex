// FETCH — Synthex consume el brightdata-mcp como cliente MCP por stdio.
// NO reimplementa scraping: spawnea el server oficial de Bright Data y llama sus tools.
// Esta es la simbiosis hecha código: sin Bright Data, no hay datos.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
// Layout del workspace: apohara-synthex/ y brightdata-mcp/ son hermanos.
const DEFAULT_SERVER = resolve(__dirname, "../../../brightdata-mcp/server.js");

export class BrightDataClient {
  constructor({ apiToken, serverPath, zones } = {}) {
    this.apiToken = apiToken ?? process.env.BRIGHT_DATA_TOKEN ?? process.env.API_TOKEN ?? null;
    this.serverPath = serverPath ?? DEFAULT_SERVER;
    this.zones = zones ?? {};
    this.client = null;
    this.transport = null;
  }

  async connect() {
    if (!this.apiToken) {
      throw new Error("Falta el token de Bright Data: definí BRIGHT_DATA_TOKEN (o API_TOKEN).");
    }
    // El SDK no hereda todo el env por seguridad: partimos de getDefaultEnvironment() y añadimos lo de BD.
    const env = { ...getDefaultEnvironment(), API_TOKEN: this.apiToken };
    if (this.zones.webUnlocker) env.WEB_UNLOCKER_ZONE = this.zones.webUnlocker;
    if (this.zones.browser) env.BROWSER_ZONE = this.zones.browser;
    if (this.zones.proMode) env.PRO_MODE = "true";

    this.transport = new StdioClientTransport({ command: "node", args: [this.serverPath], env });
    this.client = new Client({ name: "apohara-synthex", version: "0.1.0" }, { capabilities: {} });
    await this.client.connect(this.transport);
    return this;
  }

  async listTools() {
    const { tools } = await this.client.listTools();
    return tools;
  }

  /** Llama una tool del brightdata-mcp por nombre. */
  async call(name, args = {}) {
    return this.client.callTool({ name, arguments: args });
  }

  // Helpers de alto nivel sobre las tools reales del brightdata-mcp.
  searchEngine(query, opts = {}) { return this.call("search_engine", { query, ...opts }); }
  scrapeMarkdown(url) { return this.call("scrape_as_markdown", { url }); }
  scrapeHtml(url) { return this.call("scrape_as_html", { url }); }
  scrapeBatch(urls, opts = {}) { return this.call("scrape_batch", { urls, ...opts }); }
  searchBatch(queries, opts = {}) { return this.call("search_engine_batch", { queries, ...opts }); }
  extract(url, opts = {}) { return this.call("extract", { url, ...opts }); }

  async close() {
    await this.client?.close?.();
    await this.transport?.close?.();
  }
}
