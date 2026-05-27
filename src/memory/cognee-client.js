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

  /** Arranca el cognee MCP local y conecta. NOTA: la primera conexión es lenta (uv + carga de modelos). */
  async connect() {
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
