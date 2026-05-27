// Smoke del servidor MCP de Synthex: lo arranca por stdio y lista sus tools.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const serverPath = resolve(__dirname, "../server.js");
const transport = new StdioClientTransport({
  command: "node",
  args: [serverPath],
  env: { ...getDefaultEnvironment(), ...process.env },
});
const client = new Client({ name: "smoke", version: "0" }, { capabilities: {} });
try {
  await client.connect(transport);
  const { tools } = await client.listTools();
  console.log("SERVER OK — tools:", tools.map((t) => t.name).join(", "));
  await client.close();
} catch (e) {
  console.error("ERR:", e.message);
}
process.exit(0);
