// De-risk de Cognee live: arranca el cognee MCP local (con su config MiniMax+fastembed) y
// lista sus tools reales. Confirma los nombres antes de confiar en cognify/search.
import { CogneeClient } from "../src/memory/cognee-client.js";

const cogneeEnv = {
  LLM_PROVIDER: "custom",
  LLM_MODEL: "openai/MiniMax-M2.7",
  LLM_ENDPOINT: "https://api.minimax.io/v1",
  LLM_API_KEY: process.env.MINIMAX_API_KEY,
  LLM_MAX_TOKENS: "16384",
  EMBEDDING_PROVIDER: "fastembed",
  EMBEDDING_MODEL: "sentence-transformers/paraphrase-multilingual-mpnet-base-v2",
  EMBEDDING_DIMENSIONS: "768",
  DB_PROVIDER: "sqlite",
  VECTOR_DB_PROVIDER: "lancedb",
};

const c = new CogneeClient({ env: cogneeEnv });
try {
  console.log("conectando al cognee MCP (uv + carga de modelos, puede tardar)...");
  await c.connect();
  const tools = await c.listTools();
  console.log("COGNEE tools:", tools.map((t) => t.name).join(", "));
  await c.close();
  console.log("OK");
} catch (e) {
  console.error("ERR:", e.message);
}
process.exit(0);
