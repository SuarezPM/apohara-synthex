// Check manual de FETCH: connect + listTools contra el brightdata-mcp real.
// Salida forzada (process.exit) porque el transport stdio deja el server hijo vivo.
import { BrightDataClient } from "../src/fetch/bright-data-client.js";

const c = new BrightDataClient();
try {
  await c.connect();
  const tools = await c.listTools();
  console.log("CONNECT OK — tools:", tools.map((t) => t.name).join(", "));
  await c.close();
  console.log("CLOSE OK");
} catch (e) {
  console.error("ERR:", e.message);
}
process.exit(0);
