// De-risk del FETCH real: scrapea un URL vía Bright Data y muestra el formato del resultado.
import { BrightDataClient } from "../src/fetch/bright-data-client.js";
import { mcpText } from "../src/pipeline.js";

const url = process.argv[2] || "https://example.com";
const c = new BrightDataClient();
try {
  console.log(`scrapeando ${url} ...`);
  await c.connect();
  const res = await c.scrapeMarkdown(url);
  const text = mcpText(res);
  console.log("result keys:", Object.keys(res || {}));
  console.log("content isArray:", Array.isArray(res?.content), "| len:", res?.content?.length);
  console.log("content[0]:", JSON.stringify(res?.content?.[0])?.slice(0, 300));
  console.log("RAW (800):", JSON.stringify(res)?.slice(0, 800));
  console.log("mcpText length:", text.length);
  await c.close();
} catch (e) {
  console.error("ERR:", e.message);
}
process.exit(0);
