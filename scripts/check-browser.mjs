// De-risk del FETCH browser real: conecta por CDP al Scraping Browser de Bright Data,
// scrapea un URL JS-renderizado y muestra el contenido devuelto. HONESTIDAD VERIFICABLE:
// si la conexión CDP falla, reporta el error tal cual (no simula).
// Uso: set -a; source ~/.config/apohara/secrets.env; set +a; node scripts/check-browser.mjs [url]
import { browserFetch } from "../src/fetch/browser-client.js";

const url = process.argv[2] || "https://example.com";
const wss = process.env.BRIGHT_DATA_BROWSER_WSS;

console.log("BRIGHT_DATA_BROWSER_WSS presente:", Boolean(wss));
if (wss) console.log("endpoint (masked):", wss.replace(/(wss?:\/\/)[^@]*@/, "$1***@"));

try {
  console.log(`conectando CDP y scrapeando ${url} ...`);
  const t0 = Date.now();
  const { url: finalUrl, content } = await browserFetch(url);
  const ms = Date.now() - t0;
  console.log(`OK en ${ms}ms`);
  console.log("final url:", finalUrl);
  console.log("content length:", content.length);
  console.log("content (300):", JSON.stringify(content.slice(0, 300)));
} catch (e) {
  console.error("ERR:", e.message);
  process.exitCode = 1;
}
