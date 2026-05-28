// De-risk LIVE de las 3 APIs REST de Bright Data: SERP, Crawl y Dataset.
// Reporta OK/FAIL honesto por cada una (HONESTIDAD VERIFICABLE: solo OK si la API respondió de
// verdad). CUIDADO FACTURACIÓN: SERP = 1 búsqueda; Dataset = 1 input, solo trigger (sin poll);
// Crawl = 1 trigger si hay dataset de crawl configurado, si no FAIL honesto sin tocar la red.
//
// Uso: set -a; source ~/.config/apohara/secrets.env; set +a; node scripts/check-bd-apis.mjs
import { BrightDataSerpClient } from "../src/fetch/serp-client.js";
import { BrightDataCrawlClient } from "../src/fetch/crawl-client.js";
import { BrightDataDatasetClient } from "../src/fetch/dataset-client.js";

function ok(name, detail) { console.log(`OK   ${name} — ${detail}`); }
function fail(name, detail) { console.log(`FAIL ${name} — ${detail}`); }

async function checkSerp() {
  try {
    const serp = await new BrightDataSerpClient().search("apohara synthex bright data", { json: true });
    const organic = serp?.organic ?? serp?.organic_results ?? serp?.results;
    const n = Array.isArray(organic) ? organic.length : 0;
    if (n > 0) ok("SERP", `${n} resultados orgánicos (keys: ${Object.keys(serp).slice(0, 8).join(",")})`);
    else ok("SERP", `respuesta JSON sin organic[] (keys: ${Object.keys(serp || {}).slice(0, 8).join(",")})`);
  } catch (e) {
    fail("SERP", e.message);
  }
}

async function checkCrawl() {
  // Crawl multi-página REAL sobre Web Unlocker (seed → links internos → N páginas). Funciona con
  // el token que ya tenemos; maxPages=2 para no gastar de más en el check.
  try {
    const docs = await new BrightDataCrawlClient().crawl("https://en.wikipedia.org/wiki/Bright_Data", { maxPages: 2 });
    if (docs.length && docs[0].content) ok("CRAWL", `multi-page vía Web Unlocker: ${docs.length} página(s) · seed ${docs[0].content.length} chars`);
    else fail("CRAWL", "crawl devolvió vacío");
  } catch (e) {
    fail("CRAWL", e.message);
  }
}

async function checkDataset() {
  const d = new BrightDataDatasetClient();
  if (!d.datasetId) {
    fail("DATASET", "sin BRIGHT_DATA_DATASET_ID.");
    return;
  }
  try {
    // Solo trigger con 1 input; NO se poolea el snapshot (facturación).
    const res = await d.scrape("https://example.com");
    const snap = res?.snapshot_id ?? res?.id;
    if (snap) ok("DATASET", `trigger aceptado, snapshot_id=${snap} (no se poolea por costo)`);
    else ok("DATASET", `respuesta directa (keys: ${Object.keys(res || {}).slice(0, 8).join(",")})`);
  } catch (e) {
    fail("DATASET", e.message);
  }
}

console.log("== Bright Data REST APIs — check LIVE ==");
await checkSerp();
await checkCrawl();
await checkDataset();
process.exit(0);
