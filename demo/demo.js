// DEMO determinista de apohara-synthex. Corre el pipeline FETCH→FORGE→CLASSIFY→PROVE sobre
// un SNAPSHOT CACHEADO (no live) para ser reproducible sin gastar Bright Data / AI-ML en cada
// corrida. El SELLO de evidencia (HMAC-SHA256 + RFC 3161 TSA de DigiCert) SÍ se genera en vivo.
import { runPipeline } from "../src/pipeline.js";
import { verifyEvidence } from "../src/prove/evidence-report.js";

const CACHED_AT = "2026-05-27";

// Snapshot: documentos pre-scrapeados (corrida cacheada de Bright Data para el demo).
const CACHED_DOCS = [
  { url: "https://competitor-x.example/pricing", content: "Competitor X cut its Pro plan from $99 to $79/mo and launched a free tier with 10k API calls." },
  { url: "https://competitor-x.example/pricing?ref=ad", content: "Competitor X cut its Pro plan from $99 to $79/mo and launched a free tier with 10k API calls." }, // misma página, otro ref → duplicado
  { url: "https://competitor-x.example/careers", content: "Competitor X is hiring 8 enterprise account executives and 3 solutions engineers across EMEA." },
];

// Clasificación de DEMO (determinista, etiquetada — NO es salida live del LLM).
const DEMO_CLASSIFICATIONS = {
  pricing: { severity: 7, summary: "Recorte de precio agresivo (-20%) + free tier: presión competitiva alta.", signals: ["price-cut", "free-tier", "10k-api-calls"] },
  careers: { severity: 6, summary: "Expansión de ventas enterprise en EMEA: señal de go-to-market.", signals: ["hiring", "enterprise-sales", "EMEA"] },
};
const demoClassifier = async (text, lens) => {
  const cat = /pricing|plan|\$|tier/i.test(text) ? "pricing" : "careers";
  return { lens, ...DEMO_CLASSIFICATIONS[cat] };
};

/** Corre el demo y devuelve el Evidence Report. requestTsa=false en tests para rapidez.
 *  emitter (opcional) se reenvía al pipeline para el stream SSE de la UI en modo demo. */
export async function runDemo({ requestTsa = true, emitter, lens = "gtm" } = {}) {
  return runPipeline("Competitor X", {
    lens,
    fetcher: async () => CACHED_DOCS,
    classifier: demoClassifier,
    hmacKey: process.env.SYNTHEX_HMAC_KEY || "synthex-demo",
    requestTsa,
    emitter,
  });
}

async function main() {
  console.log(`\n⬡ APOHARA SYNTHEX — Evidence Report (DEMO · corrida CACHEADA ${CACHED_AT}, NO live)\n`);
  const ev = await runDemo({ requestTsa: true });
  console.log(JSON.stringify(ev, null, 2));
  const v = await verifyEvidence(ev, { hmacKey: process.env.SYNTHEX_HMAC_KEY || "synthex-demo" });
  console.log("\n── Verificación ──");
  console.log("  hash :", v.hashOk ? "OK" : "FALLO");
  console.log("  HMAC :", v.hmacOk ? "OK" : "FALLO");
  console.log("  TSA  :", v.tsaOk === true ? "OK (RFC 3161 · DigiCert)" : v.tsaOk === null ? "sin TSA (fallback HMAC-only)" : "FALLO");
  console.log(`\n  método de sello: ${ev.seal.method}`);
  console.log(`  datos: snapshot cacheado (${CACHED_AT}); sello: generado en vivo.\n`);
  process.exit(0);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
