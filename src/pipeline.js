// PIPELINE — orquesta las 4 etapas en un Evidence Report sellado:
// FETCH (Bright Data) → FORGE (dedup + pre-filtro) → CLASSIFY (AI/ML API) → PROVE (HMAC + TSA).
// fetcher y classifier son inyectables para testear sin red (y para el demo determinista).
import { BrightDataClient } from "./fetch/bright-data-client.js";
import { dedupe, prefilter } from "./forge/index.js";
import { classify as defaultClassify } from "./classify/aiml-client.js";
import { buildEvidence } from "./prove/evidence-report.js";

/** Extrae el texto de un resultado de tool MCP ({content:[{type:'text',text}]}). */
export function mcpText(result) {
  if (typeof result === "string") return result;
  return result?.content?.map((c) => c?.text ?? "").join("\n") ?? "";
}

/** FETCH por defecto: usa Bright Data real. Si target es URL, scrapea directo; si no, busca. */
async function defaultFetch(target, { maxResults = 3 } = {}) {
  const client = new BrightDataClient();
  await client.connect();
  try {
    if (/^https?:\/\//i.test(target)) {
      return [{ url: target, content: mcpText(await client.scrapeMarkdown(target)) }];
    }
    // TODO(verificar con BD real): parseo de URLs del resultado de search_engine.
    const search = mcpText(await client.searchEngine(target));
    const urls = [...search.matchAll(/https?:\/\/[^\s)\]]+/g)].map((m) => m[0]).slice(0, maxResults);
    const docs = [];
    for (const url of urls) docs.push({ url, content: mcpText(await client.scrapeMarkdown(url)) });
    return docs.length ? docs : [{ url: target, content: search }];
  } finally {
    await client.close();
  }
}

/**
 * Ejecuta el pipeline completo y devuelve un Evidence Report.
 * @param {string} target  URL o término objetivo.
 * @param {{lens?:string, hmacKey?:string, requestTsa?:boolean, fetcher?:Function, classifier?:Function}} opts
 */
export async function runPipeline(target, opts = {}) {
  const {
    lens = "security",
    hmacKey = process.env.SYNTHEX_HMAC_KEY || "synthex-dev",
    requestTsa = true,
    fetcher,
    classifier,
  } = opts;

  // 1. FETCH
  const docs = fetcher ? await fetcher(target) : await defaultFetch(target);

  // 2. FORGE: deduplicar + pre-filtrar (bloquear contenido malicioso antes de gastar LLM)
  const { unique, stats: dedup } = dedupe(docs);
  const screened = unique.map((d) => ({ ...d, screen: prefilter(d.content) }));
  const blocked = screened.filter((d) => d.screen.action === "BLOCK");
  const safe = screened.filter((d) => d.screen.action !== "BLOCK");

  // 3. CLASSIFY (cada doc seguro, bajo la lente pedida)
  const doClassify = classifier ?? defaultClassify;
  const findings = [];
  for (const d of safe) {
    const c = await doClassify(d.content, lens);
    findings.push({ url: d.url, contentHash: d.contentHash, ...c });
  }

  // 4. PROVE: sellar el reporte
  const payload = {
    target,
    lens,
    fetchedAt: new Date().toISOString(),
    sources: docs.map((d) => d.url),
    dedup,
    blocked: blocked.map((d) => ({ url: d.url, reason: d.screen.category })),
    findings,
  };
  return buildEvidence(payload, { hmacKey, requestTsa });
}
