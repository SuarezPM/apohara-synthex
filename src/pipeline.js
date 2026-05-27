// PIPELINE — orquesta las 4 etapas en un Evidence Report sellado:
// FETCH (Bright Data) → FORGE (dedup + pre-filtro) → CLASSIFY (AI/ML API) → PROVE (HMAC + TSA).
// fetcher y classifier son inyectables para testear sin red (y para el demo determinista).
import { BrightDataClient } from "./fetch/bright-data-client.js";
import { dedupe, prefilter } from "./forge/index.js";
import { classify as defaultClassify, classifyTriLens } from "./classify/aiml-client.js";
import { buildEvidence } from "./prove/evidence-report.js";
import { withSpan, recordTokens, recordBlocked, recordSealed, startTelemetry } from "./telemetry/otel.js";

const TRI_LENSES = ["gtm", "finance", "security"];

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

  await startTelemetry(); // arranca el exporter OTLP solo si hay endpoint (idempotente)

  // Duraciones por etapa (wall-clock) que se devuelven al caller (UI/stream); NO entran al
  // payload sellado → no afectan hashOk/verify. Independiente del export OTel de withSpan.
  const timings = {};
  const timed = async (stage, fn) => {
    const s = performance.now();
    try { return await withSpan(stage, fn); }
    finally { timings[stage] = +(performance.now() - s).toFixed(1); }
  };

  // 1. FETCH — target puede ser un string o un array de fuentes (multi-fuente / scale).
  const targets = Array.isArray(target) ? target : [target];
  const docs = await timed("FETCH", async ({ record }) => {
    const out = [];
    for (const t of targets) out.push(...(fetcher ? await fetcher(t) : await defaultFetch(t)));
    record("urls", out.length);
    return out;
  });

  // 2. FORGE: deduplicar + pre-filtrar (bloquear contenido malicioso antes de gastar LLM)
  const { blocked, safe, dedup } = await timed("FORGE", async ({ record }) => {
    const { unique, stats } = dedupe(docs);
    const screened = unique.map((d) => ({ ...d, screen: prefilter(d.content) }));
    const blocked = screened.filter((d) => d.screen.action === "BLOCK");
    const safe = screened.filter((d) => d.screen.action !== "BLOCK");
    record("dedup", stats.duplicateBlocks);
    record("blocked", blocked.length);
    recordBlocked(blocked.length);
    return { blocked, safe, dedup: stats };
  });

  // 3. CLASSIFY (cada doc seguro). lens="all" → tri-lente (GTM+Finance+Security) en paralelo;
  // si no, la lente pedida (retrocompat). El classifier inyectable se respeta en ambos modos.
  const doClassify = classifier ?? defaultClassify;
  const findings = await timed("CLASSIFY", async ({ record }) => {
    record("lens", lens);
    record("docs", safe.length);
    if (lens === "all") {
      return Promise.all(
        safe.map(async (d) => {
          const tri = classifier
            ? Object.fromEntries(await Promise.all(TRI_LENSES.map(async (l) => [l, await classifier(d.content, l)])))
            : await classifyTriLens(d.content, { onUsage: recordTokens });
          return { url: d.url, contentHash: d.contentHash, trilens: tri };
        })
      );
    }
    const out = [];
    for (const d of safe) {
      const c = await doClassify(d.content, lens, { onUsage: recordTokens });
      out.push({ url: d.url, contentHash: d.contentHash, ...c });
    }
    return out;
  });

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
  const evidence = await timed("PROVE", async ({ record }) => {
    const ev = await buildEvidence(payload, { hmacKey, requestTsa });
    record("method", ev.seal.method);
    recordSealed();
    return ev;
  });
  evidence.timings = timings; // hermano de payload (fuera del sello)
  return evidence;
}
