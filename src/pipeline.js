// PIPELINE — orquesta las 4 etapas en un Evidence Report sellado:
// FETCH (Bright Data) → FORGE (dedup + pre-filtro) → CLASSIFY (AI/ML API) → PROVE (HMAC + TSA).
// fetcher y classifier son inyectables para testear sin red (y para el demo determinista).
import { BrightDataClient } from "./fetch/bright-data-client.js";
import { dedupe, prefilter } from "./forge/index.js";
import { evaluate as djlScreen, POLICY_BUNDLE_VERSION as DJL_POLICY_BUNDLE_VERSION } from "./forge/djl.js";
import { POLICY_BUNDLE_VERSION as PREFILTER_POLICY_BUNDLE_VERSION } from "./forge/prefilter.js";
import { classify as defaultClassify } from "./classify/aiml-client.js";
import { buildEvidence } from "./prove/evidence-report.js";
import { sha256 } from "./prove/hmac.js";
import { withSpan, recordTokens, recordBlocked, recordSealed, startTelemetry } from "./telemetry/otel.js";

// Flag de rollback: EVIDENCE_SCHEMA_V2=0 fuerza payload v1 legacy (sin schema_version,
// sin decisions[], sin policy_bundle_version). Default = v2. Sunset post-hackathon (FU-7).
const _SCHEMA_V2 = process.env.EVIDENCE_SCHEMA_V2 !== "0";

const LENS_SET = ["gtm", "finance", "security", "supply-chain"];

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
 * @param {{lens?:string, hmacKey?:string, requestTsa?:boolean, fetcher?:Function, classifier?:Function, emitter?:Function}} opts
 */
export async function runPipeline(target, opts = {}) {
  const {
    lens = "security",
    hmacKey = process.env.SYNTHEX_HMAC_KEY || "synthex-dev",
    requestTsa = true,
    fetcher,
    classifier,
    emitter,
    dedupMode = "exact", // "semantic" (opt-in, CLI-only) carga dedup-semantic.js con import() dinámico
  } = opts;

  await startTelemetry(); // arranca el exporter OTLP solo si hay endpoint (idempotente)

  // Emisión de eventos de progreso (SSE/stream). Best-effort: si el emitter falla o no existe,
  // el pipeline NO se rompe. Eventos por stage: {status:"start"} y {status:"done", ms, ...}.
  const emit = async (stage, evt) => {
    if (!emitter) return;
    try { await emitter({ stage, ...evt }); } catch { /* no romper el pipeline por el emitter */ }
  };

  // Duraciones por etapa (wall-clock) que se devuelven al caller (UI/stream); NO entran al
  // payload sellado → no afectan hashOk/verify. Independiente del export OTel de withSpan.
  const timings = {};
  const timed = async (stage, fn) => {
    const s = performance.now();
    await emit(stage, { status: "start" });
    try {
      const out = await withSpan(stage, fn);
      await emit(stage, { status: "done", ms: +(performance.now() - s).toFixed(1) });
      return out;
    } finally { timings[stage] = +(performance.now() - s).toFixed(1); }
  };

  // 1. FETCH — target puede ser un string o un array de fuentes (multi-fuente / scale).
  const targets = Array.isArray(target) ? target : [target];
  const docs = await timed("FETCH", async ({ record }) => {
    const out = [];
    for (const t of targets) out.push(...(fetcher ? await fetcher(t) : await defaultFetch(t)));
    record("urls", out.length);
    return out;
  });

  // 2. FORGE: dedup + DJL (78 reglas harm/PII/jailbreak) + prefilter (28 reglas web-injection)
  // Orden: dedupe baja N → DJL filtra prompt-level → prefilter actúa sobre lo que DJL no bloqueó.
  // `blocked` es UNIÓN de ambas capas (no doble conteo); `reason` siempre set, `layer` distingue origen.
  const { blocked, safe, dedup } = await timed("FORGE", async ({ record }) => {
    // Default exact (SHA-256, lossless, sync). Semántico = opt-in: import() DINÁMICO para que el
    // grafo de deps de api/** nunca alcance @xenova/transformers (bundle serverless limpio).
    const { unique, stats } = dedupMode === "semantic"
      ? await (await import("./forge/dedup-semantic.js")).dedupeSemantic(docs)
      : dedupe(docs);

    // DJL screen — 78 reglas regex deterministas portadas de Aegis. Bloquea harm/jailbreak/PII
    // antes de prefilter (que solo cubre content-injection web).
    const djled = unique.map((d) => ({ ...d, djl: djlScreen(d.content) }));
    const djlBlocked = djled
      .filter((d) => d.djl.decision === "BLOCK")
      .map((d) => ({ ...d, reason: d.djl.matched_rules[0], layer: "djl" }));
    const passDjl = djled.filter((d) => d.djl.decision !== "BLOCK");

    // PREFILTER — 28 reglas web-injection sobre lo que DJL dejó pasar (ALLOW + REVIEW).
    const screened = passDjl.map((d) => ({ ...d, screen: prefilter(d.content) }));
    const prefBlocked = screened
      .filter((d) => d.screen.action === "BLOCK")
      .map((d) => ({ ...d, reason: d.screen.category, layer: "prefilter" }));
    const safe = screened.filter((d) => d.screen.action !== "BLOCK");

    // Unión sin doble conteo: DJL y prefilter atacan vectores distintos sobre conjuntos disjuntos.
    const blocked = [...djlBlocked, ...prefBlocked];
    record("dedup", stats.duplicateBlocks);
    record("djl_blocked", djlBlocked.length);
    record("blocked", blocked.length);
    recordBlocked(blocked.length);
    return { blocked, safe, dedup: stats };
  });

  // 3. CLASSIFY (cada doc seguro). lens="all" → las 4 lentes (GTM+Finance+Security+SupplyChain)
  // en paralelo; si no, la lente pedida (retrocompat). El classifier inyectable se respeta en
  // ambos modos; solo se pasa {onUsage} cuando NO hay classifier inyectado (= defaultClassify).
  const doClassify = classifier ?? defaultClassify;
  const classifyOpts = classifier ? {} : { onUsage: recordTokens };
  const findings = await timed("CLASSIFY", async ({ record }) => {
    record("lens", lens);
    record("docs", safe.length);
    if (lens === "all") {
      return Promise.all(
        safe.map(async (d) => {
          const tri = Object.fromEntries(
            await Promise.all(LENS_SET.map(async (l) => [l, await doClassify(d.content, l, classifyOpts)])),
          );
          return { url: d.url, contentHash: d.contentHash, trilens: tri };
        }),
      );
    }
    const out = [];
    for (const d of safe) {
      const c = await doClassify(d.content, lens, classifyOpts);
      out.push({ url: d.url, contentHash: d.contentHash, ...c });
    }
    return out;
  });

  // 4. PROVE: sellar el reporte.
  // Payload v2 (default): incluye schema_version + decisions[] (audit trail por stage) +
  // policy_bundle_version (sha pin de los corpus DJL+prefilter en uso). El sellado HMAC usa
  // canonicalize() (RFC 8785-like) → reproducible aunque el orden de claves cambie.
  // Payload v1 (legacy, opt-out vía EVIDENCE_SCHEMA_V2=0): shape exacto de Synthex v3.
  const fetchedAt = new Date().toISOString();
  const blockedForPayload = blocked.map((d) => ({ url: d.url, reason: d.reason, layer: d.layer }));
  const payload = _SCHEMA_V2
    ? {
        schema_version: 2,
        target,
        lens,
        fetchedAt,
        sources: docs.map((d) => d.url),
        dedup,
        blocked: blockedForPayload,
        findings,
        policy_bundle_version: {
          djl: DJL_POLICY_BUNDLE_VERSION,
          prefilter: PREFILTER_POLICY_BUNDLE_VERSION,
        },
        decisions: blocked.map((d) => ({
          stage: d.layer === "djl" ? "DJL" : "PREFILTER",
          url: d.url,
          contentHash: sha256(String(d.content ?? "")).toString("hex"),
          rule_matched: [d.reason],
          outcome: "BLOCK",
          layer: d.layer,
          policy_bundle_version: d.layer === "djl" ? DJL_POLICY_BUNDLE_VERSION : PREFILTER_POLICY_BUNDLE_VERSION,
          at: fetchedAt,
        })),
      }
    : {
        target,
        lens,
        fetchedAt,
        sources: docs.map((d) => d.url),
        dedup,
        blocked: blockedForPayload,
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
