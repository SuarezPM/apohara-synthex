// PIPELINE — orquesta las 4 etapas en un Evidence Report sellado:
// FETCH (Bright Data) → FORGE (dedup + pre-filtro) → CLASSIFY (AI/ML API) → PROVE (HMAC + TSA).
// fetcher y classifier son inyectables para testear sin red (y para el demo determinista).
import { BrightDataClient } from "./fetch/bright-data-client.js";
import { dedupe, prefilter } from "./forge/index.js";
import { evaluate as djlScreen, RULES as DJL_RULES, POLICY_BUNDLE_VERSION as DJL_POLICY_BUNDLE_VERSION } from "./forge/djl.js";
import { POLICY_BUNDLE_VERSION as PREFILTER_POLICY_BUNDLE_VERSION } from "./forge/prefilter.js";
import { screen as injectionGuardScreen, POLICY_BUNDLE_VERSION as GUARD_POLICY_BUNDLE_VERSION } from "./forge/injection-guard.js";
import { classify as defaultClassify } from "./classify/aiml-client.js";
import { buildEvidence } from "./prove/evidence-report.js";
import { sha256 } from "./prove/hmac.js";
import { withSpan, recordTokens, recordBlocked, recordSealed, startTelemetry } from "./telemetry/otel.js";
import { computeTokensSaved } from "./telemetry/tokens.js";

// Flag de rollback: EVIDENCE_SCHEMA_V2=0 fuerza payload v1 legacy (sin schema_version,
// sin decisions[], sin policy_bundle_version). Default = v2. Sunset post-hackathon (FU-7).
const _SCHEMA_V2 = process.env.EVIDENCE_SCHEMA_V2 !== "0";

const LENS_SET = ["gtm", "finance", "security", "supply-chain"];

// DJL's verdict exposes matched rule_ids but not their severity; map id→severity once from the
// frozen RULES so a REVIEW row can seal the real max severity that triggered it (the signal stays
// sealed even though L1 no longer drops the doc — D5 FP fix).
// El verdict de DJL expone rule_ids pero no su severidad; mapeamos id→severity una vez desde las
// RULES congeladas para que la fila REVIEW selle la severidad real que la disparó (la señal sigue
// sellada aunque L1 ya no dropee el doc — corrección FP D5).
const _DJL_RULE_SEVERITY = new Map(DJL_RULES.map((r) => [r.id, r.severity]));
const _maxDjlSeverity = (matchedRuleIds = []) =>
  matchedRuleIds.reduce((max, id) => Math.max(max, _DJL_RULE_SEVERITY.get(id) ?? 0), 0);

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
 * map con límite de concurrencia: corre `fn` sobre `items` con a lo sumo `limit` en vuelo a la vez,
 * preservando el orden de resultados. Acota las ráfagas que saturarían los rate-limits de Bright
 * Data / AI-ML cuando hay muchos targets o documentos (adaptación del PR #2: Promise.all → bounded).
 */
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  const cap = Math.max(1, Math.min(limit, items.length));
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: cap }, worker));
  return results;
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
    signingKey,       // v0.8.0 — Ed25519 pkcs8 PEM/base64; presence opt-in → asymmetric seal
    signerIdentity,   // v0.8.0 — out-of-band identity pointer carried in the seal
    fetcher,
    classifier,
    emitter,
    dedupMode = "exact", // "semantic" (opt-in, CLI-only) carga dedup-semantic.js con import() dinámico
    concurrency = Number(process.env.SYNTHEX_CONCURRENCY) || 6, // cap de FETCH/CLASSIFY en vuelo (PR #2 acotado)
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
    const out = (
      await mapLimit(targets, concurrency, (t) => (fetcher ? fetcher(t) : defaultFetch(t)))
    ).flat();
    record("urls", out.length);
    return out;
  });

  // 2. FORGE: dedup + DJL (78 reglas) + prefilter (32 reglas) + Layer-2 injection-guard (opt-in v0.8).
  // Orden: dedupe baja N → DJL prompt-level → prefilter web-injection → guard semantic detector.
  // `blocked` (post-D5) = SOLO injection-guard: ningún doc se dropea por L1 regex. DJL/prefilter
  // grado-BLOCK (sev≥8) producen filas REVIEW (`djlReviewed`/`prefReviewed`) y el doc se conserva.
  // tokensSaved: estimación honesta de tokens NO gastados en LLM gracias a dedup + L2 blocked.
  //
  // v1.0.0 (corrección FP D5) — L1 regex (DJL+prefilter) es REVIEW-only en ingesta: la severidad
  // sigue siendo señal sellada, pero ya NO dropea el doc scrapeado (eliminaba el 80% FP en corpus
  // benigno de seguridad). La autoridad de BLOCK en ingesta queda solo en L2 calificado (y L3,
  // Phase 1). Ver docs/guard-fp-measurement.md + docs/HONESTY.md §8.A.
  //
  // Layer-2 (injection-guard) — opt-in via SYNTHEX_GUARD_URL (or opts.injectionGuard). When unset,
  // step is SKIPPED entirely → blocked/safe identical to v0.7. When set, screen() each doc via
  // Prompt-Guard 86M (or heuristic fallback if endpoint down); BLOCK drops the doc, REVIEW keeps
  // it but annotates decisions[] with outcome:"REVIEW" + guard_mode + model_hash. See HONESTY §8.A
  // — this is a detector (REVIEW-by-default), NOT a CaMeL replacement. CaMeL-style gating lives in
  // watch+sinks (HONESTY §8.B) where verdicts trigger real actions.
  const guardEnabled = opts.injectionGuard === true
    || (typeof opts.injectionGuard === "object" && opts.injectionGuard !== null)
    || (opts.injectionGuard !== false && !!process.env.SYNTHEX_GUARD_URL);
  const guardScreenImpl = (typeof opts.injectionGuard === "object" && typeof opts.injectionGuard?.screen === "function")
    ? opts.injectionGuard.screen
    : injectionGuardScreen;

  const { blocked, safe, dedup, tokensSaved, guardReviewed, djlReviewed, prefReviewed } = await timed("FORGE", async ({ record }) => {
    // Default exact (SHA-256, lossless, sync). Semántico = opt-in: import() DINÁMICO para que el
    // grafo de deps de api/** nunca alcance @xenova/transformers (bundle serverless limpio).
    const { unique, stats } = dedupMode === "semantic"
      ? await (await import("./forge/dedup-semantic.js")).dedupeSemantic(docs)
      : dedupe(docs);

    // Layer 1a — DJL screen (78 reglas regex deterministas pre-LLM).
    // v1.0.0 (D5 FP fix) — L1 regex is REVIEW-only on ingest: a scraped doc is NEVER dropped by
    // regex severity. DJL still reports its decision (severity stays a sealed signal), but a
    // BLOCK-grade hit (sev≥8) now marks the doc REVIEW and KEEPS it in `safe` instead of dropping
    // it. BLOCK authority on ingest belongs to nobody in L1 — only a qualified L2 (Phase 1) /L3.
    // v1.0.0 (corrección FP) — L1 regex es REVIEW-only en la ingesta: ningún doc scrapeado se
    // dropea por severidad regex. DJL sigue reportando su decision (la severidad sigue siendo
    // señal sellada), pero un hit grado-BLOCK (sev≥8) ahora marca REVIEW y CONSERVA el doc en
    // `safe` en vez de dropearlo. La autoridad de BLOCK en ingesta no la tiene nadie de L1.
    const djled = unique.map((d) => ({ ...d, djl: djlScreen(d.content) }));
    const djlReviewed = djled
      .filter((d) => d.djl.decision === "BLOCK")
      .map((d) => ({ ...d, reason: d.djl.matched_rules[0], severity: _maxDjlSeverity(d.djl.matched_rules), layer: "djl" }));

    // Layer 1b — PREFILTER (32 reglas web-injection). Corre sobre TODOS los docs (ya no solo
    // sobre lo que DJL "dejó pasar", porque DJL ya no dropea). Mismo trato REVIEW-only que DJL.
    const screened = djled.map((d) => ({ ...d, screen: prefilter(d.content) }));
    const prefReviewed = screened
      .filter((d) => d.screen.action === "BLOCK")
      .map((d) => ({ ...d, reason: d.screen.category, severity: d.screen.severity, layer: "prefilter" }));
    const safe1 = screened;

    // Layer 2 — INJECTION_GUARD (opt-in, calibrated REVIEW-by-default). El ÚNICO L1/L2 con
    // autoridad BLOCK hoy (drop real del doc); su threshold se mantiene (fuera de scope D5).
    let guardBlocked = [];
    let guardReviewed = [];
    let safe = safe1;
    if (guardEnabled) {
      const verdicts = await Promise.all(
        safe1.map(async (d) => ({ ...d, guard: await guardScreenImpl(d.content) })),
      );
      guardBlocked = verdicts
        .filter((d) => d.guard?.verdict === "block")
        .map((d) => ({ ...d, reason: d.guard.label ?? "INJECTION_GUARD", layer: "injection-guard" }));
      guardReviewed = verdicts.filter((d) => d.guard?.verdict === "review");
      safe = verdicts.filter((d) => d.guard?.verdict !== "block");
    }

    // `blocked` = solo lo que L2 dropea (BLOCK real). DJL/prefilter ya NO bloquean ingesta.
    const blocked = guardBlocked;
    const tokensSaved = computeTokensSaved({ original: docs, unique, blocked });
    record("dedup", stats.duplicateBlocks);
    record("djl_reviewed", djlReviewed.length);
    record("prefilter_reviewed", prefReviewed.length);
    if (guardEnabled) {
      record("guard_blocked", guardBlocked.length);
      record("guard_reviewed", guardReviewed.length);
    }
    record("blocked", blocked.length);
    record("tokens_saved_est", tokensSaved.estimated_tokens);
    recordBlocked(blocked.length);
    return { blocked, safe, dedup: stats, tokensSaved, guardReviewed, djlReviewed, prefReviewed };
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
      // map externo capeado a `concurrency`; las 4 lentes internas por doc siguen en paralelo
      // (hasta concurrency×4 llamadas al clasificador en vuelo en el peor caso).
      return mapLimit(safe, concurrency, async (d) => {
        const tri = Object.fromEntries(
          await Promise.all(LENS_SET.map(async (l) => [l, await doClassify(d.content, l, classifyOpts)])),
        );
        return { url: d.url, contentHash: d.contentHash, trilens: tri };
      });
    }
    return mapLimit(safe, concurrency, async (d) => {
      const c = await doClassify(d.content, lens, classifyOpts);
      return { url: d.url, contentHash: d.contentHash, ...c };
    });
  });

  // 4. PROVE: sellar el reporte.
  // Payload v3 (default since v0.8.0): same canonical pre-image as v2 (so contentHash + HMAC
  // pre-image byte-identical); the v3 schema enables `seal.signature` + `seal.signerIdentity`
  // (additive, both in seal, NOT in payload) without changing the pre-image. v2 hand-built
  // payloads stay valid (v2 + v3 fall through the same `>= 2` branch in _serializeForHmac).
  // Payload v1 (legacy, opt-out vía EVIDENCE_SCHEMA_V2=0): shape exacto de Synthex v3 (the
  // 2026 SDK, not to be confused with the v3 schema version).
  const fetchedAt = new Date().toISOString();
  const blockedForPayload = blocked.map((d) => ({ url: d.url, reason: d.reason, layer: d.layer }));
  // Resolve per-layer policy + decision-row stage/bundle in a single map (DRY).
  const _layerMeta = {
    djl: { stage: "DJL", bundle: DJL_POLICY_BUNDLE_VERSION },
    prefilter: { stage: "PREFILTER", bundle: PREFILTER_POLICY_BUNDLE_VERSION },
    "injection-guard": { stage: "INJECTION_GUARD", bundle: GUARD_POLICY_BUNDLE_VERSION },
  };
  const _guardDecisionExtras = (d) => d.guard
    ? { guard_mode: d.guard.source, guard_score: d.guard.score, model_hash: d.guard.model_hash }
    : {};

  const payload = _SCHEMA_V2
    ? {
        schema_version: 3,
        target,
        lens,
        fetchedAt,
        sources: docs.map((d) => d.url),
        dedup,
        blocked: blockedForPayload,
        findings,
        tokens_saved: tokensSaved,
        policy_bundle_version: {
          djl: DJL_POLICY_BUNDLE_VERSION,
          prefilter: PREFILTER_POLICY_BUNDLE_VERSION,
          ...(guardEnabled ? { injectionGuard: GUARD_POLICY_BUNDLE_VERSION } : {}),
        },
        decisions: [
          // BLOCK rows — post-D5 only INJECTION_GUARD (L2) drops a doc on ingest; L1 regex is
          // REVIEW-only (DJL/prefilter BLOCK-grade hits surface as REVIEW rows below, never here).
          ...blocked.map((d) => ({
            stage: _layerMeta[d.layer].stage,
            url: d.url,
            contentHash: sha256(String(d.content ?? "")).toString("hex"),
            rule_matched: [d.reason],
            outcome: "BLOCK",
            layer: d.layer,
            policy_bundle_version: _layerMeta[d.layer].bundle,
            at: fetchedAt,
            ..._guardDecisionExtras(d),
          })),
          // REVIEW rows from L1 regex (DJL + prefilter) — D5 FP fix: the doc is KEPT and classified,
          // the BLOCK-grade severity is sealed as REVIEW signal. layer distinguishes DJL vs prefilter.
          ...[...djlReviewed, ...prefReviewed].map((d) => ({
            stage: _layerMeta[d.layer].stage,
            url: d.url,
            contentHash: sha256(String(d.content ?? "")).toString("hex"),
            rule_matched: [d.reason],
            outcome: "REVIEW",
            layer: d.layer,
            severity: d.severity,
            policy_bundle_version: _layerMeta[d.layer].bundle,
            at: fetchedAt,
          })),
          // REVIEW rows from injection-guard (kept but annotated; HONESTY §8.A)
          ...guardReviewed.map((d) => ({
            stage: "INJECTION_GUARD",
            url: d.url,
            contentHash: sha256(String(d.content ?? "")).toString("hex"),
            rule_matched: [d.guard.label ?? "INJECTION_GUARD_REVIEW"],
            outcome: "REVIEW",
            layer: "injection-guard",
            policy_bundle_version: GUARD_POLICY_BUNDLE_VERSION,
            at: fetchedAt,
            ..._guardDecisionExtras(d),
          })),
        ],
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
    const ev = await buildEvidence(payload, { hmacKey, requestTsa, signingKey, signerIdentity });
    record("method", ev.seal.method);
    recordSealed();
    return ev;
  });
  evidence.timings = timings; // hermano de payload (fuera del sello)
  return evidence;
}
