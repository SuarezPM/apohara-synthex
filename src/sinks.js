// Sinks del watch loop — destinos de la inteligencia producida.
// Cada sink es async ({target, lens, evidence, alert, signals, maxSeverity}).
// Cubren dos gaps del análisis de fit: memoria estructurada (Cognee) y delivery (webhook).
//
// **v0.8.0 — CaMeL-style flow-data gate (HONESTY §8.B); widened v1.0.0 (A1):**
// Both webhookSink and cogneeSink suppress their action when ANY contributing
// source URL was marked REVIEW (or BLOCK) by a gating layer — injection-guard,
// DJL or prefilter (the L1 regex layers now emit REVIEW on ingest after the D5 FP
// fix), or the L3 ALIGNMENT_CHECK stage (Phase 1). Operator override:
//   - SYNTHEX_REACT_TRUST_REVIEWED=1   → webhook fires even with REVIEW'd sources
//   - SYNTHEX_COGNEE_TRUST_REVIEWED=1  → ingest happens even with REVIEW'd sources
// Why these two and NOT classify: classify is label-only (low-risk, no
// persistence, no exfiltration). webhook + Cognee TRIGGER actions / POISON
// memory. The reviewer's distinction (detector ≠ architecture) is enforced
// where verdicts actually move state.
//
// Suppressions are surfaced via console.warn when SYNTHEX_DEBUG is set; the
// REVIEW decision itself is already sealed in evidence.payload.decisions[]
// for audit (operator can replay the run from the sealed record).
import { CogneeClient, CogneeCloudClient } from "./memory/index.js";

// Layers/stages whose REVIEW (or BLOCK) verdict gates the action/persistence sinks.
// v1.0.0 (A1) — widened beyond injection-guard: the D5 FP fix makes DJL/prefilter emit REVIEW
// rows on ingest, so a doc REVIEW'd by L1 regex must ALSO gate webhook (§2.4) and Cognee (§2.3),
// not just L2. ALIGNMENT_CHECK (L3, Phase 1) is included now so the predicate is ready when L3
// starts sealing rows; it matches by stage because L3 rows carry no `layer`.
// Capas/etapas cuyo veredicto REVIEW (o BLOCK) gate-a los sinks de acción/persistencia.
const _GATING_LAYERS = new Set(["injection-guard", "djl", "prefilter"]);
const _GATING_OUTCOMES = new Set(["REVIEW", "BLOCK"]);

/** Extract URLs a gating layer/stage marked REVIEW/BLOCK from the sealed decisions[]. */
function _reviewedUrls(evidence) {
  const rows = evidence?.payload?.decisions ?? [];
  return new Set(
    rows
      .filter(
        (d) =>
          _GATING_OUTCOMES.has(d.outcome) &&
          (_GATING_LAYERS.has(d.layer) || d.stage === "ALIGNMENT_CHECK"),
      )
      .map((d) => d.url),
  );
}

/** True iff any source in the evidence appears in the REVIEW'd URL set. */
function _hasReviewedSource(evidence) {
  const reviewed = _reviewedUrls(evidence);
  if (reviewed.size === 0) return false;
  const sources = evidence?.payload?.sources ?? [];
  return sources.some((u) => reviewed.has(u));
}

/**
 * Ingiere la inteligencia clasificada en el knowledge graph de Cognee (OSS, vía su MCP).
 * Cumple el challenge "agents that remember, reason, and improve over time".
 *
 * v0.8 — CaMeL gate: skip when any source was REVIEW'd by injection-guard (would poison
 * future recall). Operator opts-in per-namespace via SYNTHEX_COGNEE_TRUST_REVIEWED=1.
 *
 * @param {{remember: Function}} cogneeClient  un CogneeClient ya conectado.
 * @param {{trustReviewed?: boolean, env?: object}} [opts]
 */
export function cogneeSink(cogneeClient, opts = {}) {
  const env = opts.env ?? process.env;
  const trustReviewed = opts.trustReviewed ?? !!env.SYNTHEX_COGNEE_TRUST_REVIEWED;
  return async ({ target, lens, evidence, signals, maxSeverity }) => {
    if (!trustReviewed && _hasReviewedSource(evidence)) {
      if (env.SYNTHEX_DEBUG) {
        console.warn(`[cognee] ingest suppressed: REVIEW'd source(s) without SYNTHEX_COGNEE_TRUST_REVIEWED opt-in`);
      }
      return;
    }
    const summaries = (evidence.payload?.findings ?? []).map((f) => f.summary).filter(Boolean).join(" ");
    const text =
      `Synthex web intelligence — target=${target} lens=${lens} severity=${maxSeverity} ` +
      `signals=[${signals.join(", ")}] evidenceHash=${evidence.contentHash}. ${summaries}`;
    await cogneeClient.remember(text);
  };
}

/**
 * Entrega la alerta a un webhook HTTP (delivery a herramientas del equipo: Slack, SIEM, CRM…).
 * Solo dispara cuando hay alerta.
 *
 * v0.8 — CaMeL gate: suppress when any source contributing to the alert was REVIEW'd
 * by injection-guard. Operator opts-in via SYNTHEX_REACT_TRUST_REVIEWED=1.
 *
 * @param {string} url
 * @param {{trustReviewed?: boolean, env?: object}} [opts]
 */
export function webhookSink(url, opts = {}) {
  const env = opts.env ?? process.env;
  const trustReviewed = opts.trustReviewed ?? !!env.SYNTHEX_REACT_TRUST_REVIEWED;
  return async ({ alert, evidence }) => {
    if (!alert) return;
    if (!trustReviewed && _hasReviewedSource(evidence)) {
      if (env.SYNTHEX_DEBUG) {
        console.warn(`[react] webhook suppressed: REVIEW'd source(s) without SYNTHEX_REACT_TRUST_REVIEWED opt-in`);
      }
      return;
    }
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(alert),
      signal: AbortSignal.timeout(10_000),
    });
  };
}

/**
 * Sinks por DEFAULT para el camino LOCAL/CLI (watch/react). Cognee es opt-in por ENTORNO:
 * SOLO se incluye cuando `COGNEE_LIVE` está seteado — promoviéndolo a memoria default sin
 * llamar al LLM en cada deploy. El endpoint público (Vercel) NO setea COGNEE_LIVE y, además,
 * ni siquiera pasa por watch/react (corre runPipeline directo), así que jamás dispara Cognee.
 * Conexión perezosa: el CogneeClient solo arranca el MCP cuando hay que ingerir.
 *
 * v0.8 — env propaga a los sinks para que el CaMeL gate (SYNTHEX_*_TRUST_REVIEWED) sea
 * consistente con el resto del entorno.
 *
 * @param {{env?:object, cogneeClientFactory?:Function}} [opts]
 * @returns {Promise<Function[]>}
 */
export async function defaultSinks(opts = {}) {
  // Default factory: local OSS CogneeClient, OR the opt-in CogneeCloudClient when COGNEE_CLOUD is
  // set (R6). The CaMeL gate below is backend-agnostic — a REVIEW'd source is never ingested by
  // EITHER backend. The local client's COGNEE_REMOTE_URL hard-abort guard is untouched.
  const { env = process.env, cogneeClientFactory = () => (env.COGNEE_CLOUD ? new CogneeCloudClient() : new CogneeClient()) } = opts;
  const sinks = [];
  if (env.COGNEE_LIVE) {
    const client = await cogneeClientFactory();
    if (typeof client.connect === "function" && !client.client) await client.connect();
    sinks.push(cogneeSink(client, { env }));
  }
  if (env.SYNTHEX_WEBHOOK_URL) sinks.push(webhookSink(env.SYNTHEX_WEBHOOK_URL, { env }));
  return sinks;
}
