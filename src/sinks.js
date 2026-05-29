// Sinks del watch loop — destinos de la inteligencia producida.
// Cada sink es async ({target, lens, evidence, alert, signals, maxSeverity}).
// Cubren dos gaps del análisis de fit: memoria estructurada (Cognee) y delivery (webhook).
//
// **v0.8.0 — CaMeL-style flow-data gate (HONESTY §8.B):**
// Both webhookSink and cogneeSink suppress their action when ANY contributing
// source URL was marked REVIEW by the Layer-2 injection-guard (decisions[].
// outcome === "REVIEW" && layer === "injection-guard"). Operator override:
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
import { CogneeClient } from "./memory/index.js";

/** Extract URLs the injection-guard marked REVIEW from the sealed decisions[]. */
function _reviewedUrls(evidence) {
  const rows = evidence?.payload?.decisions ?? [];
  return new Set(
    rows
      .filter((d) => d.outcome === "REVIEW" && d.layer === "injection-guard")
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
  const { env = process.env, cogneeClientFactory = () => new CogneeClient() } = opts;
  const sinks = [];
  if (env.COGNEE_LIVE) {
    const client = await cogneeClientFactory();
    if (typeof client.connect === "function" && !client.client) await client.connect();
    sinks.push(cogneeSink(client, { env }));
  }
  if (env.SYNTHEX_WEBHOOK_URL) sinks.push(webhookSink(env.SYNTHEX_WEBHOOK_URL, { env }));
  return sinks;
}
