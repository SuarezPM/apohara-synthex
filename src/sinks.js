// Sinks del watch loop — destinos de la inteligencia producida.
// Cada sink es async ({target, lens, evidence, alert, signals, maxSeverity}).
// Cubren dos gaps del análisis de fit: memoria estructurada (Cognee) y delivery (webhook).
import { CogneeClient } from "./memory/index.js";

/**
 * Ingiere la inteligencia clasificada en el knowledge graph de Cognee (OSS, vía su MCP).
 * Cumple el challenge "agents that remember, reason, and improve over time".
 * @param {{remember: Function}} cogneeClient  un CogneeClient ya conectado.
 */
export function cogneeSink(cogneeClient) {
  return async ({ target, lens, evidence, signals, maxSeverity }) => {
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
 */
export function webhookSink(url) {
  return async ({ alert }) => {
    if (!alert) return;
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
 * @param {{env?:object, cogneeClientFactory?:Function}} [opts]  inyectables para test (sin red/LLM).
 * @returns {Promise<Function[]>}
 */
export async function defaultSinks(opts = {}) {
  const { env = process.env, cogneeClientFactory = () => new CogneeClient() } = opts;
  const sinks = [];
  if (env.COGNEE_LIVE) {
    const client = await cogneeClientFactory();
    if (typeof client.connect === "function" && !client.client) await client.connect();
    sinks.push(cogneeSink(client));
  }
  if (env.SYNTHEX_WEBHOOK_URL) sinks.push(webhookSink(env.SYNTHEX_WEBHOOK_URL));
  return sinks;
}
