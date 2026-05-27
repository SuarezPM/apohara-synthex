// Sinks del watch loop — destinos de la inteligencia producida.
// Cada sink es async ({target, lens, evidence, alert, signals, maxSeverity}).
// Cubren dos gaps del análisis de fit: memoria estructurada (Cognee) y delivery (webhook).

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
