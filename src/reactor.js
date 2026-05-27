// REACTOR — cierra el loop "react and act" de Triggerware (challenge: "build agents that
// react and act"). Hace poll de un trigger; por cada fila nueva (delta added) REACCIONA
// disparando el pipeline (vía watchTarget) y ACTÚA (alerta + sinks: Cognee/webhook).
//
// Flujo enterprise always-on: Triggerware vigila una query en schedule → cuando aparece algo
// nuevo, Synthex lo scrapea, clasifica, sella como evidencia y alerta — sin intervención humana.
import { TriggerWareClient } from "./trigger/index.js";
import { watchTarget } from "./watch.js";

/**
 * @param {string} triggerName  nombre del trigger en Triggerware.
 * @param {{tw?:object, deriveTarget?:Function, store?, runner?, sinks?, lens?, hmacKey?}} opts
 *   deriveTarget(row) → target scrapeable. Default: row[0] si la fila es array; si no, la fila.
 */
export async function react(triggerName, opts = {}) {
  const { tw, deriveTarget, ...watchOpts } = opts;
  const client = tw ?? new TriggerWareClient();

  const deltas = await client.poll(triggerName); // { added: [...], deleted: [...] }
  const added = deltas?.added ?? [];

  const results = [];
  for (const row of added) {
    const target = deriveTarget ? deriveTarget(row) : Array.isArray(row) ? row[0] : row;
    const r = await watchTarget(target, watchOpts); // pipeline + memoria + sinks (act)
    results.push({ row, target, alert: r.alert, evidenceHash: r.evidence.contentHash, maxSeverity: r.maxSeverity });
  }

  return {
    polled: triggerName,
    addedCount: added.length,
    results,
    alerts: results.map((x) => x.alert).filter(Boolean),
  };
}
