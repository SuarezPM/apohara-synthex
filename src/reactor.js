// REACTOR — cierra el loop "react and act" de Triggerware (challenge: "build agents that
// react and act"). Hace poll de un trigger; por cada fila nueva (delta added) REACCIONA
// disparando el pipeline (vía watchTarget) y ACTÚA (alerta + sinks: Cognee/webhook).
//
// Flujo enterprise always-on: Triggerware vigila una query en schedule → cuando aparece algo
// nuevo, Synthex lo scrapea, clasifica, sella como evidencia y alerta — sin intervención humana.
//
// SYSTEM SHAPE — short file by design, not a stub. The WATCH/REACT loop is split across
// three small files that compose:
//   - reactor.js  (this file, ~35 LOC) — the spine: poll + per-row dispatch + result aggregation
//   - watch.js    (~63 LOC)            — runs the pipeline, diffs vs memory store, decides alert
//   - sinks.js    (~56 LOC)            — fan-out of intel to Cognee/webhook (best-effort)
// End-to-end coverage of the spine lives in test/reactor.test.js (8 cases: idle poll,
// per-row dispatch, deriveTarget hook, sink fan-out, delta detection across polls,
// severity escalation, broken-sink resilience). Each downstream module has its own tests
// (test/watch.test.js, test/sinks.test.js).
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
