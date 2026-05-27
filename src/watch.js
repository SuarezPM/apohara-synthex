// WATCH — el loop "always-on" que convierte el pipeline en un sistema del que un equipo
// depende: corre el pipeline sobre un target, lo compara con el HISTÓRICO en memoria
// (deltas de señales + escalada de severidad), persiste la nueva evidencia y emite una
// ALERTA estructurada solo cuando hay novedad. Esto materializa "continuously monitor",
// "improve through structured knowledge" (Cognee) y "signals before they appear in a feed".
import { runPipeline } from "./pipeline.js";
import { MemoryStore } from "./memory/index.js";

function signalsOf(evidence) {
  return [...new Set((evidence.payload?.findings ?? []).flatMap((f) => f.signals ?? []))];
}
function maxSeverityOf(evidence) {
  return (evidence.payload?.findings ?? []).reduce((m, f) => Math.max(m, f.severity ?? 0), 0);
}

/**
 * Una ronda de vigilancia sobre `target`. Compara con lo recordado y devuelve {evidence, alert, ...}.
 * @param {string} target
 * @param {{lens?:string, store?:MemoryStore, runner?:Function, hmacKey?:string}} opts
 *   runner: inyectable (default runPipeline) para testear sin red.
 */
export async function watchTarget(target, opts = {}) {
  const { lens = "security", store, runner = runPipeline, hmacKey, sinks = [] } = opts;
  const mem = store ?? new MemoryStore();

  const prior = mem.recall({ target, lens });
  const priorSignals = new Set(prior.flatMap((p) => p.signals ?? []));
  const priorMaxSeverity = prior.reduce((m, p) => Math.max(m, p.maxSeverity ?? 0), 0);

  const evidence = await runner(target, { lens, hmacKey });
  const signals = signalsOf(evidence);
  const maxSeverity = maxSeverityOf(evidence);
  const newSignals = signals.filter((s) => !priorSignals.has(s));
  const escalated = maxSeverity > priorMaxSeverity;

  mem.remember({ target, lens, evidenceHash: evidence.contentHash, maxSeverity, signals, at: evidence.sealedAt });

  const isFirstRun = prior.length === 0;
  // Alerta: primera corrida con señales, o aparición de señales nuevas, o escalada de severidad.
  const shouldAlert = (isFirstRun && signals.length > 0) || newSignals.length > 0 || escalated;
  const alert = shouldAlert
    ? { target, lens, maxSeverity, newSignals, escalated, isFirstRun, evidenceHash: evidence.contentHash, at: evidence.sealedAt }
    : null;

  // Sinks opcionales (best-effort, no rompen el watch): ingesta a Cognee (grafo de
  // conocimiento), delivery de alertas a un webhook, etc.
  for (const sink of sinks) {
    try { await sink({ target, lens, evidence, alert, signals, maxSeverity }); }
    catch (e) { if (process.env.SYNTHEX_DEBUG) console.error("[watch] sink error:", e.message); }
  }

  return { evidence, alert, isFirstRun, newSignals, escalated, maxSeverity };
}
