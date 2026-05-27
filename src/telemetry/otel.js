// TELEMETRY — observabilidad del pipeline con OpenTelemetry GenAI Semantic Conventions.
// Diseño honesto en dos modos:
//  - SIEMPRE: spans + métricas vía @opentelemetry/api (no-op si no hay SDK registrado → costo ~0).
//  - OPT-IN: si OTEL_EXPORTER_OTLP_ENDPOINT está seteado, startTelemetry() arranca el NodeSDK
//    y exporta traces+métricas por OTLP/HTTP a un colector (Datadog, Jaeger, Tempo, etc.).
//  - DEMO: con SYNTHEX_TRACE=console imprime una línea por etapa con su duración (sin backend),
//    para que las latencias se vean en la demo. NO afirmamos export en producción si no hay endpoint.
import { trace, metrics, SpanStatusCode } from "@opentelemetry/api";

const VERSION = "0.2.0";
const tracer = trace.getTracer("synthex", VERSION);
const meter = metrics.getMeter("synthex", VERSION);

// Métricas GenAI SemConv (v1.37) + dos custom de Synthex.
const opDuration = meter.createHistogram("gen_ai.client.operation.duration", { unit: "ms", description: "Duración por etapa del pipeline" });
const tokenUsage = meter.createCounter("gen_ai.client.token.usage", { unit: "token", description: "Tokens consumidos por CLASSIFY" });
const blockedCounter = meter.createCounter("synthex.blocked.count", { description: "Documentos bloqueados por FORGE pre-LLM" });
const sealedCounter = meter.createCounter("synthex.evidence.sealed", { description: "Evidence Reports sellados" });

const CONSOLE = process.env.SYNTHEX_TRACE === "console" || process.env.SYNTHEX_TRACE === "1";

let sdk = null;
let started = false;

/**
 * Arranca el NodeSDK de OTel SOLO si hay un endpoint OTLP configurado. Idempotente y best-effort:
 * si el SDK no está disponible o falla, el pipeline sigue (los spans quedan no-op). Devuelve true
 * si se arrancó un exporter real.
 */
export async function startTelemetry() {
  if (started) return !!sdk;
  started = true;
  const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  if (!endpoint) return false;
  try {
    const { NodeSDK } = await import("@opentelemetry/sdk-node");
    const { OTLPTraceExporter } = await import("@opentelemetry/exporter-trace-otlp-http");
    const { OTLPMetricExporter } = await import("@opentelemetry/exporter-metrics-otlp-http");
    const { PeriodicExportingMetricReader } = await import("@opentelemetry/sdk-metrics");
    sdk = new NodeSDK({
      serviceName: "apohara-synthex",
      traceExporter: new OTLPTraceExporter(),
      metricReader: new PeriodicExportingMetricReader({ exporter: new OTLPMetricExporter(), exportIntervalMillis: 5000 }),
    });
    sdk.start();
    return true;
  } catch (e) {
    if (CONSOLE) console.error("[telemetry] SDK no disponible:", e.message);
    sdk = null;
    return false;
  }
}

/** Cierra el SDK (flush de spans/métricas pendientes). No-op si no se arrancó. */
export async function shutdownTelemetry() {
  if (sdk) { try { await sdk.shutdown(); } catch { /* best-effort */ } }
}

/**
 * Envuelve una etapa del pipeline en un span con duración. `fn` recibe {span, record}:
 *   record(key, value) agrega un atributo synthex.<key> al span y a la línea de consola.
 * @template T
 * @param {string} stage  nombre de etapa (FETCH/FORGE/CLASSIFY/PROVE).
 * @param {(ctx:{span:object, record:(k:string,v:any)=>void}) => Promise<T>} fn
 * @returns {Promise<T>}
 */
export function withSpan(stage, fn) {
  const start = performance.now();
  return tracer.startActiveSpan(`synthex.${stage}`, async (span) => {
    span.setAttribute("gen_ai.operation.name", stage);
    span.setAttribute("gen_ai.provider.name", "synthex");
    const attrs = {};
    const record = (k, v) => { attrs[k] = v; span.setAttribute(`synthex.${k}`, v); };
    try {
      const result = await fn({ span, record });
      span.setStatus({ code: SpanStatusCode.OK });
      return result;
    } catch (e) {
      span.recordException(e);
      span.setStatus({ code: SpanStatusCode.ERROR, message: e.message });
      throw e;
    } finally {
      const ms = +(performance.now() - start).toFixed(1);
      opDuration.record(ms, { "gen_ai.operation.name": stage });
      if (CONSOLE) {
        const extra = Object.entries(attrs).map(([k, v]) => `${k}=${v}`).join(" ");
        console.error(`[synthex.${stage}] duration=${ms}ms ${extra}`.trimEnd());
      }
      span.end();
    }
  });
}

/** Registra tokens consumidos por CLASSIFY (input/output) desde el usage de la AI/ML API. */
export function recordTokens(usage) {
  if (!usage) return;
  if (usage.prompt_tokens) tokenUsage.add(usage.prompt_tokens, { "gen_ai.token.type": "input" });
  if (usage.completion_tokens) tokenUsage.add(usage.completion_tokens, { "gen_ai.token.type": "output" });
}

export function recordBlocked(n) { if (n) blockedCounter.add(n); }
export function recordSealed() { sealedCounter.add(1); }
