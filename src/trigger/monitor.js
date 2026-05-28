// TRIGGER — monitoreo event-driven. Camino PRIMARIO: cron/manual, funcional y sin
// dependencias externas. Corre el pipeline por target y dispara alertas cuando la
// severidad supera un umbral. (La integración con TriggerWare.ai es opcional/futura:
// ver triggerware-client.js — su API no es pública aún.)
//
// v0.6.0: añade runOnceWithDelta() — método append-only que enriquece cada alerta
// con la cadena de evidencia delta vs la última lectura del mismo target
// (sealDeltaChain encadena previous_tsa_serial → current_tsa_serial).
// El contrato del pipeline (pipeline(target)=>evidence) se preserva para back-compat.
import { sealDeltaChain } from "../delta/index.js";

export class Monitor {
  /** @param {{pipeline:Function, intervalMs?:number, threshold?:number, onAlert?:Function, hmacKey?:string}} opts */
  constructor({ pipeline, intervalMs = 3_600_000, threshold = 7, onAlert, hmacKey } = {}) {
    if (typeof pipeline !== "function") throw new Error("Monitor requiere un pipeline(target)=>evidence.");
    this.pipeline = pipeline;
    this.intervalMs = intervalMs;
    this.threshold = threshold;
    this.onAlert = onAlert ?? (() => {});
    this.hmacKey = hmacKey;
    this.targets = new Set();
    this._timer = null;
    // v0.6.0: cache del último evidence sellado por target, para sealDeltaChain en
    // runOnceWithDelta(). Map<target, evidence>. Vive en memoria — para persistencia
    // real (oncall, cluster), el llamador puede inyectar opts.lastEvidence: Map<>.
    this.lastEvidence = new Map();
  }

  watch(target) { this.targets.add(target); return this; }
  unwatch(target) { this.targets.delete(target); return this; }

  /** Una ronda de monitoreo: corre el pipeline por cada target y emite alertas. */
  async runOnce() {
    const alerts = [];
    for (const target of this.targets) {
      const evidence = await this.pipeline(target);
      const findings = evidence?.payload?.findings ?? [];
      const maxSeverity = findings.reduce((m, f) => Math.max(m, f.severity ?? 0), 0);
      if (maxSeverity >= this.threshold) {
        const alert = {
          target,
          severity: maxSeverity,
          evidenceHash: evidence.contentHash,
          at: new Date().toISOString(),
        };
        alerts.push(alert);
        await this.onAlert(alert);
      }
    }
    return alerts;
  }

  /**
   * v0.6.0 — corre el pipeline y encadena cada evidence con sealDeltaChain.
   * Cada alerta sale enriquecida con deltaSummary y previous_tsa_serial,
   * para que el operador vea "qué cambió desde la última lectura" en vez
   * de solo "severidad alta ahora".
   * @returns {Promise<Array>} alertas con shape {target, severity, evidenceHash, deltaSummary, at, previousTsaSerial, currentTsaSerial}
   */
  async runOnceWithDelta() {
    const alerts = [];
    for (const target of this.targets) {
      const evidence = await this.pipeline(target);
      const findings = evidence?.payload?.findings ?? [];
      const content = evidence?.payload?.content ?? evidence?.payload?.text ?? JSON.stringify(findings);
      const prev = this.lastEvidence.get(target) ?? null;
      const chained = await sealDeltaChain({
        prev_evidence: prev,
        curr_snapshot: {
          target,
          lens: evidence?.payload?.lens ?? null,
          content: String(content),
          fetchedAt: evidence?.payload?.fetchedAt ?? new Date().toISOString(),
          findings,
        },
        hmacKey: this.hmacKey,
        // requestTsa default true del core; el integration test usa stub HTTP que no llega a TSA real,
        // así que el TSA queda null y currentTsaSerial null — esperado y no-falla.
      });
      this.lastEvidence.set(target, chained);

      const maxSeverity = findings.reduce((m, f) => Math.max(m, f.severity ?? 0), 0);
      const dc = chained.payload.delta_chain ?? {};
      // Emite alerta cuando supera threshold O cuando hay cualquier cambio detectado
      // (un cambio de pricing sin que la severidad cambie igual es señal accionable).
      const hasChange = (dc.diff_summary?.added ?? 0) + (dc.diff_summary?.removed ?? 0) > 0;
      const shouldAlert = maxSeverity >= this.threshold || (prev !== null && hasChange);
      if (shouldAlert) {
        const alert = {
          target,
          severity: maxSeverity,
          evidenceHash: chained.contentHash,
          deltaSummary: dc.diff_summary ?? null,
          previousTsaSerial: dc.previous_tsa_serial ?? null,
          currentTsaSerial: dc.current_tsa_serial ?? null,
          at: new Date().toISOString(),
        };
        alerts.push(alert);
        await this.onAlert(alert);
      }
    }
    return alerts;
  }

  /** Arranca el loop por cron (setInterval). unref() para no bloquear la salida del proceso. */
  start() {
    this._timer = setInterval(() => { this.runOnce().catch(() => {}); }, this.intervalMs);
    if (this._timer.unref) this._timer.unref();
    return this;
  }
  stop() { if (this._timer) clearInterval(this._timer); this._timer = null; return this; }
}
