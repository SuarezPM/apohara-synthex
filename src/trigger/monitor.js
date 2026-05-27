// TRIGGER — monitoreo event-driven. Camino PRIMARIO: cron/manual, funcional y sin
// dependencias externas. Corre el pipeline por target y dispara alertas cuando la
// severidad supera un umbral. (La integración con TriggerWare.ai es opcional/futura:
// ver triggerware-client.js — su API no es pública aún.)

export class Monitor {
  /** @param {{pipeline:Function, intervalMs?:number, threshold?:number, onAlert?:Function}} opts */
  constructor({ pipeline, intervalMs = 3_600_000, threshold = 7, onAlert } = {}) {
    if (typeof pipeline !== "function") throw new Error("Monitor requiere un pipeline(target)=>evidence.");
    this.pipeline = pipeline;
    this.intervalMs = intervalMs;
    this.threshold = threshold;
    this.onAlert = onAlert ?? (() => {});
    this.targets = new Set();
    this._timer = null;
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

  /** Arranca el loop por cron (setInterval). unref() para no bloquear la salida del proceso. */
  start() {
    this._timer = setInterval(() => { this.runOnce().catch(() => {}); }, this.intervalMs);
    if (this._timer.unref) this._timer.unref();
    return this;
  }
  stop() { if (this._timer) clearInterval(this._timer); this._timer = null; return this; }
}
