// MEMORY — store local de evidencias/entidades. Camino PRIMARIO: persistencia JSON,
// funcional y sin dependencias. Permite recordar qué se clasificó por target/lens y
// recuperarlo entre corridas (base del monitoreo y del knowledge graph).
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

// v0.7.0 T5/M4 — ring-buffer cap para que monitorings de larga duración no inflen el JSON
// store ilimitadamente. Override vía SYNTHEX_MEMORY_MAX (entero positivo) o constructor opt.
export const DEFAULT_MAX_RECORDS = Number(process.env.SYNTHEX_MEMORY_MAX) || 5000;

export class MemoryStore {
  constructor({ path = process.env.SYNTHEX_MEMORY_PATH || ".synthex-memory.json", maxRecords = DEFAULT_MAX_RECORDS } = {}) {
    this.path = path;
    this.maxRecords = Math.max(1, Number(maxRecords) || DEFAULT_MAX_RECORDS);
    this.records = existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : [];
    // Carga inicial: si el store on-disk excede el cap (e.g. migración), evicta los más viejos.
    if (this.records.length > this.maxRecords) {
      this.records.splice(0, this.records.length - this.maxRecords);
    }
  }

  /** Guarda un registro (p.ej. {target, lens, evidenceHash, severity}). Ring buffer FIFO. */
  remember(record) {
    const entry = { ...record, rememberedAt: new Date().toISOString() };
    this.records.push(entry);
    // T5/M4 — evicta los más viejos si superamos el cap (FIFO).
    if (this.records.length > this.maxRecords) {
      this.records.splice(0, this.records.length - this.maxRecords);
    }
    this._persist();
    return entry;
  }

  /** Recupera registros que matcheen todos los campos de `query` (igualdad exacta). */
  recall(query = {}) {
    return this.records.filter((r) => Object.entries(query).every(([k, v]) => r[k] === v));
  }

  all() { return [...this.records]; }
  clear() { this.records = []; this._persist(); }

  _persist() {
    const dir = dirname(this.path);
    if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
    writeFileSync(this.path, JSON.stringify(this.records, null, 2));
  }
}
