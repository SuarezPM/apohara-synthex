// MEMORY — store local de evidencias/entidades. Camino PRIMARIO: persistencia JSON,
// funcional y sin dependencias. Permite recordar qué se clasificó por target/lens y
// recuperarlo entre corridas (base del monitoreo y del knowledge graph).
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export class MemoryStore {
  constructor({ path = process.env.SYNTHEX_MEMORY_PATH || ".synthex-memory.json" } = {}) {
    this.path = path;
    this.records = existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : [];
  }

  /** Guarda un registro (p.ej. {target, lens, evidenceHash, severity}). */
  remember(record) {
    const entry = { ...record, rememberedAt: new Date().toISOString() };
    this.records.push(entry);
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
