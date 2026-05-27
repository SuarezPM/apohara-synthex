// FORGE — preparación de contexto del pipeline: dedup (SHA-256) + pre-filtro OWASP.
// Nota honesta: el gate INV-15 (inv15-gate.js) es la implementación JS del invariante del
// paper Context_Forge (DOI 10.5281/zenodo.20277875) — se conserva como módulo y prior-art
// citado, pero NO forma parte del pipeline de scraping (no aplica a un flujo sin juez/cache).
export { dedupe } from "./dedup.js";
export { classify as prefilter } from "./prefilter.js";
