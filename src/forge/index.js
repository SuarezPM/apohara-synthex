// FORGE — capa de preparación de contexto: dedup + gate de seguridad INV-15 + pre-filtro.
export { dedupe, ContextCache, fingerprint } from "./dedup.js";
export { computeJcrRisk, shouldUseDensePrefill } from "./inv15-gate.js";
export { classify as prefilter, RULES } from "./prefilter.js";
