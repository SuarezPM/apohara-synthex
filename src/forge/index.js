// FORGE — preparación de contexto del pipeline: dedup (SHA-256) + pre-filtro OWASP.
export { dedupe } from "./dedup.js";
export { classify as prefilter } from "./prefilter.js";
