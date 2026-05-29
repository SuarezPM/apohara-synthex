// FORGE/inv15-gate — JCR Safety Gate (invariante INV-15), heurístico determinista O(1).
// Portado del jcr_gate.py de Context_Forge. Fuerza dense-prefill (bypass de cache reusado)
// para agentes juez/crítico cuando el riesgo de contaminación supera el umbral.
// Respaldo formal: paper INV-15 (Zenodo DOI 10.5281/zenodo.20277875) — citado como prior-art.

/**
 * Riesgo JCR en [0,1].
 * @param {{role:string, candidateCount?:number, reuseRate?:number, layoutShuffled?:boolean}} p
 */
export function computeJcrRisk({ role, candidateCount = 1, reuseRate = 0, layoutShuffled = false }) {
  let risk = (role === "judge" || role === "critic") ? 0.6 : 0.1;
  risk += 0.10 * Math.max(0, candidateCount - 1);
  if (layoutShuffled) risk += 0.20;
  if (reuseRate > 0.8) risk += 0.15;
  return Math.max(0, Math.min(1, risk));
}

/** ¿Forzar dense prefill (no reusar cache) para proteger al juez? */
export function shouldUseDensePrefill(role, risk) {
  return (role === "judge" || role === "critic") && risk > 0.7;
}
