// PROVE/report/risk-score — the deterministic, published, reproducible Risk Score (P5). Moved
// out of pdf-report.js so both the orchestrator (which re-exports it for tests) and page-broker
// import from one place without a circular dep. Logic is UNCHANGED from Phase 1.
//
// Risk Score 0–100 — fórmula determinista ANCLADA en frameworks públicos NOMBRADOS (mapping,
// NOT endorsement): severidad usa la escala CVSS 0–10; bandas alineadas a CVSS severity ratings
// (High ≥ 7.0); encuadre de cumplimiento mapeado a NIST AI RMF y EU AI Act. EPSS documentado
// como input futuro. NO es evaluación de un tercero ni calificación de suscripción. Ver
// docs/compliance-mapping.md.
//
//   maxSev   = máxima severity entre findings (escala CVSS 0..10)  → 70% del peso
//   blockTerm= min(blockedCount, 5) / 5 * 10  (0..10)              → 30% del peso
//   score    = round( (maxSev*0.7 + blockTerm*0.3) * 10 )          → 0..100
import { cveIdsFromFinding, epssWeight } from "../epss.js";

function rowsOf(finding) {
  if (finding.trilens) {
    return Object.entries(finding.trilens).map(([lens, c]) => ({ url: finding.url, lens, ...c }));
  }
  return [{ url: finding.url, lens: finding.lens, severity: finding.severity, summary: finding.summary, signals: finding.signals }];
}
function allRows(findings) {
  return findings.flatMap(rowsOf);
}

/** @returns {{score:number, band:string, maxSev:number, blocked:number}} */
export function riskScore(evidence) {
  const findings = evidence?.payload?.findings ?? [];
  const blocked = (evidence?.payload?.blocked ?? []).length;
  const sevs = allRows(findings).map((r) => Number(r.severity) || 0);
  const maxSev = sevs.length ? Math.max(...sevs) : 0;
  const blockTerm = (Math.min(blocked, 5) / 5) * 10;
  const score = Math.round((maxSev * 0.7 + blockTerm * 0.3) * 10);
  const band = score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW";
  return { score, band, maxSev, blocked };
}

/**
 * EPSS-weighted Risk Score — ADDITIVE, render-time, NON-SEALED enrichment (item R1). The base
 * riskScore() is the single source of truth and is UNCHANGED; this layers an OPTIONAL EPSS
 * multiplier on the severity term when the maxSev finding names a CVE in `epssMap`. With a
 * null/empty map (or no CVE match) it returns the base result with `weighted:false`.
 * @param {object} evidence
 * @param {Map<string,{epss:number}>|null} epssMap
 */
export function riskScoreWeighted(evidence, epssMap) {
  const base = riskScore(evidence);
  if (!(epssMap instanceof Map) || epssMap.size === 0) return { ...base, weighted: false };
  const rows = allRows(evidence?.payload?.findings ?? []);
  const topCves = rows
    .filter((r) => (Number(r.severity) || 0) === base.maxSev)
    .flatMap((r) => cveIdsFromFinding(r));
  const { factor, epss, cve } = epssWeight(epssMap, topCves);
  if (epss === null) return { ...base, weighted: false };
  const weightedMaxSev = Math.min(10, base.maxSev * factor);
  const blockTerm = (Math.min(base.blocked, 5) / 5) * 10;
  const weightedScore = Math.round((weightedMaxSev * 0.7 + blockTerm * 0.3) * 10);
  const weightedBand = weightedScore >= 70 ? "HIGH" : weightedScore >= 40 ? "MEDIUM" : "LOW";
  return { ...base, weighted: true, weightedScore, weightedBand, weightedMaxSev, epss, cve };
}
