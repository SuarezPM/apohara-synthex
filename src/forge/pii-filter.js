// PII FILTER (T2.3 del PRD v0.6.0) — bundle dedicado para gating de Cognee ingest
// durante el stress test. Reusa las 10 reglas existentes DJL-PII-001..010 (definidas
// en src/forge/djl.js, category="pii") y añade 15 reglas PII-EXT centradas en secrets
// leakage (cloud creds, API keys, JWT) + patterns de bulk PII.
//
// Total: 25 reglas (NO 78 — el conteo de "78 DJL" incluye PI/SQLI/XSS/EXF/MIS/POL/HARM
// que NO son PII filter. Critic R1 F3 + R2 #2 cumplido).
//
// Comportamiento: evaluate(text) → {matched, max_severity, rule_ids}. Si matched=true,
// el caller (stress script, monitor) decide skip de cognee.remember y marca
// payload.delta_chain.kg_skip_reason = "pii_filter".

import { RULES as DJL_RULES } from "./djl.js";
import { createHash } from "node:crypto";

// Re-exportar las 10 reglas DJL-PII (filtradas por category).
const DJL_PII_RULES = DJL_RULES.filter((r) => r.category === "pii");

// 15 reglas PII-EXT — secretos / credenciales / patterns de bulk leak.
// Diseñadas para no superponer con DJL-PII existente (ids no chocan).
export const PII_EXT_RULES = Object.freeze([
  { id: "PII-EXT-001", re: /\bAKIA[0-9A-Z]{16}\b/, severity: 10, description: "AWS Access Key ID (AKIA prefix)." },
  { id: "PII-EXT-002", re: /\b(?:aws_)?secret(?:_access)?_key["'\s:=]+[A-Za-z0-9/+=]{40}\b/i, severity: 10, description: "AWS Secret Access Key (40-char base64)." },
  { id: "PII-EXT-003", re: /\bAIza[0-9A-Za-z\-_]{35}\b/, severity: 10, description: "Google API Key (AIza prefix)." },
  { id: "PII-EXT-004", re: /\bsk_live_[0-9a-zA-Z]{24,99}\b/, severity: 10, description: "Stripe live secret key." },
  { id: "PII-EXT-005", re: /\bghp_[0-9A-Za-z]{36,40}\b/, severity: 10, description: "GitHub Personal Access Token (ghp_)." },
  { id: "PII-EXT-006", re: /\bgh[opsu]_[0-9A-Za-z]{36,40}\b/, severity: 10, description: "GitHub OAuth/server/user token (gho_/ghs_/ghu_)." },
  { id: "PII-EXT-007", re: /\bnpm_[A-Za-z0-9]{36}\b/, severity: 10, description: "npm publish token." },
  { id: "PII-EXT-008", re: /\bxox[abprs]-[0-9]+-[0-9]+-[0-9]+-[0-9a-zA-Z]{24,32}\b/, severity: 10, description: "Slack bot/user/refresh token." },
  { id: "PII-EXT-009", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/, severity: 10, description: "PEM private key block header." },
  { id: "PII-EXT-010", re: /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/, severity: 9, description: "JSON Web Token (3-segment dot-separated b64url)." },
  { id: "PII-EXT-011", re: /\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b/, severity: 10, description: "SendGrid API key." },
  { id: "PII-EXT-012", re: /\bAC[0-9a-f]{32}\b/, severity: 8, description: "Twilio Account SID (AC + 32 hex)." },
  { id: "PII-EXT-013", re: /\b(?:[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}[\s,;]*){5,}/, severity: 7, description: "Bulk email harvest (>=5 contiguous emails)." },
  { id: "PII-EXT-014", re: /\b9\d{2}[\s\-]?\d{2}[\s\-]?\d{4}\b/, severity: 8, description: "US Individual Taxpayer ID Number (ITIN, 9xx-xx-xxxx)." },
  { id: "PII-EXT-015", re: /\bglpat-[0-9A-Za-z\-_]{20}\b/, severity: 10, description: "GitLab Personal Access Token (glpat-)." },
]);

// Corpus combinado: 10 + 15 = 25.
export const PII_RULES = Object.freeze([...DJL_PII_RULES, ...PII_EXT_RULES]);

// Versión del bundle (sha del corpus de IDs+descriptions, para policy_bundle_version
// que se sella en el payload — Critic R3 requirement de trazabilidad).
const _corpus = PII_RULES.map((r) => `${r.id}|${r.description}`).join("\n");
export const PII_POLICY_BUNDLE_VERSION = `pii-v1-${createHash("sha256").update(_corpus).digest("hex").slice(0, 12)}`;

/**
 * Evalúa si `text` contiene PII filtrable. NO mutate; pure.
 * @param {string} text
 * @returns {{matched: boolean, max_severity: number, rule_ids: string[], matches: Array}}
 */
export function evaluate(text) {
  if (typeof text !== "string" || text.length === 0) {
    return { matched: false, max_severity: 0, rule_ids: [], matches: [] };
  }
  const matches = [];
  let maxSev = 0;
  for (const rule of PII_RULES) {
    if (rule.re.test(text)) {
      matches.push({ rule_id: rule.id, severity: rule.severity, description: rule.description });
      if (rule.severity > maxSev) maxSev = rule.severity;
    }
  }
  return {
    matched: matches.length > 0,
    max_severity: maxSev,
    rule_ids: matches.map((m) => m.rule_id),
    matches,
  };
}

/**
 * Conveniente para gating de KG ingest: ¿debo skip cognee.remember sobre este content?
 * Default threshold: severity >= 7 (US passport, IBAN, AWS keys, GitHub PAT, JWTs, etc.).
 */
export function shouldSkipKgIngest(text, { threshold = 7 } = {}) {
  const r = evaluate(text);
  return { skip: r.matched && r.max_severity >= threshold, reason: r.matched ? `pii_filter:${r.rule_ids[0]}` : null, ...r };
}
