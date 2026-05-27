// FORGE/prefilter — pre-filtro determinista (sin LLM), estilo OWASP.
// Subconjunto portado de las reglas de apohara-aegis (Deterministic Judge Layer) a regex JS.
// Corre ANTES de AI/ML API para abaratar/acelerar: bloquea lo obvio sin gastar una llamada.
const RULES = [
  { id: "PI-1", re: /ignore (all |the )?(previous|prior|above) (instructions|prompts)/i, category: "prompt-injection", severity: 9 },
  { id: "PI-2", re: /disregard (your |the )?(system )?(prompt|instructions)/i, category: "prompt-injection", severity: 9 },
  { id: "PI-3", re: /you are now (a |an )?(dan|jailbroken|developer mode)/i, category: "prompt-injection", severity: 8 },
  { id: "PI-4", re: /\b(reveal|print|show|leak) (me )?(your |the )?(system prompt|instructions|api key|secret)/i, category: "prompt-injection", severity: 8 },
  { id: "SQLI-1", re: /('|")\s*(or|and)\s+\d+\s*=\s*\d+/i, category: "sqli", severity: 8 },
  { id: "SQLI-2", re: /\bunion\s+select\b/i, category: "sqli", severity: 8 },
  { id: "SQLI-3", re: /;\s*(drop|delete|truncate)\s+(table|database)\b/i, category: "sqli", severity: 9 },
  { id: "XSS-1", re: /<script[\s>]/i, category: "xss", severity: 7 },
  { id: "XSS-2", re: /javascript:\s*\S/i, category: "xss", severity: 6 },
  { id: "XSS-3", re: /\bon(error|load|click|mouseover)\s*=\s*['"]?/i, category: "xss", severity: 6 },
  { id: "EXF-1", re: /\b(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b/, category: "secret-exfil", severity: 9 },
  { id: "EXF-2", re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, category: "secret-exfil", severity: 10 },
];

/**
 * Clasifica texto contra las reglas deterministas.
 * @returns {{severity:number, action:"BLOCK"|"REVIEW"|"ALLOW", category:(string|null), matched:object[]}}
 */
export function classify(text) {
  const s = String(text ?? "");
  const matched = [];
  let maxSeverity = 0;
  for (const r of RULES) {
    if (r.re.test(s)) {
      matched.push({ id: r.id, category: r.category, severity: r.severity });
      if (r.severity > maxSeverity) maxSeverity = r.severity;
    }
  }
  const action = maxSeverity >= 8 ? "BLOCK" : maxSeverity >= 5 ? "REVIEW" : "ALLOW";
  return { severity: maxSeverity, action, category: matched[0]?.category ?? null, matched };
}

export { RULES };
