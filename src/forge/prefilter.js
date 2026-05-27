// FORGE/prefilter — pre-filtro determinista (sin LLM), estilo OWASP.
// Subconjunto portado de las reglas de apohara-aegis (Deterministic Judge Layer) a regex JS.
// Corre ANTES de AI/ML API para abaratar/acelerar: bloquea lo obvio sin gastar una llamada.
//
// v2 (auditoría Mayo 2026): +8 reglas que cubren vectores documentados en BrowseSafe
// (Perplexity, 2026) y VPI-Bench (2026). HONESTIDAD: este filtro cubre injection
// basada en TEXTO/HTML; NO detecta VPI *visual* (capturas/imágenes renderizadas).
// Las reglas de ocultamiento CSS (PI-5/9/10) son INDICADORES de técnica de entrega
// (severity<8 → REVIEW, común en HTML benigno): el payload real lo bloquean PI-1..PI-8.
const RULES = [
  { id: "PI-1", re: /ignore (all |the )?(previous|prior|above) (instructions|prompts)/i, category: "prompt-injection", severity: 9 },
  { id: "PI-2", re: /disregard (your |the )?(system )?(prompt|instructions)/i, category: "prompt-injection", severity: 9 },
  { id: "PI-3", re: /you are now (a |an )?(dan|jailbroken|developer mode)/i, category: "prompt-injection", severity: 8 },
  { id: "PI-4", re: /\b(reveal|print|show|leak) (me )?(your |the )?(system prompt|instructions|api key|secret)/i, category: "prompt-injection", severity: 8 },
  // v2 — vectores BrowseSafe / VPI-Bench (2026)
  { id: "PI-5", re: /style\s*=\s*["'][^"']*visibility\s*:\s*hidden[^"']*["']/i, category: "prompt-injection", severity: 7 }, // texto invisible (indicador)
  { id: "PI-6", re: /<!--[\s\S]{0,200}\b(ignore|disregard|override|new instruction)/i, category: "prompt-injection", severity: 8 }, // smuggling en comentario HTML
  { id: "PI-7", re: /[\u202a-\u202e\u2066-\u2069]/, category: "prompt-injection", severity: 8 }, // Trojan Source: bidi override (CVE-2021-42574)
  { id: "PI-8", re: /<meta[^>]+content\s*=\s*["'][^"']*(ignore|system.?prompt|you\s+are)[^"']*["']/i, category: "prompt-injection", severity: 8 }, // injection en meta-tag
  { id: "PI-9", re: /font-size\s*:\s*0(\s*px)?\b/i, category: "prompt-injection", severity: 6 }, // texto a 0px (indicador)
  { id: "PI-10", re: /color\s*:\s*(white|#fff(fff)?|rgba?\(\s*255\s*,\s*255\s*,\s*255)/i, category: "prompt-injection", severity: 6 }, // texto blanco (indicador)
  { id: "SQLI-1", re: /('|")\s*(or|and)\s+\d+\s*=\s*\d+/i, category: "sqli", severity: 8 },
  { id: "SQLI-2", re: /\bunion\s+select\b/i, category: "sqli", severity: 8 },
  { id: "SQLI-3", re: /;\s*(drop|delete|truncate)\s+(table|database)\b/i, category: "sqli", severity: 9 },
  { id: "XSS-1", re: /<script[\s>]/i, category: "xss", severity: 7 },
  { id: "XSS-2", re: /javascript:\s*\S/i, category: "xss", severity: 6 },
  { id: "XSS-3", re: /\bon(error|load|click|mouseover)\s*=\s*['"]?/i, category: "xss", severity: 6 },
  { id: "EXF-1", re: /\b(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b/, category: "secret-exfil", severity: 9 },
  { id: "EXF-2", re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, category: "secret-exfil", severity: 10 },
  { id: "EXF-3", re: /\bgh[opsur]_[A-Za-z0-9]{36,}\b/, category: "secret-exfil", severity: 9 }, // GitHub tokens (PAT/OAuth/user/server/refresh)
  { id: "EXF-4", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, category: "secret-exfil", severity: 9 }, // Slack tokens
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
