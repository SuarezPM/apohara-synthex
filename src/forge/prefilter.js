// FORGE/prefilter — pre-filtro determinista web-injection (sin LLM), estilo OWASP.
// 28 reglas regex JS sobre HTML/texto scrapeado. Corre ANTES de la llamada al LLM
// (AI/ML API) para abaratar/acelerar: bloquea lo obvio sin gastar tokens.
//
// v2 (auditoría Mayo 2026): +8 reglas que cubren vectores documentados en BrowseSafe
// (Perplexity, 2026) y VPI-Bench (2026). HONESTIDAD: este filtro cubre injection
// basada en TEXTO/HTML; NO detecta VPI *visual* (capturas/imágenes renderizadas).
// Las reglas de ocultamiento CSS (PI-5/9/10) son INDICADORES de técnica de entrega
// (severity<8 → REVIEW, común en HTML benigno): el payload real lo bloquean PI-1..PI-8.
//
// v3 (auditoría Mayo 2026): +8 reglas (SSRF, prototype pollution, MCP tool poisoning,
// indirect PI en datos estructurados). HONESTIDAD: estas son regex HEURÍSTICAS,
// "aligned with" el benchmark SkillFortify (arXiv 2603.00195) — NO "formally verified".
// No hay garantía formal de cobertura; cubren los vectores documentados, no su clausura.
//
// v3.1 (auditoría Deep-Research, Mayo 2026): hardening de regex SIN reglas nuevas (conteo 28
// intacto). Cerrados 2 huecos reales hallados en el audit: PROTO-1 ahora atrapa proto-pollution
// JSON-anidada ("constructor":{"prototype"}) — antes solo "constructor.prototype" con punto;
// MCP-2 ahora atrapa <tool_response> — antes solo tool_result/function_results/tool_use.
// Candidatos ARIA/alt-text DESCARTADOS: el texto de instrucción ya lo atrapan PI-*/MCP-1
// (una regla sobre aria-label/alt= dispararía falsos positivos en todo sitio accesible).
const RULES = [
  { id: "PI-1", re: /ignore (all |the )?(previous|prior|above) (instructions|prompts)/i, category: "prompt-injection", severity: 9 },
  { id: "PI-2", re: /disregard (your |the )?(system )?(prompt|instructions)/i, category: "prompt-injection", severity: 9 },
  // v3.2 — Spanish/voseo prompt-injection. Rioplatense + neutro. Pareja del PI-1/PI-2
  // inglés para que un atacante hispanohablante no esquive con sólo cambiar idioma.
  { id: "PI-ES-1", re: /\bignor[áa]\s+(las|todas las|esas|las anteriores)\s+(instrucciones|reglas|órdenes|directivas)/i, category: "prompt-injection", severity: 9 },
  { id: "PI-ES-2", re: /\bolvid[áa]\s+(todo|las|todas las|esas)\s+(instrucciones|reglas|órdenes)/i, category: "prompt-injection", severity: 9 },
  { id: "PI-ES-3", re: /\bsos\s+(ahora|un nuevo|otro)\s+(dan|jailbroken|agente|asistente sin)/i, category: "prompt-injection", severity: 8 },
  { id: "PI-ES-4", re: /\bsin\s+(restricciones|filtros|límites|reglas|censura)\b/i, category: "prompt-injection", severity: 8 },
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
  // v3 — SSRF / prototype pollution / MCP tool poisoning / indirect PI (aligned with SkillFortify, arXiv 2603.00195)
  { id: "SSRF-1", re: /\b(?:https?:\/\/)?(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b/i, category: "ssrf", severity: 9 }, // cloud metadata endpoint (AWS/GCP/Alibaba)
  { id: "SSRF-2", re: /\b(?:file|gopher|dict):\/\//i, category: "ssrf", severity: 8 }, // esquemas SSRF/exfil clásicos
  { id: "SSRF-3", re: /\bhttps?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?:[:/]|\b)/i, category: "ssrf", severity: 8 }, // host interno embebido en URL
  { id: "PROTO-1", re: /(?:"__proto__"|\b__proto__\s*[:=[]|constructor\s*\.\s*prototype|"constructor"\s*:\s*\{\s*"prototype"|\bprototype\s*\[)/, category: "proto-pollution", severity: 8 }, // prototype pollution / JSON hijacking (incl. JSON-LD nested "constructor":{"prototype"})
  { id: "MCP-1", re: /\bwhen (?:you (?:see|receive|read)|reading) this[\s,]+(?:call|invoke|use|run|execute|trigger)\b/i, category: "tool-poisoning", severity: 8 }, // ClawHavoc: instrucción oculta en descripción de tool
  { id: "MCP-2", re: /<(?:tool[_-]?result|tool[_-]?response|function[_-]?results?|tool_use)>[\s\S]{0,200}\b(?:ignore|disregard|override|new instruction|system:)/i, category: "tool-poisoning", severity: 8 }, // tool-result/response injection (envuelto en tags de resultado)
  { id: "IPI-1", re: /(?:^|[\s"',[{>])(?:assistant|system|developer)\s*:\s*\S/im, category: "indirect-injection", severity: 6 }, // role override embebido en campo JSON/CSV (indicador)
  { id: "IPI-2", re: /\b(?:role"?\s*:\s*"?(?:system|assistant|developer)|<\|(?:im_start|system|assistant)\|>)/i, category: "indirect-injection", severity: 7 }, // chat-template/role-key smuggling en datos estructurados
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

// POLICY_BUNDLE_VERSION — sha256 truncado del corpus canónico (mismo patrón que djl.js).
// Formato: `prefilter-v<major>-<sha256-12>`. Bump del `vN` solo si cambia contrato severity
// o se elimina una rule_id. El hash captura cambios en regex/category automáticamente.
import { createHash as _createHash } from "node:crypto";
const _prefilterCorpus = JSON.stringify(
  RULES
    .map((r) => [r.id, r.re.source, r.severity, r.category])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)),
);
export const POLICY_BUNDLE_VERSION = `prefilter-v3-${_createHash("sha256").update(_prefilterCorpus).digest("hex").slice(0, 12)}`;
