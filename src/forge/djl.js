// SPDX-License-Identifier: MIT
//
// DJL — Zero-LLM Deterministic Judge Layer.
//
// 78 reglas regex deterministas pre-LLM en 8 categorías:
//   PI(20)   prompt injection         — override patterns, jailbreak, system-prompt exfil
//   SQLI(6)  SQL injection            — tautology, UNION, time-based blind
//   XSS(6)   cross-site scripting     — <script>, javascript:, on*= handlers
//   PII(10)  PII leakage              — SSN, CC, IBAN, passport, phone, email
//   EXF(5)   data exfiltration        — DB dump, export-all, curl-to-external
//   MIS(10)  tool/system misuse       — rm -rf, fork bomb, reverse shell, eval/exec
//   POL(5)   sector policy violation  — FINCEN, HIPAA, PCI, EO-13526, OT/ICS
//   HARM(16) harmful content (EN+ES)  — drugs, weapons, violence, self-harm, CSAM, hate
//
// Verdict mapping:
//   * any matched rule with severity >= 8 → BLOCK
//   * any matched rule with severity 5..7 → REVIEW
//   * otherwise                           → ALLOW
//
// Honesty contract: las latencias se miden en logs/djl-latency.json. NO editar números
// en este header sin re-correr el benchmark.

import { createHash } from "node:crypto";

// ---------------------------------------------------------------------------
// PI — Prompt Injection (20 rules)
// ---------------------------------------------------------------------------
const _RULES_PI = [
  { id: "DJL-PI-001", re: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?/i, category: "prompt_injection", severity: 9, description: "Classic 'ignore previous instructions' override." },
  { id: "DJL-PI-002", re: /disregard\s+(?:the\s+)?(?:system\s+)?(?:prompt|message|instructions?)/i, category: "prompt_injection", severity: 9, description: "'Disregard system prompt' override." },
  { id: "DJL-PI-003", re: /you\s+are\s+now\s+(?:a\s+)?(?:DAN|jailbroken|unrestricted|free|uncensored)/i, category: "prompt_injection", severity: 9, description: "Role re-assignment to known jailbreak persona (DAN, etc)." },
  { id: "DJL-PI-004", re: /\b(?:developer|dev|debug|admin|root|god|sudo)\s+mode\b/i, category: "prompt_injection", severity: 8, description: "Request to enter a privileged 'mode' that doesn't exist." },
  { id: "DJL-PI-005", re: /\bDAN\b(?:\s+mode|\s+prompt|\s+jailbreak)?/i, category: "prompt_injection", severity: 8, description: "Explicit DAN ('Do Anything Now') invocation." },
  { id: "DJL-PI-006", re: /\bjailbreak\b/i, category: "prompt_injection", severity: 8, description: "Direct 'jailbreak' lexical token." },
  { id: "DJL-PI-007", re: /pretend\s+(?:you\s+(?:are|have\s+no)|to\s+be)\s+(?:a\s+)?(?:hacker|criminal|villain|evil|no\s+restrictions?)/i, category: "prompt_injection", severity: 7, description: "Roleplay manipulation to remove safety persona." },
  { id: "DJL-PI-008", re: /act\s+as\s+(?:if\s+)?(?:you\s+(?:are|have)\s+)?(?:no\s+(?:restrictions?|safety|guardrails?|ethics?)|unrestricted|uncensored)/i, category: "prompt_injection", severity: 8, description: "'Act as if you have no restrictions' framing." },
  { id: "DJL-PI-009", re: /\b(?:[A-Za-z0-9+/]{80,}={0,2})\b/, category: "prompt_injection", severity: 7, description: "Suspiciously long base64 blob (possible instruction smuggle)." },
  { id: "DJL-PI-010", re: /[Ѐ-ӿͰ-Ͽ]{3,}/, category: "prompt_injection", severity: 6, description: "Cyrillic/Greek homoglyph cluster (Unicode confusable attack)." },
  { id: "DJL-PI-011", re: /[‪-‮⁦-⁩]/, category: "prompt_injection", severity: 9, description: "Bidirectional control character (Trojan-Source)." },
  { id: "DJL-PI-012", re: /new\s+(?:rules?|instructions?|directives?|guidelines?)\s*[:\-]/i, category: "prompt_injection", severity: 7, description: "Context-window displacement: redefining the rules." },
  { id: "DJL-PI-013", re: /(?:reveal|show|print|output|reproduce|repeat).{0,40}(?:system\s+prompt|initial\s+instructions?|hidden\s+(?:prompt|message|instructions?))/i, category: "prompt_injection", severity: 9, description: "System-prompt exfiltration attempt." },
  { id: "DJL-PI-014", re: /(?:end|terminate|exit|close|finish)\s+(?:of\s+)?(?:system\s+)?(?:prompt|instructions?|context|message)\s*[.!,]/i, category: "prompt_injection", severity: 7, description: "False 'end of system prompt' sentinel." },
  { id: "DJL-PI-015", re: /(?:assistant|model|ai|llm|chatgpt|gemini|claude)\s*[,:\-]\s*(?:please\s+)?(?:do|execute|run|forget|ignore)/i, category: "prompt_injection", severity: 7, description: "Indirect injection: addressing the assistant by name." },
  { id: "DJL-PI-016", re: /<\s*[/|]?\s*(?:system|user|assistant|im_start|im_end|im_sep)\b[^>]*>/i, category: "prompt_injection", severity: 8, description: "Chat-template control tag injection (<|im_start|> etc)." },
  { id: "DJL-PI-017", re: /\b(?:i\s+am|i'?m)\s+(?:the\s+)?(?:developer|creator|owner|admin|administrator|openai|anthropic|google)\b/i, category: "prompt_injection", severity: 7, description: "Confidence-hijacking: false claim of authority." },
  { id: "DJL-PI-018", re: /\brot[\-\s]?13\b|\bbase64[\s\-]?decode\b|\bdecode\s+(?:and|then)\s+(?:execute|run|follow)\b/i, category: "prompt_injection", severity: 8, description: "Instruction-smuggling via encoded payload directive." },
  { id: "DJL-PI-019", re: /this\s+is\s+(?:a\s+)?(?:test|simulation|hypothetical|fictional)\s+(?:scenario|exercise|environment)/i, category: "prompt_injection", severity: 6, description: "'This is just a test' rationalisation frame." },
  { id: "DJL-PI-020", re: /forget\s+(?:everything|all)\s+(?:above|before|prior|previously)/i, category: "prompt_injection", severity: 9, description: "'Forget everything above' override." },
];

// ---------------------------------------------------------------------------
// SQLI — SQL Injection (6 rules)
// ---------------------------------------------------------------------------
const _RULES_SQLI = [
  { id: "DJL-SQLI-001", re: /'\s*OR\s+1\s*=\s*1/i, category: "sqli", severity: 9, description: "Tautology-based SQLi: ' OR 1=1." },
  { id: "DJL-SQLI-002", re: /;\s*DROP\s+TABLE\b/i, category: "sqli", severity: 10, description: "Stacked SQLi: ; DROP TABLE." },
  { id: "DJL-SQLI-003", re: /(?:['`)\s\d]|^)UNION\s+(?:ALL\s+)?SELECT\s+(?:[*\w`,\s]+\s+)?FROM\b|['`)\d]\s*UNION\s+(?:ALL\s+)?SELECT\b/i, category: "sqli", severity: 9, description: "Union-based SQLi." },
  { id: "DJL-SQLI-004", re: /'\s*OR\s*'?x'?\s*=\s*'?x'?/i, category: "sqli", severity: 9, description: "Tautology SQLi: ' OR 'x'='x." },
  { id: "DJL-SQLI-005", re: /admin'\s*--/i, category: "sqli", severity: 9, description: "Auth-bypass SQLi: admin'--." },
  { id: "DJL-SQLI-006", re: /WAITFOR\s+DELAY\s+'\d|BENCHMARK\s*\(|SLEEP\s*\(\s*\d/i, category: "sqli", severity: 9, description: "Time-based blind SQLi." },
];

// ---------------------------------------------------------------------------
// XSS — Cross-Site Scripting (6 rules)
// ---------------------------------------------------------------------------
const _RULES_XSS = [
  { id: "DJL-XSS-001", re: /<\s*script\b[^>]*>/i, category: "xss", severity: 8, description: "Inline <script> tag." },
  { id: "DJL-XSS-002", re: /javascript\s*:/i, category: "xss", severity: 8, description: "javascript: pseudo-protocol." },
  { id: "DJL-XSS-003", re: /\bon(?:error|load|click|mouseover|focus|blur|change|submit|keypress)\s*=/i, category: "xss", severity: 8, description: "HTML event handler attribute (onerror, onload, etc)." },
  { id: "DJL-XSS-004", re: /<\s*iframe\b[^>]*\bsrc\s*=/i, category: "xss", severity: 7, description: "Inline <iframe src=> tag." },
  { id: "DJL-XSS-005", re: /<\s*img\b[^>]*\bonerror\s*=/i, category: "xss", severity: 8, description: "<img onerror=> XSS vector." },
  { id: "DJL-XSS-006", re: /data\s*:\s*text\/html|data\s*:\s*application\/x-javascript/i, category: "xss", severity: 8, description: "data: URL with HTML/JS payload." },
];

// ---------------------------------------------------------------------------
// PII — Personally Identifiable Information leakage (10 rules)
// ---------------------------------------------------------------------------
const _RULES_PII = [
  { id: "DJL-PII-001", re: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/, category: "pii", severity: 8, description: "US Social Security Number (XXX-XX-XXXX format)." },
  { id: "DJL-PII-002", re: /\b(?:\d[ \-]?){12,18}\d\b/, category: "pii", severity: 7, description: "Credit card number candidate (13-19 digit run)." },
  { id: "DJL-PII-003", re: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/, category: "pii", severity: 7, description: "IBAN bank account number." },
  { id: "DJL-PII-004", re: /\b[A-Z]\d{8}\b/, category: "pii", severity: 6, description: "US passport number candidate." },
  { id: "DJL-PII-005", re: /\+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}/, category: "pii", severity: 5, description: "International phone number (E.164)." },
  { id: "DJL-PII-006", re: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/, category: "pii", severity: 4, description: "Email address." },
  { id: "DJL-PII-007", re: /\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b/, category: "pii", severity: 7, description: "UK National Insurance Number." },
  { id: "DJL-PII-008", re: /\b(?<!\d)\d{11}(?!\d)\b/, category: "pii", severity: 6, description: "German Steuer-ID candidate (11-digit run)." },
  { id: "DJL-PII-009", re: /\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b/, category: "pii", severity: 4, description: "Date of birth (MM/DD/YYYY) candidate." },
  { id: "DJL-PII-010", re: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/, category: "pii", severity: 4, description: "IPv4 address (GDPR quasi-identifier)." },
];

// ---------------------------------------------------------------------------
// EXF — Data Exfiltration (5 rules)
// ---------------------------------------------------------------------------
const _RULES_EXFIL = [
  { id: "DJL-EXF-001", re: /\bdump\b[^\n]{0,40}\b(?:database|db|table|schema)\b/i, category: "exfiltration", severity: 9, description: "Database dump request." },
  { id: "DJL-EXF-002", re: /\bexport\s+(?:all\s+|every\s+)?(?:users?|customers?|records?|rows?|emails?|accounts?)\b/i, category: "exfiltration", severity: 8, description: "'Export all users/records' request." },
  { id: "DJL-EXF-003", re: /\blist\s+every\s+(?:record|user|customer|account|file|secret|credential|api[\s\-]?key)\b/i, category: "exfiltration", severity: 8, description: "'List every record' enumeration request." },
  { id: "DJL-EXF-004", re: /\b(?:send|post|forward|upload|exfiltrate|transmit)\s+(?:this\s+|that\s+|the\s+|all\s+)?(?:data|results?|output|content|info(?:rmation)?)\s+(?:to\s+)?(?:https?:\/\/|ftp:\/\/|webhook|external|endpoint)/i, category: "exfiltration", severity: 9, description: "Send-to-external-endpoint exfiltration directive." },
  { id: "DJL-EXF-005", re: /\b(?:curl|wget|nc|netcat|ncat|fetch|httpie)\b[^\n]{0,80}\bhttps?:\/\/[A-Za-z0-9.\-]+/i, category: "exfiltration", severity: 8, description: "curl/wget call to an external HTTP(S) host." },
];

// ---------------------------------------------------------------------------
// MIS — Tool / System Misuse (10 rules)
// ---------------------------------------------------------------------------
const _RULES_MISUSE = [
  { id: "DJL-MIS-001", re: /\brm\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+-rf\b/i, category: "tool_misuse", severity: 10, description: "rm -rf destructive filesystem call." },
  { id: "DJL-MIS-002", re: /\bdelete\s+all\s+(?:files?|records?|users?|accounts?|data|backups?)\b/i, category: "tool_misuse", severity: 10, description: "'Delete all' destructive directive." },
  { id: "DJL-MIS-003", re: /(?:transfer|wire|send|pay|remit)\b[^\n]{0,40}(?:\$|€|£|¥|USD|EUR|GBP|JPY)\s*(?:\d{1,3}(?:[,.]?\d{3}){1,}|[1-9]\d{4,})/i, category: "tool_misuse", severity: 9, description: "Financial transfer >= 10,000 of any currency." },
  { id: "DJL-MIS-004", re: /\b(?:auto|automatically|silently|without\s+(?:review|approval|confirmation))\s+(?:merge|approve|deploy|push)\b/i, category: "tool_misuse", severity: 8, description: "Unauthorized auto-merge / auto-deploy directive." },
  { id: "DJL-MIS-005", re: /(?:\bsyscall\b|\bkernel\s+call\b|\/dev\/(?:mem|kmem|sda|raw\d*)|\bioctl\b|\bmmap\s*\([^)]*PROT_EXEC)/i, category: "tool_misuse", severity: 9, description: "Direct kernel / raw-device access attempt." },
  { id: "DJL-MIS-006", re: /\b(?:sudo|su\s+(?:-\s+)?root|setuid|chmod\s+(?:[+u]?s|4[0-7]{3})|setcap)\b/, category: "tool_misuse", severity: 8, description: "Privilege-escalation primitive (sudo, setuid, chmod +s)." },
  { id: "DJL-MIS-007", re: /:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:[^}]*\}\s*;\s*:/, category: "tool_misuse", severity: 10, description: "Bash fork-bomb pattern :(){ :|:& };:" },
  { id: "DJL-MIS-008", re: /\b(?:bash\s+-i\s+>&\s*\/dev\/tcp|nc\s+(?:-[a-z]+\s+)?-e\s+\/bin\/(?:bash|sh)|\/bin\/(?:bash|sh)\s+-i\b)/i, category: "tool_misuse", severity: 10, description: "Reverse-shell invocation pattern." },
  { id: "DJL-MIS-009", re: /\b(?:disable|turn\s+off|stop|kill|uninstall)\s+(?:the\s+)?(?:firewall|antivirus|edr|siem|monitoring|logging|audit)\b/i, category: "tool_misuse", severity: 9, description: "Disable defensive-tool directive." },
  { id: "DJL-MIS-010", re: /\b(?:eval|exec|system|popen|subprocess\.(?:call|Popen|run))\s*\([^)]*(?:user|input|prompt|request|param)/i, category: "tool_misuse", severity: 9, description: "Code-injection sink fed with untrusted input." },
];

// ---------------------------------------------------------------------------
// POL — Sector Policy Violations (5 rules)
// ---------------------------------------------------------------------------
const _RULES_POLICY = [
  { id: "DJL-POL-001", re: /\b(?:initiate|process|approve)\s+(?:wire\s+)?transfer\b[^\n]{0,80}(?:\$|€|£|¥|USD|EUR|GBP)\s*(?:\d{1,3}(?:[,.]?\d{3}){2,}|[1-9]\d{6,})/i, category: "policy", severity: 9, description: "Financial: transfer >= 1,000,000 (regulatory threshold)." },
  { id: "DJL-POL-002", re: /\b(?:export|disclose|share|forward|send)\b[^\n]{0,60}\b(?:phi|patient\s+(?:records?|data|chart|history)|medical\s+(?:records?|history)|diagnos[ie]s)\b/i, category: "policy", severity: 9, description: "Healthcare: PHI export request (HIPAA Privacy Rule)." },
  { id: "DJL-POL-003", re: /\b(?:TOP\s+SECRET|TS\/\/SCI|SECRET\/\/(?:NOFORN|REL)|CONFIDENTIAL\/\/(?:NOFORN|REL)|classified\s+(?:information|data|material))\b/, category: "policy", severity: 10, description: "Government: classified-marking handling." },
  { id: "DJL-POL-004", re: /\b(?:store|save|persist|log|cache)\b[^\n]{0,40}\b(?:cvv|cvc|cv2|cid|track[\s\-]?(?:1|2|data)|magnetic\s+stripe|pan(?:\s+data)?)\b/i, category: "policy", severity: 10, description: "Retail: storing cardholder authentication data (PCI-DSS 3.2 violation)." },
  { id: "DJL-POL-005", re: /\b(?:open|close|trip|disable|bypass)\s+(?:the\s+)?(?:breaker|relay|valve|safety[\s\-]?interlock|scada|plc|hmi|rtuP?)\b/i, category: "policy", severity: 10, description: "Energy / Manufacturing: OT control directive (NERC CIP / IEC 62443)." },
];

// ---------------------------------------------------------------------------
// HARM — Harmful Content bilingual EN+ES (16 rules)
// Cubre EU AI Act Annex III prohibited content + OWASP LLM 2026 LLM06 adjacent.
// ---------------------------------------------------------------------------
const _RULES_HARM = [
  { id: "DJL-HARM-001", re: /\b(?:how\s+to\s+(?:make|synth(?:esi[sz]e)?|cook|manufacture|produce)|step[s]?\s+to\s+(?:make|synth)|recipe\s+for)\s+(?:meth(?:amphetamine)?|cocaine|crack|heroin|fentanyl|lsd|mdma|ecstasy|crystal|amphetamine|opioid|opium)\b/i, category: "harm", severity: 10, description: "Drug synthesis instructions (EN). EU AI Act Annex III prohibited content." },
  { id: "DJL-HARM-002", re: /\b(?:c[oó]mo\s+(?:hacer|fabricar|sintetizar|cocinar|preparar|elaborar|producir)|pasos?\s+para\s+(?:hacer|fabricar)|receta\s+(?:de|para))\s+(?:coca[ií]na|crack|hero[ií]na|metanfetamina|fentanilo|[eé]xtasis|cristal|anfetamina|opi[oó]?ide|droga[s]?)\b/i, category: "harm", severity: 10, description: "Drug synthesis instructions (ES). EU AI Act Annex III prohibited content." },
  { id: "DJL-HARM-003", re: /\b(?:how\s+to\s+(?:make|build|assemble|construct)|step[s]?\s+to\s+(?:make|build|assemble)|recipe\s+for|instructions?\s+for)\s+(?:a\s+|an\s+)?(?:bomb|explosive|ied|pipe[\s\-]?bomb|nail[\s\-]?bomb|nerve\s+agent|chemical\s+weapon|biological\s+weapon|firearm|untraceable\s+(?:gun|weapon)|ghost\s+gun|silencer|suppressor)(?![\w\-])/i, category: "harm", severity: 10, description: "Weapons / explosives assembly instructions (EN)." },
  { id: "DJL-HARM-004", re: /\b(?:c[oó]mo\s+(?:hacer|fabricar|construir|armar|ensamblar)|pasos?\s+para\s+(?:hacer|fabricar|construir)|receta\s+(?:de|para))\s+(?:una\s+|un\s+)?(?:bomba|explosivo|artefacto|arma\s+(?:qu[ií]mica|biol[oó]gica|de\s+fuego|sin\s+licencia)|silenciador|munici[oó]n\s+casera)\b/i, category: "harm", severity: 10, description: "Weapons / explosives assembly instructions (ES)." },
  { id: "DJL-HARM-005", re: /\b(?:how\s+to\s+(?:kill|murder|assassinate|harm|hurt|stab|poison|strangle|torture)|plan\s+(?:to|for)\s+(?:kill|murder|assassinate|attack)|ways?\s+to\s+(?:kill|murder|hurt|harm))\s+(?:(?:a|an|the|my)\s+)?(?:someone|people|person|child|kid|wife|husband|spouse|coworker|neighbor|family|partner|friend|colleague|stranger|victim)\b/i, category: "harm", severity: 10, description: "Direct violence solicitation against a person (EN)." },
  { id: "DJL-HARM-006", re: /\b(?:c[oó]mo\s+(?:matar|asesinar|herir|da[nñ]ar|envenenar|estrangular|torturar)|plan\s+para\s+(?:matar|asesinar|atacar|herir)|formas?\s+de\s+(?:matar|asesinar|herir))\s+(?:a\s+)?(?:alguien|una?\s+persona|gente|ni[nñ]o|esposa?|c[oó]nyuge|compa[nñ]ero|vecino)\b/i, category: "harm", severity: 10, description: "Direct violence solicitation against a person (ES)." },
  { id: "DJL-HARM-007", re: /\b(?:how\s+to\s+(?:hack|crack|brute[\s\-]?force|exploit|bypass\s+the\s+login|breach|infiltrate|sql[\s\-]?inject)\s+(?:into\s+|a\s+|an\s+|the\s+|someone(?:'s)?\s+|my\s+ex(?:'s)?\s+|a\s+stranger(?:'s)?\s+)?(?:account|password|credential|database|server|gmail|outlook|facebook|instagram|whatsapp|tiktok|router|wifi|network|system|website|webapp|wallet|2fa|mfa)|(?:crack|steal|brute[\s\-]?force)\s+(?:the\s+)?(?:passwords?|credentials?|2fa|mfa|otp|sessions?)|gain\s+unauthorized\s+access\s+to)\b/i, category: "harm", severity: 9, description: "Illegal hacking / unauthorized credential access (EN)." },
  { id: "DJL-HARM-008", re: /\b(?:c[oó]mo\s+(?:hackear|crackear|romper|vulnerar|infiltrar|penetrar|saltarse|saltar\s+el\s+login)|(?:hackear|crackear|robar|romper)\s+(?:una?\s+)?(?:cuenta|contrase[nñ]a|credencial|2fa|mfa|sesi[oó]n|sistema)|acceso\s+(?:no\s+autorizado|ilegal)\s+a)\b/i, category: "harm", severity: 9, description: "Illegal hacking / unauthorized credential access (ES)." },
  { id: "DJL-HARM-009", re: /\b(?:steal|exfiltrate|siphon|harvest|scrape\s+(?:without\s+permission|illegally))\s+(?:user\s+)?(?:data|information|records|database|personal\s+info|customer\s+data|emails?|contacts?)\b|\bwrite\s+(?:a\s+)?(?:program|script|tool|code)\s+(?:to|that)\s+(?:steal|exfiltrate|siphon|harvest)\b/i, category: "harm", severity: 9, description: "Generic data theft / unauthorized exfiltration (EN)." },
  { id: "DJL-HARM-010", re: /\b(?:robar|extraer|exfiltrar|recopilar\s+sin\s+permiso|recolectar\s+ilegalmente)\s+(?:los\s+|las\s+)?(?:datos|informaci[oó]n|registros?|base\s+de\s+datos|datos?\s+(?:personales?|de\s+usuarios?|de\s+clientes?)|correos?|contactos?)\b|\b(?:crea[rs]?|escrib[ie]r?|hac[ae]r?)\s+(?:un\s+)?(?:programa|script|herramienta|c[oó]digo|app)\s+para\s+(?:robar|extraer|exfiltrar)\b/i, category: "harm", severity: 9, description: "Generic data theft / unauthorized exfiltration (ES)." },
  { id: "DJL-HARM-011", re: /\b(?:how\s+to\s+(?:kill\s+myself|commit\s+suicide|end\s+my\s+life|self[\s\-]?harm)|c[oó]mo\s+(?:suicidarme|matarme|terminar\s+con\s+mi\s+vida|hacerme\s+da[nñ]o)|m[eé]todo\s+para\s+suicid)/i, category: "harm", severity: 10, description: "Self-harm / suicide instructions (EN+ES). Requires safety-resource response, not method information." },
  { id: "DJL-HARM-012", re: /\b(?:sexual|erotic|nude|naked|undress)\s+(?:content|imagery|images?|story|stories|description|fantasy)\s+(?:of|with|featuring|involving)\s+(?:a\s+|the\s+)?(?:child|children|minor[s]?|kid[s]?|underage|teen(?:ager)?|infant)\b|\b(?:csam|child\s+(?:porn|sexual))\b/i, category: "harm", severity: 10, description: "Child sexual content (CSAM-adjacent). Mandatory report to NCMEC; non-negotiable BLOCK." },
  { id: "DJL-HARM-013", re: /\b(?:how\s+to\s+(?:join|recruit\s+for)|c[oó]mo\s+(?:unirme|reclutar)\s+a)\s+(?:isis|al[\s\-]?qaeda|hamas|hezbollah|boko\s+haram|talib[aá]n|estado\s+isl[aá]mico|a\s+terrorist\s+(?:cell|organization|group)|una?\s+(?:c[eé]lula|organizaci[oó]n)\s+terrorista)\b|\b(?:plan(?:ning)?|planeando)\s+(?:a\s+|an\s+|un\s+)?(?:terrorist\s+attack|atentado|ataque\s+terrorista)\b/i, category: "harm", severity: 10, description: "Terrorism recruitment / attack planning (EN+ES)." },
  { id: "DJL-HARM-014", re: /\b(?:write|create|generate|draft|escrib[ie]r?|crea[rs]?|genera[rs]?)\s+(?:a\s+|an\s+|un\s+|una\s+)?(?:hateful|racist|antisemitic|xenophobic|islamophobic|homophobic|transphobic|misogynist(?:ic)?|racista|antisemita|xen[oó]fobo|hom[oó]fobo|tr[aá]nsfobo|mis[oó]gino)\s+(?:rant|manifesto|post|message|content|discurso|manifiesto|publicaci[oó]n|mensaje|contenido)\b/i, category: "harm", severity: 9, description: "Hate-speech generation against protected class (EN+ES). EU AI Act Article 5 + DSA Article 34." },
  { id: "DJL-HARM-015", re: /\b(?:make|build|create|develop|write|code|design|generate)\s+(?:a|an|the|some)?\s*(?:program|app(?:lication)?|script|tool|software|utility|malware|virus|trojan|backdoor|keylogger|spyware|stealer|grabber|extension|bot|exploit|payload)s?\s+(?:to|that|which|for|capable\s+of)\s+(?:steal|steel|grab|harvest|extract|exfiltrate|siphon|capture|sniff|intercept|crack|brute[\s\-]?force|phish|skim|dump)s?\s+(?:[\w\-]+\s+){0,4}?(?:passwords?|credentials?|tokens?|api[\s\-]?keys?|accounts?|sessions?|cookies?|cards?|wallets?|seed[\s\-]?phrases?|private[\s\-]?keys?|2fa|mfa|otps?|personal\s+(?:data|info(?:rmation)?)|user\s+(?:data|info(?:rmation)?)|customer\s+(?:data|info(?:rmation)?)|emails?|contacts?|database)\b/i, category: "harm", severity: 10, description: "Malware app/script/tool synthesis request targeting credentials/data (EN)." },
  { id: "DJL-HARM-016", re: /\b(?:hac[ae]r?|crea[rs]?|construi[rs]?|desarrolla[rs]?|escrib[ie]r?|programa[rs]?|disen[aã]r?|dise[nñ]a[rs]?)\s+(?:un|una|el|la|alg[uú]n|alguna)?\s*(?:programa|app|aplicaci[oó]n|script|herramienta|software|utilidad|malware|virus|troyano|backdoor|keylogger|spyware|extensi[oó]n|bot|exploit)s?\s+(?:para|que|capaz\s+de)\s+(?:roba[rs]?|extrae[rs]?|exfiltra[rs]?|captura[rs]?|interceptar?|crackear?|hackear?|sniffea[rs]?|sustrae[rs]?)\s+(?:[\w\-]+\s+){0,4}?(?:contrase[nñ]as?|credenciales?|tokens?|claves?\s+api|cuentas?|sesion(?:es)?|cookies?|tarjetas?|wallets?|frases?\s+semilla|claves?\s+privadas?|2fa|mfa|datos?\s+(?:personales?|de\s+usuarios?|de\s+clientes?)|correos?|contactos?|bases?\s+de\s+datos)\b/i, category: "harm", severity: 10, description: "Malware app/script/tool synthesis request targeting credentials/data (ES)." },
];

// ---------------------------------------------------------------------------
// Materialised global list — orden de inserción preservado, congelado al import.
// ---------------------------------------------------------------------------
export const RULES = Object.freeze([
  ..._RULES_PI,
  ..._RULES_SQLI,
  ..._RULES_XSS,
  ..._RULES_PII,
  ..._RULES_EXFIL,
  ..._RULES_MISUSE,
  ..._RULES_POLICY,
  ..._RULES_HARM,
].map((r) => Object.freeze(r)));

// ---------------------------------------------------------------------------
// POLICY_BUNDLE_VERSION — sha256 truncado del corpus canónico.
// Formato: `djl-v<major>-<sha256-12>`. Bump del `vN` solo si: cambia el contrato
// de severity, se elimina una rule_id, o se rompe retro-compat del shape del verdict.
// El hash captura el resto automáticamente (cambios en regex, descripciones, etc.).
// ---------------------------------------------------------------------------
const _canonicalCorpus = JSON.stringify(
  RULES
    .map((r) => [r.id, r.re.source, r.severity, r.category])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)),
);
const _corpusSha = createHash("sha256").update(_canonicalCorpus).digest("hex").slice(0, 12);
export const POLICY_BUNDLE_VERSION = `djl-v1-${_corpusSha}`;

// ---------------------------------------------------------------------------
// evaluate(text) — corre las 78 reglas y devuelve verdict.
// Contrato del verdict:
//   { decision: "BLOCK"|"REVIEW"|"ALLOW", matched_rules: string[], latency_ms: number, layer: "djl" }
//
// Contractos extra (T1 AC#N1, AC#8, AC#9):
//   - No muta el input (string es inmutable en JS, pero documentado por contrato).
//   - matched_rules contiene SOLO rule_ids (strings), nunca substrings ni objetos.
// ---------------------------------------------------------------------------
export function evaluate(text /*, context */) {
  const s = String(text ?? "");
  const t0 = performance.now();
  const matched = [];
  let maxSev = 0;
  for (const rule of RULES) {
    if (rule.re.test(s)) {
      matched.push(rule.id);
      if (rule.severity > maxSev) maxSev = rule.severity;
    }
  }
  const decision = maxSev >= 8 ? "BLOCK" : maxSev >= 5 ? "REVIEW" : "ALLOW";
  const latency_ms = +(performance.now() - t0).toFixed(4);
  return { decision, matched_rules: matched, latency_ms, layer: "djl" };
}
