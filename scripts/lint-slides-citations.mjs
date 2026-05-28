#!/usr/bin/env node
// T3.2 — lint para SLIDES.md: cada NÚMERO debe tener fuente citada.
//
// Reglas (conservadoras, no busca cazar falsos positivos):
//   1. Una línea con dígitos (excluyendo años, números de slide, citas de
//      arXiv id, CVE id, márgenes de tiempo "5s" sin contexto) debe contener
//      o bien una fuente entre [src: ...] o bien estar dentro de una sección
//      que ya cita arriba (heurística: src: en el mismo párrafo).
//   2. Líneas que enumeran reglas estilo "78 DJL", "28 web-injection",
//      "25 PII" DEBEN tener [src:] explícito si no está en la misma sección.
//
// Exit 0 si todo OK, exit 1 si encuentra claims sin fuente.

import { readFileSync } from "node:fs";

const SLIDES_PATH = "SLIDES.md";

// Patterns considerados "claim numérico" que requiere citación.
const NUMERIC_CLAIM = /\b\d{2,}\s*(tests?|pass|fail|skip|URLs?|reglas?|rules?|seconds?|ms|MB|GB|%|\$|requests?|fixtures?|days?)\b|p\d{2,3}\s+\d+\s*(ms|s)\b|\$\d/i;

// Líneas que NO se evalúan (header, código, comentarios markdown, blockquotes).
const SKIP_LINE = /^(#|>|\s*[`]|---)/;

// Patrones "fuente": [src: ...], "src:", URL al repo/archivo, "ver `path`".
const CITATION = /\[src:|src:|verify[a-z\s]+(in|at|see)\s+(?:`|\(|\[)/i;

const content = readFileSync(SLIDES_PATH, "utf8");
const lines = content.split("\n");

const issues = [];
let inFootnote = false;

for (let i = 0; i < lines.length; i++) {
  const ln = lines[i];
  if (SKIP_LINE.test(ln) || ln.trim() === "") continue;

  // Si la línea tiene un claim numérico, debe tener citation O bien la línea
  // anterior (continuación de párrafo) debe tener citation.
  if (NUMERIC_CLAIM.test(ln)) {
    const hasCitation = CITATION.test(ln);
    // Ventana adyacente: línea anterior + siguiente.
    const ctx = [lines[i - 1] ?? "", ln, lines[i + 1] ?? ""].join("\n");
    const ctxHasCitation = CITATION.test(ctx);
    if (!hasCitation && !ctxHasCitation) {
      issues.push({ line: i + 1, snippet: ln.slice(0, 120) });
    }
  }
}

if (issues.length === 0) {
  console.log(`[lint-slides] ✓ ${lines.length} lines scanned, 0 uncited numeric claims`);
  process.exit(0);
}

console.error(`[lint-slides] ✗ ${issues.length} uncited numeric claims:`);
for (const iss of issues) {
  console.error(`  SLIDES.md:${iss.line}: ${iss.snippet}`);
}
console.error("");
console.error("Fix: append [src: path/to/file.json] or merge the claim into a sentence that already cites a source.");
process.exit(1);
