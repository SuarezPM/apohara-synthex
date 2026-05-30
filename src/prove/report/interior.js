// PROVE/report/interior — shared interior-page scaffolding (light paper). The Phase-1 page
// bodies are MOVED here intact and now consume theme.PAPER + components instead of the old
// inline COLORS/pageHeader. Phase 2b redesigns each interior page; for now they just render
// light and printable on the new design system. pageOpen() draws the persona tag + H1 and
// registers the footer; the helpers (kv, owasp, severity) preserve the Phase-1 logic exactly.
import { PAPER, FONTS, TYPE, PAGE } from "./theme.js";
import { pageFrame, sectionTitle as cSectionTitle } from "./components.js";

// Open an interior page: light persona tag + H1 + footer registration. Leaves the cursor under
// the H1 at the left margin.
export function pageOpen(doc, { persona, title, reportId, registry }) {
  pageFrame(doc, { theme: PAPER, persona, title, reportId, dark: false, registry });
}

// Interior section title (delegates to the component, bound to the PAPER palette).
export function sectionTitle(doc, text) {
  cSectionTitle(doc, { theme: PAPER, text });
}

// Key/value line (Phase-1 kv, re-themed to PAPER + Inter).
export function kv(doc, label, value, valueColor) {
  const x = doc.page.margins.left;
  doc.font(FONTS.semibold).fontSize(9.5).fillColor(PAPER.muted)
    .text(label, x, doc.y, { continued: true, width: 170 });
  doc.font(FONTS.body).fillColor(valueColor ?? PAPER.ink).text(`  ${value}`);
  doc.x = x;
}

// Interior body paragraph at the standard body type.
export function body(doc, text, color) {
  doc.x = doc.page.margins.left;
  doc.font(FONTS.body).fontSize(TYPE.body.size).fillColor(color ?? PAPER.ink)
    .text(text, doc.page.margins.left, doc.y, { width: PAGE.textWidth });
  doc.x = doc.page.margins.left;
}

// Severity → interior RAG color (Phase-1 sevColor, re-themed). >=8 red, >=5 amber, else green.
export const sevColor = (s) => (s >= 8 ? PAPER.red : s >= 5 ? PAPER.amber : PAPER.green);

// Mapa categoría del pre-filtro FORGE → OWASP (Phase-1 OWASP, unchanged).
const OWASP = {
  "prompt-injection": { code: "LLM01:2025", name: "Prompt Injection", sev: 9 },
  "secret-exfil": { code: "LLM02:2025", name: "Sensitive Information Disclosure", sev: 9 },
  "sqli": { code: "A03:2021", name: "Injection (SQLi)", sev: 8 },
  "xss": { code: "A03:2021", name: "Injection (XSS)", sev: 7 },
};
export const owaspOf = (cat) => OWASP[cat] ?? { code: "—", name: cat ?? "uncategorized", sev: 8 };

// Normaliza un finding (plano o tri-lens) a filas (Phase-1 rowsOf/allRows, unchanged).
function rowsOf(finding) {
  if (finding.trilens) {
    return Object.entries(finding.trilens).map(([lens, c]) => ({ url: finding.url, lens, ...c }));
  }
  return [{ url: finding.url, lens: finding.lens, severity: finding.severity, summary: finding.summary, signals: finding.signals }];
}
export function allRows(findings) {
  return findings.flatMap(rowsOf);
}
