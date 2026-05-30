// PROVE/report/page-broker — Underwriter / Broker Risk Snapshot (interior, light paper).
// Phase-2b redesign on the new component system. RISK EVIDENCE ONLY — there is NO premium and NO
// dollar quote on this page (non-negotiable #6). It keeps the DISTINCT-AXIS labeling so the
// Composite gauge (0–100 blend of severity + block-volume) and the Lead-finding CVSS verdict can
// never read as a contradiction: they are named as different axes everywhere they appear.
//
// PDFKit pitfall guarded throughout: PDFKit does NOT advance doc.y after a lineBreak:false draw,
// so single-line draws step y by a fixed amount and only WRAPPING blocks read doc.y afterward.
import { PAPER, FONTS, TYPE, PAGE } from "./theme.js";
import { pageOpen, sectionTitle, body } from "./interior.js";
import { codeBox, frameworkMatrix, truncMid } from "./components.js";
import { riskScore, riskScoreWeighted } from "./risk-score.js";
import { synthesizeOutput } from "../output.js";

// VERBATIM disclaimer line required by the page spec — printed unchanged inside the amber box.
const VERBATIM = "mapping, NOT endorsement; not an insurance rating; no third party reviewed this number";

const bandColorOf = (band) => (band === "HIGH" ? PAPER.red : band === "MEDIUM" ? PAPER.amber : PAPER.green);

export function pageBroker(doc, ev, ctx = {}) {
  const { payload = {}, contentHash, seal = {} } = ev;
  const sig = seal.signature ?? null;
  const r = riskScore(ev);
  const left = doc.page.margins.left;

  pageOpen(doc, {
    persona: "● Risk Snapshot · for Underwriter / Broker",
    title: "Risk evidence, mapped not endorsed",
    reportId: ctx.reportId,
    registry: ctx.registry,
  });

  // ── Composite gauge — axis #1 (0–100 blend of severity + block-volume) ─────────
  sectionTitle(doc, "Synthex Risk Score — composite (0–100, severity + block-volume blend)");
  const gaugeColor = bandColorOf(r.band);
  const gaugeTop = doc.y;
  doc.font(FONTS.bold).fontSize(46).fillColor(gaugeColor).text(String(r.score), left, gaugeTop, { lineBreak: false });
  doc.font(FONTS.body).fontSize(12).fillColor(PAPER.muted).text("/ 100", left + 78, gaugeTop + 22, { lineBreak: false });
  doc.font(FONTS.semibold).fontSize(13).fillColor(gaugeColor)
    .text(`Composite band · ${r.band}`, left + 78, gaugeTop + 4, { lineBreak: false });
  // Step past the single-line gauge block manually (lineBreak:false leaves doc.y unmoved).
  const barY = gaugeTop + 56;
  const barW = PAGE.textWidth;
  doc.rect(left, barY, barW, 9).fill(PAPER.rule);
  doc.rect(left, barY, (Math.min(r.score, 100) / 100) * barW, 9).fill(gaugeColor);
  doc.x = left;
  doc.y = barY + 18;

  // ── Honest deterministic formula — light Mono codeBox (printable) ──────────────
  sectionTitle(doc, "How this number is computed (deterministic, reproducible)");
  const blockTerm = (Math.min(r.blocked, 5) / 5) * 10;
  codeBox(doc, {
    theme: PAPER,
    lines:
      `maxSev    = max severity across all findings ......... ${r.maxSev}/10 (CVSS base-score scale)\n` +
      `blockTerm = min(blocked, 5) / 5 * 10 ................. ${blockTerm.toFixed(1)}/10  (blocked = ${r.blocked})\n` +
      `score     = round( (maxSev*0.70 + blockTerm*0.30) * 10 ) = ${r.score} / 100  ->  ${r.band}`,
  });

  // EPSS enrichment (opt-in, non-sealed, render-time only) — present-gated.
  const w = ctx.epssMap ? riskScoreWeighted(ev, ctx.epssMap) : null;
  if (w && w.weighted) {
    doc.x = left;
    doc.font(FONTS.mono).fontSize(8).fillColor(PAPER.muted).text(
      `EPSS enrichment (FIRST.org · non-sealed · mapping, not endorsement): ${w.cve} ` +
      `epss=${w.epss.toFixed(3)} -> weighted ${w.weightedScore}/100 (${w.weightedBand})`,
      left, doc.y, { width: PAGE.textWidth });
    doc.x = left;
    doc.moveDown(0.4);
  }
  doc.moveDown(0.2);

  // ── Lead finding — axis #2 (CVSS severity of the single worst finding) ─────────
  // Distinct axis from the composite above, labeled so a low composite + a high lead never read
  // as a contradiction. The band here follows the CVSS severity ratings (High >= 7.0).
  sectionTitle(doc, "Lead finding — CVSS severity (separate axis from the composite above)");
  const leadBand = r.maxSev >= 7 ? "HIGH" : r.maxSev >= 4 ? "MEDIUM" : "LOW";
  const leadColor = r.maxSev >= 7 ? PAPER.red : r.maxSev >= 4 ? PAPER.amber : PAPER.green;
  const out = (payload.verdict && Array.isArray(payload.questions))
    ? { verdict: payload.verdict, questions: payload.questions }
    : synthesizeOutput(payload ?? {});
  const ly = doc.y;
  const leadGlyph = leadBand === "HIGH" ? "✗" : leadBand === "MEDIUM" ? "▲" : "✓";
  doc.font(FONTS.monoBold).fontSize(9.5).fillColor(leadColor)
    .text(`${leadGlyph} CVSS ${Number(r.maxSev).toFixed(1)} / 10 · ${leadBand}`, left, ly, { width: 180, lineBreak: false });
  doc.font(FONTS.body).fontSize(9).fillColor(PAPER.muted)
    .text("CVSS axis is the worst single finding; the 0–100 composite above is a separate blend.",
      left + 188, ly, { width: PAGE.textWidth - 188, lineGap: 2 });
  const capBottom = doc.y; // the caption wraps → advance past whichever is taller
  doc.x = left;
  doc.y = Math.max(ly + 20, capBottom) + 8;
  // Band-matched verdict, rendered verbatim from the SEALED payload (a verifier recomputes it).
  doc.font(FONTS.semibold).fontSize(10).fillColor(leadColor).text(out.verdict, left, doc.y, { width: PAGE.textWidth });
  doc.x = left;
  doc.moveDown(0.6);

  // ── Compliance framing — NIST AI RMF / EU AI Act (mapping, not endorsement) ────
  sectionTitle(doc, "Compliance framing — mapping aid (not endorsement)");
  frameworkMatrix(doc, {
    theme: PAPER,
    // frameworkMatrix → ragRow expects a RAG status token (green|amber|red), not a coverage word.
    // These are MAPPING AIDS (one signal), so amber = PARTIAL is the honest status.
    rows: [
      { control: "NIST AI RMF — MEASURE", status: "amber",
        citation: "MS-2.5 (validity/robustness); GOVERN/MAP/MEASURE/MANAGE framing" },
      { control: "EU AI Act 2024/1689", status: "amber",
        citation: "Art 15 robustness/cybersecurity · Art 9 risk management" },
    ],
  });
  doc.moveDown(0.2);

  // ── Verbatim honesty disclaimer — amber-tinted box, hairline (printable) ───────
  const dy = doc.y;
  const dH = 58;
  doc.rect(left, dy, PAGE.textWidth, dH).fill("#fdf6e3");
  doc.rect(left, dy, PAGE.textWidth, dH).lineWidth(0.5).strokeColor(PAPER.rule).stroke();
  doc.font(FONTS.semibold).fontSize(8.5).fillColor(PAPER.amber)
    .text("DISCLAIMER", left + 10, dy + 8, { width: PAGE.textWidth - 20, lineBreak: false });
  doc.font(FONTS.body).fontSize(8).fillColor(PAPER.ink).text(
    `This Risk Score is computed by Synthex from the data in this report using the formula above — ` +
    `${VERBATIM}. Severity follows the CVSS 0–10 scale; framing maps to NIST AI RMF and EU AI Act ` +
    `risk categories. See docs/compliance-mapping.md.`,
    left + 10, dy + 22, { width: PAGE.textWidth - 20 });
  doc.x = left;
  doc.y = dy + dH + 10;

  // ── Verifiable evidence to defend the highest-severity finding ─────────────────
  // Seal pointer (Ed25519-led) + the lead finding's own contentHash + the sidecar pointer. Long
  // values truncate head…tail; the FULL value lives in the sidecar evidence.json (design spec §4).
  sectionTitle(doc, "Verifiable evidence — to defend the highest-severity finding");
  const topFinding = topFindingOf(payload.findings, r.maxSev);
  const sidecar = `${ctx.reportId ?? "SYNTHEX-EVR-?"}.evidence.json`;
  evRow(doc, "Lead finding URL", topFinding?.url ?? "—", { trunc: false });
  evRow(doc, "Lead finding SHA-256", topFinding?.contentHash ?? contentHash, { trunc: [20, 14] });
  if (sig) {
    evRow(doc, "Ed25519 keyId", sig.keyId ?? "—", { trunc: [22, 10], accent: true });
    evRow(doc, "Ed25519 signature", sig.value, { trunc: [18, 12] });
  }
  evRow(doc, "RFC 3161 TSA", tsaLine(seal.rfc3161Tsa), { trunc: false });
  evRow(doc, "Report SHA-256", contentHash, { trunc: [20, 14] });
  evRow(doc, "Full values in", sidecar, { trunc: false, accent: true });
  doc.moveDown(0.5);

  // ── 3 questions this evidence raises (verbatim from sealed payload) ────────────
  sectionTitle(doc, "3 questions this evidence raises");
  doc.x = left;
  out.questions.slice(0, 3).forEach((q, i) => {
    doc.x = left;
    doc.font(FONTS.body).fontSize(9).fillColor(PAPER.ink)
      .text(`${i + 1}.  ${q}`, left, doc.y, { width: PAGE.textWidth });
    doc.moveDown(0.2);
  });
  doc.x = left;
}

// One label → mono-value evidence line. Single line, manual y-step (PDFKit does not advance doc.y
// after a lineBreak:false draw). Long values truncate head…tail; the full value lives in the sidecar.
function evRow(doc, label, value, { trunc = [22, 12], accent = false } = {}) {
  const left = doc.page.margins.left;
  const labelW = 150;
  const y = doc.y;
  doc.font(FONTS.body).fontSize(TYPE.tableCell.size).fillColor(PAPER.muted)
    .text(label, left, y, { width: labelW, lineBreak: false });
  const shown = trunc ? truncMid(value, trunc[0], trunc[1]) : String(value ?? "—");
  doc.font(FONTS.mono).fontSize(TYPE.tableCell.size).fillColor(accent ? PAPER.violet : PAPER.ink)
    .text(shown, left + labelW + 8, y, { width: PAGE.textWidth - labelW - 8, lineBreak: false });
  doc.x = left;
  doc.y = y + TYPE.tableCell.leading + 2;
}

// Pick the single worst finding (matching maxSev) so the evidence pointer defends the right row.
function topFindingOf(findings, maxSev) {
  const list = Array.isArray(findings) ? findings : [];
  const flat = list.flatMap((f) =>
    f?.trilens
      ? Object.values(f.trilens).map((c) => ({ url: f.url, contentHash: f.contentHash, severity: c.severity }))
      : [{ url: f?.url, contentHash: f?.contentHash, severity: f?.severity }]);
  return flat.find((x) => (Number(x.severity) || 0) === maxSev) ?? flat[0] ?? null;
}

// Compact RFC 3161 TSA descriptor (authority · genTime · serial), present-gated to a dash.
function tsaLine(tsa) {
  if (!tsa) return "absent (HMAC-only)";
  const serial = tsa.serial ? `serial ${truncMid(tsa.serial, 8, 6)}` : "";
  return `${tsa.authority ?? "DigiCert"} · ${tsa.genTime ?? "—"} · ${serial}`.trim();
}
