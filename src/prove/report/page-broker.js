// PROVE/report/page-broker — Underwriter Risk Snapshot (interior, light). Phase-1 body MOVED
// here, re-themed to PAPER. Logic unchanged, INCLUDING the distinct-axis labeling that keeps the
// composite gauge (0–100) and the lead-finding CVSS verdict from ever reading as a contradiction.
// NO premium quote (non-negotiable #6 — risk EVIDENCE only).
import { PAPER, FONTS, PAGE } from "./theme.js";
import { pageOpen, sectionTitle, body } from "./interior.js";
import { riskScore, riskScoreWeighted } from "./risk-score.js";
import { synthesizeOutput } from "../output.js";

export function pageBroker(doc, ev, ctx = {}) {
  const epssMap = ctx.epssMap ?? null;
  const { payload = {} } = ev;
  const r = riskScore(ev);
  pageOpen(doc, { persona: "● Risk Snapshot · for Underwriter", title: "Risk evidence, mapped not endorsed", reportId: ctx.reportId, registry: ctx.registry });
  sectionTitle(doc, "Synthex Risk Score (CVSS 0–10 severity · NIST AI RMF / EU AI Act framing · mapping, not endorsement)");

  // Composite gauge (0–100 blend of severity + block-volume). DIFFERENT axis from the verdict's
  // lead-finding CVSS band below — labeled distinctly so a low composite + a medium lead finding
  // never read as a contradiction.
  const x = doc.page.margins.left;
  const bandColor = r.band === "HIGH" ? PAPER.red : r.band === "MEDIUM" ? PAPER.amber : PAPER.green;
  doc.font(FONTS.bold).fontSize(56).fillColor(bandColor).text(String(r.score), x, doc.y);
  const numBottom = doc.y;
  doc.font(FONTS.body).fontSize(12).fillColor(PAPER.muted).text("/ 100", x + 92, numBottom - 28);
  doc.font(FONTS.bold).fontSize(15).fillColor(bandColor).text(`Composite · ${r.band}`, x + 92, numBottom - 12);
  doc.fillColor(PAPER.ink).x = x;
  doc.moveDown(0.6);

  const barY = doc.y;
  const barW = PAGE.textWidth;
  doc.rect(x, barY, barW, 10).fill(PAPER.rule);
  doc.rect(x, barY, (r.score / 100) * barW, 10).fill(bandColor);
  doc.fillColor(PAPER.ink).y = barY + 22;
  doc.x = x;

  sectionTitle(doc, "How this number is computed (honest formula)");
  doc.font(FONTS.mono).fontSize(8.5).fillColor(PAPER.ink).text(
    "maxSev    = max severity across all findings .......... " + `${r.maxSev}/10\n` +
    "blockTerm = min(blockedCount, 5) / 5 * 10 ............. " + `${((Math.min(r.blocked, 5) / 5) * 10).toFixed(1)}/10  (blocked=${r.blocked})\n` +
    "score     = round( (maxSev*0.70 + blockTerm*0.30) * 10 ) = " + `${r.score}`,
    x, doc.y, { width: PAGE.textWidth });
  doc.x = x;
  doc.moveDown(0.8);

  // EPSS enrichment (R1) — OPT-IN, NON-SEALED, render-time only.
  const w = epssMap ? riskScoreWeighted(ev, epssMap) : null;
  if (w && w.weighted) {
    doc.font(FONTS.mono).fontSize(8.5).fillColor(PAPER.muted).text(
      `EPSS enrichment (FIRST.org · non-sealed · mapping, not endorsement):\n` +
      `  ${w.cve}  epss=${w.epss.toFixed(3)}  ->  severity term x${(1 + 0.3 * w.epss).toFixed(3)}  ->  weighted score ${w.weightedScore}/100 (${w.weightedBand})`,
      x, doc.y, { width: PAGE.textWidth }).fillColor(PAPER.ink);
    doc.x = x;
    doc.moveDown(0.6);
  }

  // Disclaimer EXPLÍCITO (honestidad) — light amber-tinted box, hairline.
  const discY = doc.y;
  const discH = 70;
  doc.rect(x, discY, PAGE.textWidth, discH).fill("#fdf6e3");
  doc.rect(x, discY, PAGE.textWidth, discH).lineWidth(0.5).strokeColor(PAPER.rule).stroke();
  doc.fillColor(PAPER.amber).font(FONTS.semibold).fontSize(9).text("DISCLAIMER", x + 10, discY + 8, { width: PAGE.textWidth - 20 });
  doc.font(FONTS.body).fontSize(8).fillColor(PAPER.ink).text(
    "This Risk Score is computed by Synthex from the data in this report using the deterministic " +
    "formula shown above. Its severity axis is the CVSS 0–10 base-score scale and its bands align " +
    "to CVSS severity ratings; the compliance framing maps to NIST AI RMF and EU AI Act risk " +
    "categories. This is a MAPPING, NOT an ENDORSEMENT: it is NOT a Munich Re assessment, NOT an " +
    "insurance rating, and NOT underwriting advice. No third party or framework body has reviewed " +
    "or endorsed this number. See docs/compliance-mapping.md.",
    x + 10, discY + 22, { width: PAGE.textWidth - 20 });
  doc.fillColor(PAPER.ink).y = discY + discH + 6;
  doc.x = x;

  // Closing synthesis: one-line verdict (sealed bytes rendered verbatim) + 3 questions.
  const out = (payload.verdict && Array.isArray(payload.questions))
    ? { verdict: payload.verdict, questions: payload.questions }
    : synthesizeOutput(payload ?? {});
  const leadBand = r.maxSev >= 7 ? "HIGH" : r.maxSev >= 4 ? "MEDIUM" : "LOW";
  const leadColor = r.maxSev >= 8 ? PAPER.red : r.maxSev >= 5 ? PAPER.amber : PAPER.green;
  doc.moveDown(0.6);
  sectionTitle(doc, "Verdict — lead finding (CVSS severity)");
  doc.font(FONTS.semibold).fontSize(10).fillColor(leadColor)
    .text(`Lead finding: ${leadBand} · CVSS ${Number(r.maxSev).toFixed(1)}  (composite gauge above is a separate 0–100 blend)`,
      x, doc.y, { width: PAGE.textWidth });
  doc.font(FONTS.semibold).fontSize(11).fillColor(leadColor).text(out.verdict, x, doc.y, { width: PAGE.textWidth });
  doc.fillColor(PAPER.ink).x = x;
  doc.moveDown(0.6);
  sectionTitle(doc, "3 questions this evidence raises");
  doc.font(FONTS.body).fontSize(10).fillColor(PAPER.ink);
  out.questions.slice(0, 3).forEach((q, i) => {
    doc.x = x;
    doc.text(`${i + 1}.  ${q}`, x, doc.y, { width: PAGE.textWidth }).moveDown(0.25);
  });
  doc.x = x;
}
