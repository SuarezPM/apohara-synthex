// PROVE/report/page-ciso — CISO Security Briefing (interior, light). Phase-1 body MOVED here,
// re-themed to PAPER + components. Logic unchanged: FORGE pre-LLM blocks (OWASP-mapped) + the
// 3-tier injection-defense ledger from sealed decisions[] + per-lens classification severity.
// Phase 2b splits this into Data-BOM + Security Briefing; for now it renders light + printable.
import { PAPER, FONTS, PAGE } from "./theme.js";
import { pageOpen, sectionTitle, body, sevColor, owaspOf, allRows } from "./interior.js";
import { guardLedger } from "./guard-ledger.js";

export function pageCISO(doc, ev, ctx = {}) {
  const { payload = {} } = ev;
  const blocked = payload.blocked ?? [];
  pageOpen(doc, { persona: "● Security Briefing · for CISO", title: "Threats screened before the model", reportId: ctx.reportId, registry: ctx.registry });
  sectionTitle(doc, "Threats blocked by FORGE (pre-LLM)");

  body(doc,
    "FORGE flags injection and exfiltration vectors before the LLM; high-confidence hits are BLOCKED, " +
    "the rest are REVIEW-flagged (fail-safe: scraped docs are not silently dropped). It is a " +
    "deterministic regex pre-filter that runs BEFORE any LLM call; categories are mapped to their " +
    "OWASP reference class. The pre-filter is heuristic, not formally verified.");
  doc.moveDown(0.7);

  if (!blocked.length) {
    doc.font(FONTS.semibold).fontSize(11).fillColor(PAPER.green).text("No malicious content detected in this batch.");
    doc.font(FONTS.body).fontSize(9).fillColor(PAPER.muted).moveDown(0.3)
      .text("All fetched sources passed the FORGE pre-filter and were forwarded to classification.");
    doc.fillColor(PAPER.ink);
  } else {
    const x = doc.page.margins.left;
    doc.font(FONTS.mono).fontSize(8).fillColor(PAPER.muted);
    doc.text("OWASP", x, doc.y, { continued: true, width: 90 });
    doc.text("CATEGORY", { continued: true, width: 230 });
    doc.text("SEVERITY", { continued: false });
    doc.moveTo(x, doc.y + 1).lineTo(doc.page.width - doc.page.margins.right, doc.y + 1).strokeColor(PAPER.rule).lineWidth(0.5).stroke();
    doc.moveDown(0.4);
    for (const b of blocked) {
      const o = owaspOf(b.reason);
      doc.font(FONTS.semibold).fontSize(9).fillColor(PAPER.ink).text(o.code, x, doc.y, { continued: true, width: 90 });
      doc.font(FONTS.body).text(o.name, { continued: true, width: 230 });
      doc.font(FONTS.semibold).fillColor(sevColor(o.sev)).text(`${o.sev}/10  BLOCKED`, { continued: false });
      doc.fillColor(PAPER.muted).font(FONTS.body).fontSize(7.5).text(b.url ?? "—").fillColor(PAPER.ink).moveDown(0.4);
    }
  }

  // 3-tier defense ledger — honestly labeled per row from the SEALED payload.decisions[].
  doc.moveDown(0.5);
  sectionTitle(doc, "3-tier injection defense (from sealed decisions)");
  const modeColor = (m) => m === "LIVE" ? PAPER.green : m.startsWith("DEGRADED") ? PAPER.amber : m.startsWith("DEMO") ? PAPER.violet : PAPER.muted;
  const lx = doc.page.margins.left;
  for (const led of guardLedger(payload.decisions)) {
    const rowY = doc.y;
    doc.font(FONTS.semibold).fontSize(9).fillColor(modeColor(led.mode)).text(led.mode, lx, rowY, { width: 140, lineBreak: false });
    doc.fillColor(PAPER.ink).text(led.tier, lx + 150, rowY, { width: 150, lineBreak: false });
    doc.font(FONTS.body).fillColor(PAPER.muted).fontSize(8).text(led.detail, lx + 150, rowY + 11, { width: PAGE.textWidth - 150 });
    doc.fillColor(PAPER.ink).moveDown(0.5);
  }
  doc.x = lx;

  doc.moveDown(0.5);
  sectionTitle(doc, "Classification severity (per lens)");
  const rows = allRows(payload.findings ?? []);
  if (!rows.length) {
    doc.font(FONTS.body).fontSize(9).fillColor(PAPER.muted).text("No findings classified.").fillColor(PAPER.ink);
  }
  for (const r of rows) {
    doc.x = doc.page.margins.left;
    doc.font(FONTS.semibold).fontSize(9.5).fillColor(sevColor(r.severity ?? 0))
      .text(`[${String(r.lens ?? "").toUpperCase()}]  severity ${r.severity ?? 0}/10`);
    doc.font(FONTS.body).fontSize(9).fillColor(PAPER.ink).text(r.summary ?? "");
    if (r.signals?.length) doc.fontSize(7.5).fillColor(PAPER.muted).text(`signals: ${r.signals.join(" · ")}`).fillColor(PAPER.ink);
    doc.moveDown(0.4);
  }
  doc.x = doc.page.margins.left;
}
