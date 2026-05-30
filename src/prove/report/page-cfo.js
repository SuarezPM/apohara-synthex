// PROVE/report/page-cfo — CFO Cost & Efficiency (interior, light). Two halves: the operational
// efficiency the screening already bought (exact dedup + per-stage wall-clock latency, from the
// evidence object) and the DECISION it frames — Synthex's marginal cost of a signed evidence vs
// the cost of an AI-data incident (IBM Cost of a Data Breach 2025). The incident figure is a
// MAPPING, not an insurance figure: no body priced this, and Synthex does not transfer risk.
import { PAPER, FONTS, PAGE } from "./theme.js";
import { pageOpen, sectionTitle, body, kv } from "./interior.js";

// Marginal cost of one signed evidence record — published list price, not an internal estimate.
// $0.75 per 500 signed URLs => $0.0015 per record. Kept as a constant so the two cells agree.
const COST_PER_RECORD = "$0.0015";
const COST_PER_BATCH = "$0.75 / 500 URLs";

// IBM Cost of a Data Breach Report 2025 (Ponemon · ibm.com/reports/data-breach). Verbatim figures;
// NEVER an invented number. Framed as a mapping aid, explicitly NOT an insurance price.
const IBM_AI_BREACH = "USD 4.46M";   // AI-targeted breach (org's AI involved), global average
const IBM_SHADOW_AI = "+USD 670K";   // shadow-AI premium (high 4.74M vs low 4.07M)

export function pageCFO(doc, ev, ctx = {}) {
  const { payload = {} } = ev;
  const dedup = payload.dedup ?? null;
  const timings = ev.timings ?? null;
  const sources = (payload.sources ?? []).length;
  const x = doc.page.margins.left;

  pageOpen(doc, {
    persona: "● Cost & Efficiency · for CFO",
    title: "The screening already paid for itself",
    reportId: ctx.reportId,
    registry: ctx.registry,
  });

  // ── 1 · Token cost saved (exact dedup) ──────────────────────────────────────
  sectionTitle(doc, "Token cost saved (deduplication)");
  body(doc,
    "FORGE deduplicates fetched documents by full SHA-256 before classification: every duplicate " +
    "block removed is one fewer LLM call paid for. The ratio below is exact, not estimated.");
  doc.moveDown(0.5);

  if (dedup) {
    const pct = (Number(dedup.dedupRatio ?? 0) * 100).toFixed(1);
    const dup = Number(dedup.duplicateBlocks ?? 0);
    const savedColor = dup ? PAPER.green : PAPER.muted;
    kv(doc, "Unique blocks classified", String(dedup.uniqueBlocks ?? "—"));
    kv(doc, "Duplicate blocks skipped", String(dup), savedColor);
    kv(doc, "Input tokens saved", `~${pct}% (not paid to the model)`, savedColor);
    if (dedup.bytesSaved != null) {
      kv(doc, "Bytes not re-processed", `${dedup.bytesSaved} B`, savedColor);
    }
  } else {
    body(doc, "Dedup stats not present in this evidence object (no FORGE pass recorded).", PAPER.muted);
  }
  doc.moveDown(0.7);

  // ── 2 · Latency per stage (wall-clock, non-sealed) ──────────────────────────
  sectionTitle(doc, "Latency per stage (wall-clock)");
  body(doc,
    "Measured by the pipeline (evidence.timings), outside the sealed payload so it never affects " +
    "verification.", PAPER.muted);
  doc.moveDown(0.5);

  if (timings && Object.keys(timings).length) {
    const entries = Object.entries(timings);
    const maxMs = Math.max(...entries.map(([, v]) => Number(v) || 0), 1);
    const labelW = 96;
    const barW = 232;
    for (const [stage, ms] of entries) {
      const v = Number(ms) || 0;
      const rowY = doc.y;
      doc.font(FONTS.semibold).fontSize(8.5).fillColor(PAPER.ink)
        .text(stage, x, rowY + 1, { width: labelW, lineBreak: false });
      const w = Math.max(2, (v / maxMs) * barW);
      doc.rect(x + labelW, rowY, barW, 9).fill(PAPER.rule);
      doc.rect(x + labelW, rowY, w, 9).fill(PAPER.violet);
      doc.font(FONTS.mono).fontSize(8).fillColor(PAPER.ink)
        .text(`${v} ms`, x + labelW + barW + 8, rowY + 1, { width: 60, lineBreak: false });
      doc.x = x;
      doc.y = rowY + 14; // manual y-step: lineBreak:false rows do not advance doc.y
    }
    const total = entries.reduce((a, [, v]) => a + (Number(v) || 0), 0).toFixed(1);
    doc.moveDown(0.2);
    doc.font(FONTS.semibold).fontSize(8.5).fillColor(PAPER.ink)
      .text(`Total wall-clock: ${total} ms${sources ? ` across ${sources} source(s)` : ""}`, x, doc.y, { width: PAGE.textWidth });
    doc.x = x;
  } else {
    body(doc, "No per-stage timings present in this evidence object.", PAPER.muted);
  }
  doc.moveDown(0.8);

  // ── 3 · The decision — cost of evidence vs cost of an incident ──────────────
  sectionTitle(doc, "The decision — cost of evidence vs cost of an incident");

  // Two-column compare strip: what one signed record costs (left) vs the modelled downside the
  // sealed audit trail is meant to make defensible (right). Light tinted panel, hairline border.
  const panelY = doc.y;
  const panelH = 96;
  const colW = (PAGE.textWidth - 1) / 2;
  doc.rect(x, panelY, PAGE.textWidth, panelH).fill("#f1efe8");
  doc.rect(x, panelY, PAGE.textWidth, panelH).lineWidth(0.5).strokeColor(PAPER.rule).stroke();
  doc.moveTo(x + colW, panelY + 10).lineTo(x + colW, panelY + panelH - 10)
    .lineWidth(0.5).strokeColor(PAPER.rule).stroke();

  // Left column — Synthex marginal cost (the spend).
  const lx = x + 14;
  const lw = colW - 24;
  doc.font(FONTS.mono).fontSize(7.5).fillColor(PAPER.muted)
    .text("SYNTHEX · PER SIGNED EVIDENCE", lx, panelY + 12, { width: lw, characterSpacing: 0.8, lineBreak: false });
  doc.font(FONTS.bold).fontSize(26).fillColor(PAPER.green)
    .text(COST_PER_RECORD, lx, panelY + 28, { width: lw, lineBreak: false });
  doc.font(FONTS.body).fontSize(8).fillColor(PAPER.ink)
    .text(`list price · ${COST_PER_BATCH}`, lx, panelY + 60, { width: lw, lineBreak: false });
  doc.font(FONTS.body).fontSize(8).fillColor(PAPER.muted)
    .text("marginal cost to seal what an agent ingested", lx, panelY + 73, { width: lw });

  // Right column — modelled incident cost (the downside being mapped against).
  const rx = x + colW + 14;
  const rw = colW - 24;
  doc.font(FONTS.mono).fontSize(7.5).fillColor(PAPER.muted)
    .text("AI-DATA INCIDENT · IBM 2025", rx, panelY + 12, { width: rw, characterSpacing: 0.8, lineBreak: false });
  doc.font(FONTS.bold).fontSize(26).fillColor(PAPER.red)
    .text(IBM_AI_BREACH, rx, panelY + 28, { width: rw, lineBreak: false });
  doc.font(FONTS.body).fontSize(8).fillColor(PAPER.ink)
    .text(`avg AI-targeted breach · shadow-AI ${IBM_SHADOW_AI}`, rx, panelY + 60, { width: rw, lineBreak: false });
  doc.font(FONTS.body).fontSize(8).fillColor(PAPER.muted)
    .text("Cost of a Data Breach Report 2025 (Ponemon)", rx, panelY + 73, { width: rw });

  doc.x = x;
  doc.y = panelY + panelH + 8;

  // Honest framing — this is a mapping aid, NOT a priced insurance figure.
  doc.font(FONTS.body).fontSize(8).fillColor(PAPER.muted).text(
    "This is a mapping, not an insurance figure: the USD 4.46M is IBM's measured industry average " +
    "(ibm.com/reports/data-breach), not a price Synthex quotes or a loss it transfers. Synthex " +
    "produces the signed, timestamped evidence that makes an incident defensible — it does not " +
    "underwrite the risk. No third party reviewed this comparison.",
    x, doc.y, { width: PAGE.textWidth });
  doc.fillColor(PAPER.ink).x = x;
}
