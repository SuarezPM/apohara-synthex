// PROVE/report/page-cfo — CFO Cost & Efficiency (interior, light). Phase-1 body MOVED here,
// re-themed to PAPER. Logic unchanged: exact dedup savings + per-stage wall-clock latency bars.
import { PAPER, FONTS, PAGE } from "./theme.js";
import { pageOpen, sectionTitle, body, kv } from "./interior.js";

export function pageCFO(doc, ev, ctx = {}) {
  const { payload = {} } = ev;
  const dedup = payload.dedup ?? null;
  const timings = ev.timings ?? null;
  pageOpen(doc, { persona: "● Cost & Efficiency · for CFO", title: "What screening saved", reportId: ctx.reportId, registry: ctx.registry });
  sectionTitle(doc, "Token cost saved (deduplication)");

  body(doc,
    "FORGE deduplicates fetched documents by full SHA-256 before classification: every duplicate " +
    "block removed is one fewer LLM call paid for. The ratio below is exact (not estimated).");
  doc.moveDown(0.5);

  if (dedup) {
    const pct = (dedup.dedupRatio * 100).toFixed(1);
    kv(doc, "Unique blocks", String(dedup.uniqueBlocks ?? "—"));
    kv(doc, "Duplicate blocks", String(dedup.duplicateBlocks ?? 0), (dedup.duplicateBlocks ?? 0) ? PAPER.green : PAPER.muted);
    kv(doc, "Tokens saved", `~${pct}% of input tokens`, (dedup.duplicateBlocks ?? 0) ? PAPER.green : PAPER.muted);
  } else {
    doc.font(FONTS.body).fontSize(9).fillColor(PAPER.muted)
      .text("Dedup stats not present in this evidence object (no FORGE pass recorded).").fillColor(PAPER.ink);
  }

  doc.moveDown(0.6);
  sectionTitle(doc, "Latency per stage (wall-clock)");
  body(doc,
    "Measured by the pipeline (evidence.timings), outside the sealed payload so it never affects verification.",
    PAPER.muted);
  doc.moveDown(0.4);

  if (timings && Object.keys(timings).length) {
    const x = doc.page.margins.left;
    const entries = Object.entries(timings);
    const maxMs = Math.max(...entries.map(([, v]) => Number(v) || 0), 1);
    const barW = 240;
    for (const [stage, ms] of entries) {
      const v = Number(ms) || 0;
      doc.font(FONTS.semibold).fontSize(9).fillColor(PAPER.ink).text(stage, x, doc.y, { continued: false, width: 80 });
      const barY = doc.y - 11;
      const w = Math.max(2, (v / maxMs) * barW);
      doc.rect(x + 90, barY, barW, 9).fill(PAPER.rule);
      doc.rect(x + 90, barY, w, 9).fill(PAPER.violet);
      doc.fillColor(PAPER.ink).font(FONTS.mono).fontSize(8.5).text(`${v} ms`, x + 90 + barW + 8, barY);
      doc.moveDown(0.5);
    }
    const total = entries.reduce((a, [, v]) => a + (Number(v) || 0), 0).toFixed(1);
    doc.x = x;
    doc.moveDown(0.4).font(FONTS.semibold).fontSize(9).fillColor(PAPER.ink).text(`Total: ${total} ms`);
  } else {
    doc.font(FONTS.body).fontSize(9).fillColor(PAPER.muted)
      .text("No per-stage timings present in this evidence object.").fillColor(PAPER.ink);
  }
  doc.x = doc.page.margins.left;
}
