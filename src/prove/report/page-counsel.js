// PROVE/report/page-counsel — General Counsel Compliance Trace (interior, light). Phase-1 body
// MOVED here, re-themed to PAPER. Logic unchanged: EU AI Act Art 12 record-keeping trace with
// the fixed-X column layout + the cursor-reset overflow fix (doc.x = left margin before the
// closing disclaimer — the Phase-1 fix preserved).
import { PAPER, FONTS, PAGE } from "./theme.js";
import { pageOpen, sectionTitle, body } from "./interior.js";

export function pageCounsel(doc, ev, ctx = {}) {
  const { payload = {}, contentHash, seal = {}, sealedAt } = ev;
  const tsa = seal.rfc3161Tsa;
  pageOpen(doc, { persona: "● Compliance Trace · for General Counsel", title: "An automatic, timestamped log", reportId: ctx.reportId, registry: ctx.registry });
  sectionTitle(doc, "EU AI Act — Article 12 (record-keeping / logging)");

  body(doc,
    "Article 12 requires high-risk AI systems to automatically record events ('logs') enabling " +
    "traceability. This report is itself such a record: an immutable, timestamped log of the data " +
    "lifecycle, sealed so any tampering is detectable.");
  doc.moveDown(0.5);

  const trace = [
    ["Traceability of inputs", `${(payload.sources ?? []).length} source URL(s) recorded`, true],
    ["Pre-processing log", `${(payload.blocked ?? []).length} block(s) by FORGE pre-filter, with category`, true],
    ["Classification output", `${(payload.findings ?? []).length} finding record(s) retained`, (payload.findings ?? []).length > 0],
    ["Integrity of records", `HMAC-SHA256 over canonical payload (${seal.hmacSha256 ? "present" : "absent"})`, !!seal.hmacSha256],
    ["Timekeeping (independent)", tsa ? `RFC 3161 TSA — ${tsa.authority ?? "DigiCert"}, ${tsa.genTime ?? "—"}` : "HMAC-only (no third-party time source)", !!tsa],
    ["Tamper-evidence", `SHA-256 content hash: ${(contentHash ?? "").slice(0, 24)}…`, !!contentHash],
    ["Record timestamp", sealedAt ?? "—", !!sealedAt],
  ];

  // Columnas en X fija (no continued+width estrecho, que dispara saltos de página espurios).
  const cx = doc.page.margins.left;
  for (const [req, detail, ok] of trace) {
    const rowY = doc.y;
    doc.font(FONTS.monoBold).fontSize(9).fillColor(ok ? PAPER.green : PAPER.amber)
      .text(ok ? "✓ OK" : "▲ !!", cx, rowY, { lineBreak: false, width: 36 });
    doc.font(FONTS.semibold).fontSize(9.5).fillColor(PAPER.ink).text(req, cx + 42, rowY, { width: 168, lineBreak: false });
    doc.font(FONTS.body).fillColor(PAPER.muted).fontSize(9)
      .text(detail, cx + 214, rowY, { width: PAGE.textWidth - 214 });
    doc.fillColor(PAPER.ink).moveDown(0.4);
  }

  // Reset doc.x to the left margin so the disclaimer renders at full text width (Phase-1 fix).
  doc.x = doc.page.margins.left;
  doc.moveDown(0.5);
  doc.font(FONTS.body).fontSize(8.5).fillColor(PAPER.muted).text(
    "This is an evidentiary record, not legal advice. Mapping to Article 12 is provided as a " +
    "good-faith aid; applicability depends on whether the deploying system is classified high-risk.",
    doc.page.margins.left, doc.y, { width: PAGE.textWidth, oblique: true }).fillColor(PAPER.ink);
  doc.x = doc.page.margins.left;
}
