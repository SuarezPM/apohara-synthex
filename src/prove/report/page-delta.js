// PROVE/report/page-delta — Delta Evidence Chain (interior, light). Phase-1 body MOVED here,
// re-themed to PAPER. Inserted only when payload.delta_chain present. Logic unchanged, INCLUDING
// the cursor-reset overflow fix after the 3-cell diff table (doc.x = left margin).
import { PAPER, FONTS, PAGE } from "./theme.js";
import { pageOpen, sectionTitle, body } from "./interior.js";
import { rekorLogIndex } from "./components.js";

export function pageDelta(doc, ev, ctx = {}) {
  const { payload = {}, seal = {} } = ev;
  const dc = payload.delta_chain ?? {};
  pageOpen(doc, { persona: "● Delta Evidence Chain · Watch & Prove", title: "Two readings, two sealed times", reportId: ctx.reportId, registry: ctx.registry });

  sectionTitle(doc, "TSA chain (RFC 3161)");
  body(doc,
    "Each scrape of the same target is sealed with an independent DigiCert RFC 3161 timestamp. " +
    "The chain below proves both readings existed at the times shown — neither can be back-dated " +
    "without breaking the cryptographic chain.");
  doc.moveDown(0.5);

  const prev = dc.previous_tsa_serial ?? null;
  const curr = dc.current_tsa_serial ?? null;
  const lx = doc.page.margins.left;
  doc.font(FONTS.mono).fontSize(9).fillColor(PAPER.ink);
  doc.text(`previous_tsa_serial : ${prev ?? "— (cold start — first reading)"}`, lx, doc.y, { width: PAGE.textWidth });
  doc.text(`current_tsa_serial  : ${curr ?? "— (TSA unavailable this run)"}`, lx, doc.y, { width: PAGE.textWidth });
  doc.x = lx;
  doc.moveDown(0.6);

  sectionTitle(doc, "Diff summary");
  const ds = dc.diff_summary ?? { added: 0, removed: 0, changed: 0 };
  const tableY = doc.y;
  const cx = doc.page.margins.left;
  const cells = [
    { label: "ADDED", value: ds.added ?? 0, color: PAPER.green },
    { label: "REMOVED", value: ds.removed ?? 0, color: PAPER.red },
    { label: "CHANGED", value: ds.changed ?? 0, color: PAPER.amber },
  ];
  const cellW = PAGE.textWidth / 3;
  for (let i = 0; i < cells.length; i++) {
    const c = cells[i];
    const cellX = cx + i * cellW;
    doc.rect(cellX + 4, tableY, cellW - 8, 56).fill(PAPER.zebra);
    doc.font(FONTS.mono).fontSize(8).fillColor(PAPER.muted).text(c.label, cellX + 12, tableY + 8, { width: cellW - 24 });
    doc.font(FONTS.bold).fontSize(28).fillColor(c.color).text(String(c.value), cellX + 12, tableY + 20, { width: cellW - 24 });
    doc.fillColor(PAPER.ink);
  }
  // Reset doc.x to the left margin after the far-right cell (Phase-1 overflow fix).
  doc.x = doc.page.margins.left;
  doc.y = tableY + 64;
  doc.moveDown(0.6);

  sectionTitle(doc, "Knowledge graph status (Cognee)");
  const kgStatus = dc.kg_status ?? "skipped";
  const kgColor = kgStatus === "ingested" ? PAPER.green : kgStatus === "unreachable" ? PAPER.amber : PAPER.muted;
  doc.font(FONTS.semibold).fontSize(10).fillColor(kgColor).text(`status: ${kgStatus.toUpperCase()}`, lx, doc.y);
  if (dc.kg_skip_reason) {
    doc.font(FONTS.body).fontSize(9).fillColor(PAPER.muted).text(`reason: ${dc.kg_skip_reason}`, lx, doc.y);
  }
  doc.fillColor(PAPER.ink).x = lx;
  doc.moveDown(0.6);

  const sealParts = [seal.method ?? "HMAC-SHA256"];
  if (rekorLogIndex(ctx.rekorBundle) != null) sealParts.push("Sigstore Rekor v2");
  if (ctx.c2paSidecar) sealParts.push("C2PA");
  doc.font(FONTS.body).fontSize(8).fillColor(PAPER.muted).text(
    "What this proves: the bytes of the target changed between the two timestamps shown. " +
    "What this does NOT prove: the truthfulness of either reading. Both snapshots are sealed " +
    `with ${sealParts.join(" + ")} — verify with bin/decode-evidence.js.`,
    lx, doc.y, { width: PAGE.textWidth }).fillColor(PAPER.ink);
  doc.x = lx;
}
