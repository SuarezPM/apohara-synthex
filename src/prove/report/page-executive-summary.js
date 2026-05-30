// PROVE/report/page-executive-summary — the COVER (page 1). WHITE letterhead cover: a full-bleed
// branded header banner (the Apohara artwork — public/hero-apohara-landscape.jpg) over a clean
// white body (verdict + real seal stack + QR + metadata), closed by a branded dark footer band
// (drawn in the buffered pass). Brand-faithful to synthex.apohara.dev; no "court-grade".
//
// Vertical flow uses MANUAL y-stepping for single-line headings: PDFKit does NOT advance doc.y
// after a `lineBreak:false` draw, so reading doc.y there overlaps the next element (the Phase-2a
// cover bug). Single lines step y by a fixed amount; only wrapping blocks read doc.y.
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { COVER, PAPER, FONTS, TYPE, PAGE, VOICE } from "./theme.js";
import { sealBlock } from "./components.js";
import { riskScore } from "./risk-score.js";

const here = dirname(fileURLToPath(import.meta.url));
// Canonical brand artwork (shield logo + APOHARA wordmark + neon waves). Committed asset.
const BANNER = resolve(here, "../../../public/hero-apohara-landscape.jpg");

export function pageExecutiveSummary(doc, ev, ctx = {}) {
  const { payload = {}, contentHash, seal = {}, sealedAt } = ev;
  const { qrPng, registry, reportId, c2paSidecar, rekorBundle } = ctx;
  const W = doc.page.width;
  const H = doc.page.height;
  const L = PAGE.margins.left;
  const R = W - PAGE.margins.right;
  const colW = R - L;
  const pal = PAPER; // white cover uses the interior (light) palette for body text

  // single-line heading at an explicit y, no wrap; caller steps y by a fixed amount.
  const lineAt = (yy, font, size, color, text, extra = {}) => {
    doc.font(font).fontSize(size).fillColor(color)
      .text(text, L, yy, { lineBreak: false, ...extra });
  };

  // ── white page ──────────────────────────────────────────────────────────────
  doc.save().rect(0, 0, W, H).fill("#FFFFFF").restore();

  // ── branded header banner (full-bleed) — the Apohara artwork clipped to a band ──
  const bandH = 178;
  if (existsSync(BANNER)) {
    doc.save();
    doc.rect(0, 0, W, bandH).clip();
    // Cover the band width-wise; the artwork extends below and is clipped to bandH,
    // showing the logo + wordmark + the upper neon waves + stars.
    doc.image(BANNER, 0, 0, { width: W });
    doc.restore();
  } else {
    // Fallback brand band (artwork absent): dark void with the wordmark.
    doc.save().rect(0, 0, W, bandH).fill(COVER.bg).restore();
    doc.font(FONTS.bold).fontSize(30).fillColor(COVER.ink)
      .text("APOHARA", 0, bandH / 2 - 18, { width: W, align: "center", lineBreak: false });
  }
  // thin lime transition rule under the banner (brand → white).
  doc.rect(0, bandH, W, 2.5).fill(PAPER.green);

  // ── document title block ───────────────────────────────────────────────────────
  let y = bandH + 30;
  lineAt(y, FONTS.bold, 25, pal.ink, "Evidence Report");
  y += 34;
  lineAt(y, FONTS.body, 10, pal.muted, "Sealed · tamper-evident · independently verifiable.");
  y += 15;
  lineAt(y, FONTS.body, 9.5, pal.muted, VOICE.coverCouplet);
  y += 28;

  // ── VERDICT (band-matched, distinct-axis labeled so it never contradicts) ──────
  const r = riskScore(ev);
  const leadBand = r.maxSev >= 7 ? "HIGH" : r.maxSev >= 4 ? "MEDIUM" : "LOW";
  const bandColor = leadBand === "HIGH" ? pal.red : leadBand === "MEDIUM" ? pal.amber : pal.green;
  const verdictText = (payload.verdict && typeof payload.verdict === "string") ? payload.verdict : `${leadBand} RISK`;

  lineAt(y, FONTS.mono, TYPE.kicker.size, pal.violet, "VERDICT · LEAD FINDING (CVSS SEVERITY)", { characterSpacing: TYPE.kicker.tracking });
  y += 17;
  lineAt(y, FONTS.bold, 28, bandColor, `${leadBand} · CVSS ${Number(r.maxSev).toFixed(1)}`);
  y += 37;
  // sealed verdict sentence — WRAPS, so doc.y advances correctly here.
  doc.font(FONTS.body).fontSize(9.5).fillColor(pal.ink).text(verdictText, L, y, { width: colW });
  y = doc.y + 26;

  // ── cryptographic seal (Ed25519 leads) + QR side-by-side ───────────────────────
  lineAt(y, FONTS.mono, TYPE.kicker.size, pal.violet, "CRYPTOGRAPHIC SEAL", { characterSpacing: TYPE.kicker.tracking });
  y += 16;

  const sealTop = y;
  const qrSize = 110;
  doc.x = L;
  doc.y = sealTop;
  sealBlock(doc, {
    theme: pal, seal, contentHash, c2paSidecar, rekorBundle,
    width: colW - qrSize - 28, accentColor: pal.violet,
  });
  doc.font(FONTS.mono).fontSize(TYPE.code.size).fillColor(pal.muted)
    .text(`method · ${seal.method ?? "—"}`, L, doc.y + 3, { width: colW - qrSize - 28 });
  const sealBottom = doc.y;

  // QR — dark-on-white, top-right of the seal block, encoding the verifiable-bundle pointer.
  if (qrPng) {
    try {
      doc.image(qrPng, R - qrSize, sealTop, { width: qrSize });
      doc.font(FONTS.mono).fontSize(7).fillColor(pal.muted)
        .text("scan to verify", R - qrSize, sealTop + qrSize + 4, { width: qrSize, align: "center", lineBreak: false });
    } catch { /* layout best-effort */ }
  }

  // ── metadata strip: target / lens / fetched / sealed / sources / blocked ────────
  let my = Math.max(sealBottom, sealTop + qrSize + 22) + 18;
  doc.moveTo(L, my).lineTo(R, my).strokeColor(pal.rule).lineWidth(0.5).stroke();
  my += 14;

  const blockedN = (payload.blocked ?? []).length;
  const meta = [
    ["TARGET", Array.isArray(payload.target) ? payload.target.join(", ") : (payload.target ?? "—")],
    ["LENS", payload.lens ?? "—"],
    ["FETCHED", payload.fetchedAt ?? "—"],
    ["SEALED", sealedAt ?? "—"],
    ["SOURCES", String((payload.sources ?? []).length)],
    ["BLOCKED PRE-LLM", String(blockedN)],
  ];
  const cellW = colW / 3;
  meta.forEach(([label, value], i) => {
    const col = i % 3;
    const rowIdx = Math.floor(i / 3);
    const cx = L + col * cellW;
    const cy = my + rowIdx * 40;
    doc.font(FONTS.mono).fontSize(7).fillColor(pal.muted)
      .text(label, cx, cy, { width: cellW - 10, characterSpacing: 1, lineBreak: false });
    const valColor = label === "BLOCKED PRE-LLM" ? (blockedN ? pal.amber : pal.green) : pal.ink;
    doc.font(FONTS.medium).fontSize(10).fillColor(valColor)
      .text(value, cx, cy + 12, { width: cellW - 10, ellipsis: true, lineBreak: false, height: 14 });
  });

  // The branded dark footer band is drawn in the buffered pass (drawFooters, cover variant),
  // where the total page count is known. Register this page as the cover.
  if (registry) registry.push({ pageIndex: doc.bufferedPageRange().count - 1, reportId, cover: true });
}
