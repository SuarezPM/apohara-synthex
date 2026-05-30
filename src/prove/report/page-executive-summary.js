// PROVE/report/page-executive-summary — the COVER (page 1). FULL-BLEED DARK (--void), edge-to
// -edge: the brand moment + at-a-glance verdict/seal. Rebuilt per docs/internal/
// EVIDENCE_REPORT_DESIGN.md §0/§5/§8. A single thin lime "fold" rule sits at the base as the
// transition signal to the light interior. NO "court-grade", no invented metric.
import { COVER, FONTS, TYPE, PAGE, VOICE } from "./theme.js";
import { sealBlock } from "./components.js";
import { riskScore } from "./risk-score.js";

// Resolve the cover wordmark font: Pixel if the Press Start 2P TTF registered, else Mono (spec §2).
function wordmarkFont(doc) {
  // PDFKit throws on an unknown font name; probe by checking the registered set via a try.
  try { doc.font(FONTS.pixel); return FONTS.pixel; } catch { return FONTS.mono; }
}

export function pageExecutiveSummary(doc, ev, ctx = {}) {
  const { payload = {}, contentHash, seal = {}, sealedAt } = ev;
  const { qrPng, registry, reportId, c2paSidecar, rekorBundle } = ctx;
  const W = doc.page.width;
  const H = doc.page.height;
  const L = PAGE.margins.left;
  const R = W - PAGE.margins.right;
  const colW = R - L;

  // ── full-bleed void ────────────────────────────────────────────────────────
  doc.save().rect(0, 0, W, H).fill(COVER.bg).restore();

  // ── wordmark + kicker ────────────────────────────────────────────────────────
  let y = PAGE.margins.top;
  const wmFont = wordmarkFont(doc);
  doc.font(wmFont).fontSize(TYPE.coverWordmark.size).fillColor(COVER.ink)
    .text("APOHARA SYNTHEX", L, y, { characterSpacing: TYPE.coverWordmark.tracking, lineBreak: false });
  y = doc.y + 6;
  doc.font(FONTS.mono).fontSize(TYPE.kicker.size).fillColor(COVER.violet)
    .text("EVIDENCE REPORT · SEALED", L, y, { characterSpacing: TYPE.kicker.tracking, lineBreak: false });
  y = doc.y + 18;

  // ── value couplet (the one-line value) ──────────────────────────────────────
  doc.font(FONTS.semibold).fontSize(13).fillColor(COVER.ink)
    .text(VOICE.coverCouplet, L, y, { width: colW });
  y = doc.y + 22;

  // ── VERDICT (band-matched, distinct-axis labeled so it never contradicts) ────
  const r = riskScore(ev);
  // The headline verdict uses the LEAD-FINDING CVSS-severity axis (maxSev ≥7 HIGH / ≥4 MEDIUM /
  // else LOW) — a DIFFERENT scale from the composite 0–100 gauge on the Underwriter page. Caption
  // the lead severity so the two bands can never read as a contradiction.
  const leadBand = r.maxSev >= 7 ? "HIGH" : r.maxSev >= 4 ? "MEDIUM" : "LOW";
  const bandColor = leadBand === "HIGH" ? COVER.red : leadBand === "MEDIUM" ? COVER.amber : COVER.lime;
  const verdictText = (payload.verdict && typeof payload.verdict === "string") ? payload.verdict : `${leadBand} RISK`;

  doc.font(FONTS.mono).fontSize(TYPE.kicker.size).fillColor(COVER.muted)
    .text("VERDICT · LEAD FINDING (CVSS SEVERITY)", L, y, { characterSpacing: TYPE.kicker.tracking, lineBreak: false });
  y = doc.y + 6;
  doc.font(FONTS.bold).fontSize(TYPE.coverVerdict.size).fillColor(bandColor)
    .text(`${leadBand} · CVSS ${Number(r.maxSev).toFixed(1)}`, L, y, { width: colW });
  y = doc.y + 4;
  // the sealed verdict string, rendered verbatim (we never edit its bytes).
  doc.font(FONTS.body).fontSize(9.5).fillColor(COVER.ink)
    .text(verdictText, L, y, { width: colW });
  y = doc.y + 20;

  // ── seal stack (Ed25519 leads) + QR side-by-side ────────────────────────────
  doc.font(FONTS.mono).fontSize(TYPE.kicker.size).fillColor(COVER.violet)
    .text("CRYPTOGRAPHIC SEAL", L, y, { characterSpacing: TYPE.kicker.tracking, lineBreak: false });
  y = doc.y + 8;

  const sealTop = y;
  const qrSize = 118;
  doc.x = L;
  doc.y = sealTop;
  // sealBlock leads with Ed25519 (violet accent on void) per the design system.
  sealBlock(doc, {
    theme: COVER, seal, contentHash, c2paSidecar, rekorBundle,
    width: colW - qrSize - 24, accentColor: COVER.violet,
  });
  // seal method line.
  doc.font(FONTS.mono).fontSize(TYPE.code.size).fillColor(COVER.muted)
    .text(`method · ${seal.method ?? "—"}`, L, doc.y + 2, { width: colW - qrSize - 24 });
  const sealBottom = doc.y;

  // QR — lime on void, top-right of the seal block, encoding the verifiable-bundle pointer.
  if (qrPng) {
    try {
      doc.image(qrPng, R - qrSize, sealTop, { width: qrSize });
      doc.font(FONTS.mono).fontSize(7).fillColor(COVER.lime)
        .text("scan to verify", R - qrSize, sealTop + qrSize + 4, { width: qrSize, align: "center", lineBreak: false });
    } catch { /* layout best-effort */ }
  }

  // ── metadata strip: target / lens / fetched / sealed / sources / blocked ─────
  let my = Math.max(sealBottom, sealTop + qrSize + 22) + 18;
  doc.moveTo(L, my).lineTo(R, my).strokeColor(COVER.muted).lineWidth(0.5).opacity(0.4).stroke().opacity(1);
  my += 12;

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
    const cy = my + rowIdx * 38;
    doc.font(FONTS.mono).fontSize(7).fillColor(COVER.muted)
      .text(label, cx, cy, { width: cellW - 10, characterSpacing: 1, lineBreak: false });
    const valColor = label === "BLOCKED PRE-LLM" ? (blockedN ? COVER.amber : COVER.lime) : COVER.ink;
    doc.font(FONTS.medium).fontSize(10).fillColor(valColor)
      .text(value, cx, cy + 11, { width: cellW - 10, ellipsis: true, lineBreak: false, height: 14 });
  });

  // ── cover signature + the single thin lime "fold" rule at the base ──────────
  doc.font(FONTS.body).fontSize(8).fillColor(COVER.muted)
    .text(VOICE.coverSignature, L, H - 78, { width: colW, lineBreak: false });
  // the fold rule — full bleed, thin, lime.
  doc.rect(0, H - 3, W, 3).fill(COVER.lime);

  // register the cover footer (dark variant) for the buffered pass.
  if (registry) registry.push({ pageIndex: doc.bufferedPageRange().count - 1, reportId, dark: true });
}
