// PROVE/report/components — reusable PDFKit helpers for the Evidence Report. Each takes the
// live `doc` + a palette object (COVER or PAPER from theme.js) so cover/interior pull from ONE
// source. Small + cohesive (project rule: many small files). The hard rule, repeated from the
// design audit: tables NEVER overflow — measure → grow → paginate — and ALWAYS reset doc.x to
// the left margin before any wrapping block (the Phase-1 Counsel/Delta overflow fix).
import { FONTS, TYPE, PAGE, VOICE, reportIdOf } from "./theme.js";

// ── value truncation (design spec §4) ─────────────────────────────────────────
// Trunca un valor largo (firma/keyId/hash/url) a head…tail con elipsis REAL. El valor COMPLETO
// vive en el sidecar evidence.json — nunca un truncado sin ruta al completo.
export function truncMid(value, head = 16, tail = 12) {
  const s = String(value ?? "");
  if (s.length <= head + tail + 1) return s;
  return tail > 0 ? `${s.slice(0, head)}…${s.slice(-tail)}` : `${s.slice(0, head)}…`;
}

// Lee el logIndex de un bundle Rekor v2, tolerante a su forma real. null → row present-gated.
export function rekorLogIndex(bundle) {
  if (!bundle) return null;
  return bundle?.tlogEntry?.logIndex ?? bundle?.logIndex ?? null;
}

// ── footer registry (buffered pass) ────────────────────────────────────────────
// pageFrame registers each page's footer triplet here; pdf-report's drawFooters() consumes it in
// the bufferPages pass so writing into the bottom margin never triggers PDFKit auto-pagination.
export function makeFooterRegistry() {
  return [];
}

// ── pageFrame: persona tag (kicker) + H1, and register the footer for the buffered pass ────────
// dark=true → cover variant (ink on void); else interior (muted ink on paper). Returns nothing;
// leaves the cursor below the H1 at the left margin so content flows.
export function pageFrame(doc, { theme, persona, title, reportId, dark = false, registry }) {
  const pal = theme; // caller passes COVER or PAPER
  doc.x = doc.page.margins.left;
  doc.y = doc.page.margins.top;

  if (persona) {
    setType(doc, TYPE.kicker);
    doc.fillColor(dark ? pal.muted : pal.violet)
      .text(persona.toUpperCase(), doc.page.margins.left, doc.y, { width: PAGE.textWidth, characterSpacing: TYPE.kicker.tracking });
    doc.moveDown(0.4);
  }
  if (title) {
    setType(doc, TYPE.h1);
    doc.fillColor(pal.ink).text(title, doc.page.margins.left, doc.y, { width: PAGE.textWidth });
    doc.moveDown(0.6);
  }
  doc.x = doc.page.margins.left;

  // Register the footer for this page so the buffered pass can stamp it (left: report ID,
  // center: verbatim disclaimer, right: p N/M). variant carried so cover stays dark.
  if (registry) registry.push({ pageIndex: doc.bufferedPageRange().count - 1, reportId, dark });
}

// Stamp the footer band on every buffered page (called once, after all pages, in the buffered
// pass). Anula el margen inferior para escribir al pie sin disparar auto-paginado. variant per
// registry entry: dark cover footer = ink on void; interior = muted on paper.
export function drawFooters(doc, { theme, registry }) {
  const total = doc.bufferedPageRange().count;
  const byIndex = new Map(registry.map((r) => [r.pageIndex, r]));
  for (let i = 0; i < total; i++) {
    doc.switchToPage(i);
    doc.page.margins.bottom = 0;
    const meta = byIndex.get(i) ?? { reportId: reportIdOf(""), dark: false };
    // Cover: a branded full-bleed dark footer band (wordmark + tagline + id + page).
    if (meta.cover) {
      const fH = 38;
      const by = doc.page.height - fH;
      const left2 = doc.page.margins.left;
      const rx = doc.page.width - doc.page.margins.right - 220;
      doc.save().rect(0, by, doc.page.width, fH).fill(theme.COVER.bg).restore();
      doc.font(FONTS.semibold).fontSize(8.5).fillColor(theme.COVER.ink)
        .text("APOHARA SYNTHEX", left2, by + 9, { characterSpacing: 0.5, lineBreak: false });
      doc.font(FONTS.body).fontSize(7.5).fillColor(theme.COVER.muted)
        .text("everything signed, nothing trusted.", left2, by + 21, { lineBreak: false });
      doc.font(FONTS.mono).fontSize(7).fillColor(theme.COVER.muted)
        .text(meta.reportId, rx, by + 9, { width: 220, align: "right", lineBreak: false });
      doc.font(FONTS.mono).fontSize(7).fillColor(theme.COVER.muted)
        .text(`p. ${i + 1} / ${total}`, rx, by + 21, { width: 220, align: "right", lineBreak: false });
      continue;
    }
    const pal = meta.dark ? theme.COVER : theme.PAPER;
    const y = doc.page.height - 44;
    const left = doc.page.margins.left;
    const w = doc.page.width - left - doc.page.margins.right;

    // left: report ID (Mono); right: page N/M (Mono); center: verbatim disclaimer (Inter).
    setType(doc, TYPE.footer);
    doc.font(FONTS.mono).fontSize(TYPE.footer.size).fillColor(pal.muted)
      .text(meta.reportId, left, y, { width: 150, lineBreak: false });
    doc.font(FONTS.mono).fontSize(TYPE.footer.size).fillColor(pal.muted)
      .text(`p. ${i + 1} / ${total}`, doc.page.width - doc.page.margins.right - 70, y, { width: 70, align: "right", lineBreak: false });
    doc.font(FONTS.body).fontSize(TYPE.footer.size).fillColor(pal.muted)
      .text(VOICE.disclaimer, left + 158, y - 4, { width: w - 158 - 78, align: "center" });
  }
}

// ── type helper: apply a TYPE entry's font+size (caller sets fillColor) ─────────
function setType(doc, t) {
  doc.font(t.font).fontSize(t.size);
  return doc;
}

// ── sectionTitle: interior section heading with a hairline underline ───────────
export function sectionTitle(doc, { theme, text }) {
  doc.x = doc.page.margins.left;
  setType(doc, TYPE.sectionTitle);
  doc.fillColor(theme.ink).text(text, doc.page.margins.left, doc.y, {
    width: PAGE.textWidth, characterSpacing: TYPE.sectionTitle.tracking,
  });
  doc.moveTo(doc.page.margins.left, doc.y + 2)
    .lineTo(doc.page.width - doc.page.margins.right, doc.y + 2)
    .strokeColor(theme.rule).lineWidth(0.5).stroke();
  doc.moveDown(0.7);
  doc.x = doc.page.margins.left;
}

// ── body paragraph ─────────────────────────────────────────────────────────────
export function paragraph(doc, { theme, text, color }) {
  doc.x = doc.page.margins.left;
  setType(doc, TYPE.body);
  doc.fillColor(color ?? theme.ink).text(text, doc.page.margins.left, doc.y, {
    width: PAGE.textWidth, lineGap: TYPE.body.leading - TYPE.body.size - 1,
  });
  doc.x = doc.page.margins.left;
}

// ── table: sized-to-content, NEVER overflow (design spec §4) ───────────────────
// columns: [{ key, header, width?, align?('left'|'right'), mono?, trunc?([head,tail]) }].
// Widths sum to PAGE.textWidth; an unsized column gets the slack. Numerics right-aligned Mono.
// Rows measured with heightOfString → grow; if a row would cross the footer band, paginate
// (repeat header + "(cont.)"). Zebra + 0.5pt hairlines; header underlined 1pt ink.
export function table(doc, { theme, columns, rows, onNewPage }) {
  const left = doc.page.margins.left;
  const cols = resolveWidths(columns);
  const cellPadX = 4;
  const footerTop = doc.page.height - PAGE.footerBand; // never draw below this

  const drawHeader = (cont) => {
    doc.x = left;
    let cx = left;
    setType(doc, TYPE.tableHeader);
    doc.fillColor(theme.muted);
    for (const c of cols) {
      const label = `${c.header ?? c.key}${cont && c === cols[0] ? " (cont.)" : ""}`;
      doc.text(label.toUpperCase(), cx + cellPadX, doc.y, {
        width: c.width - cellPadX * 2, align: c.align === "right" ? "right" : "left",
        characterSpacing: TYPE.tableHeader.tracking, lineBreak: false,
      });
      cx += c.width;
    }
    const hy = doc.y + TYPE.tableHeader.leading - 2;
    doc.moveTo(left, hy).lineTo(left + cols.reduce((a, c) => a + c.width, 0), hy)
      .strokeColor(theme.ink).lineWidth(1).stroke();
    doc.y = hy + 4;
    doc.x = left;
  };

  drawHeader(false);

  let zebra = false;
  for (const row of rows) {
    // measure: the tallest cell drives row height.
    const cellTexts = cols.map((c) => formatCell(row[c.key], c));
    setType(doc, TYPE.tableCell);
    let rowH = 0;
    cols.forEach((c, i) => {
      const f = c.mono || c.align === "right" ? FONTS.mono : FONTS.body;
      doc.font(f).fontSize(TYPE.tableCell.size);
      const h = doc.heightOfString(cellTexts[i], { width: c.width - cellPadX * 2 });
      rowH = Math.max(rowH, h);
    });
    rowH = Math.max(rowH, TYPE.tableCell.leading) + 4;

    // paginate if this row would cross the footer band.
    if (doc.y + rowH > footerTop) {
      doc.addPage();
      if (onNewPage) onNewPage(doc);
      drawHeader(true);
      zebra = false;
    }

    const rowY = doc.y;
    if (zebra) {
      doc.rect(left, rowY - 1, cols.reduce((a, c) => a + c.width, 0), rowH).fill(theme.zebra);
    }
    let cx = left;
    cols.forEach((c, i) => {
      const mono = c.mono || c.align === "right";
      doc.font(mono ? FONTS.mono : FONTS.body).fontSize(TYPE.tableCell.size).fillColor(theme.ink);
      doc.text(cellTexts[i], cx + cellPadX, rowY + 1, {
        width: c.width - cellPadX * 2, align: c.align === "right" ? "right" : "left",
      });
      cx += c.width;
    });
    // hairline rule under the row.
    doc.moveTo(left, rowY + rowH - 1).lineTo(left + cols.reduce((a, c) => a + c.width, 0), rowY + rowH - 1)
      .strokeColor(theme.rule).lineWidth(0.5).stroke();
    doc.y = rowY + rowH;
    doc.x = left;
    zebra = !zebra;
  }
  doc.x = left; // ALWAYS reset before whatever follows
}

function resolveWidths(columns) {
  const sized = columns.filter((c) => typeof c.width === "number");
  const used = sized.reduce((a, c) => a + c.width, 0);
  const unsized = columns.filter((c) => typeof c.width !== "number");
  const slack = Math.max(0, PAGE.textWidth - used);
  const per = unsized.length ? slack / unsized.length : 0;
  return columns.map((c) => ({ ...c, width: typeof c.width === "number" ? c.width : per }));
}

function formatCell(value, col) {
  let s = value == null ? "—" : String(value);
  if (col.trunc) s = truncMid(s, col.trunc[0], col.trunc[1]);
  return s;
}

// ── sealBlock: lead Ed25519, present-gated layers, HMAC labeled internal checksum ──
// Extracts Phase-1 sealRows() ordering exactly: Ed25519 → RFC 3161 TSA → Rekor → C2PA →
// SHA-256 → HMAC (internal integrity checksum). Renders as a label/value list in Mono.
export function sealRows({ seal, contentHash, c2paSidecar, rekorBundle }) {
  const rows = [];
  const sig = seal?.signature;
  if (sig) {
    rows.push(["Ed25519 sig", `keyId ${sig.keyId ?? "—"}`]);
    rows.push(["", truncMid(sig.value)]);
  }
  const tsa = seal?.rfc3161Tsa;
  if (tsa) {
    rows.push(["RFC 3161 TSA", `${tsa.authority ?? "DigiCert"} · ${tsa.genTime ?? "—"}`]);
    rows.push(["", `serial ${tsa.serial ?? "—"}`]);
  }
  const logIndex = rekorLogIndex(rekorBundle);
  if (logIndex != null) rows.push(["Sigstore Rekor v2", `logIndex ${logIndex}`]);
  if (c2paSidecar) rows.push(["C2PA Content Cred.", "present (sidecar)"]);
  rows.push(["SHA-256 hash", truncMid(contentHash, 20, 16)]);
  rows.push(["HMAC-SHA256", `${truncMid(seal?.hmacSha256, 20, 16)}  (internal integrity checksum)`]);
  return rows;
}

// Draw the seal block at the current cursor. opts.accentColor used on the leading label so
// Ed25519 visually leads. width defaults to a column so the QR can sit beside it on the cover.
export function sealBlock(doc, { theme, seal, contentHash, c2paSidecar, rekorBundle, width = 360, accentColor }) {
  const left = doc.page.margins.left;
  doc.x = left;
  const rows = sealRows({ seal, contentHash, c2paSidecar, rekorBundle });
  const accent = accentColor ?? theme.violet;
  for (const [label, value] of rows) {
    const y = doc.y;
    if (label) {
      doc.font(FONTS.monoBold).fontSize(TYPE.code.size).fillColor(label.startsWith("Ed25519") ? accent : theme.muted)
        .text(label, left, y, { width: 116, lineBreak: false });
      doc.font(FONTS.mono).fontSize(TYPE.code.size).fillColor(theme.ink)
        .text(value, left + 122, y, { width: width - 122 });
    } else {
      // continuation line (sig value / TSA serial): indent, no label.
      doc.font(FONTS.mono).fontSize(TYPE.code.size).fillColor(theme.muted)
        .text(value, left + 122, y, { width: width - 122 });
    }
    doc.x = left;
  }
  doc.x = left;
}

// ── ragRow: green ✓ / amber ▲ / red ✗ with token color AND a text label (a11y: never color alone) ──
const RAG_GLYPH = { green: "✓", amber: "▲", red: "✗" };
export function ragRow(doc, { theme, label, status, detail, labelWidth = 200 }) {
  const left = doc.page.margins.left;
  const color = status === "green" ? theme.green : status === "amber" ? theme.amber : theme.red;
  const glyph = RAG_GLYPH[status] ?? "•";
  const statusText = status === "green" ? "OK" : status === "amber" ? "PARTIAL" : "FAIL";
  const y = doc.y;
  setType(doc, TYPE.tableCell);
  doc.font(FONTS.monoBold).fillColor(color).text(`${glyph} ${statusText}`, left, y, { width: 86, lineBreak: false });
  doc.font(FONTS.body).fontSize(TYPE.tableCell.size).fillColor(theme.ink)
    .text(label, left + 92, y, { width: labelWidth, lineBreak: false });
  if (detail) {
    doc.font(FONTS.body).fontSize(TYPE.tableCell.size).fillColor(theme.muted)
      .text(detail, left + 92 + labelWidth, y, { width: PAGE.textWidth - 92 - labelWidth });
  }
  doc.x = left;
  doc.moveDown(0.4);
}

// ── codeBox: INTERIOR light tinted box (#f0f0ec) + hairline + Mono ink (printable) ──
// NOT a dark block — toner-friendly per Pablo's directive (design spec §0/§5).
export function codeBox(doc, { theme, lines, color }) {
  const left = doc.page.margins.left;
  const w = PAGE.textWidth;
  const pad = 6;
  const text = Array.isArray(lines) ? lines.join("\n") : String(lines ?? "");
  doc.font(FONTS.mono).fontSize(TYPE.code.size);
  const innerW = w - pad * 2;
  const h = doc.heightOfString(text, { width: innerW, lineGap: TYPE.code.leading - TYPE.code.size }) + pad * 2;
  const y = doc.y;
  doc.rect(left, y, w, h).fill(theme.codebg);
  doc.rect(left, y, w, h).lineWidth(0.5).strokeColor(theme.rule).stroke();
  doc.font(FONTS.mono).fontSize(TYPE.code.size).fillColor(color ?? theme.ink)
    .text(text, left + pad, y + pad, { width: innerW, lineGap: TYPE.code.leading - TYPE.code.size });
  doc.y = y + h;
  doc.x = left;
  doc.moveDown(0.4);
}

// ── RAG coverage vocabulary (shared by mappingTable + frameworkMatrix) ──────────
// Maps a coverage word to its RAG status + a glyphed text label. full = pack-validated AND
// policy-covered · partial = one signal · none = none. Text label ALWAYS present (a11y: never
// color alone). Unknown coverage degrades to amber/partial rather than throwing.
const COVERAGE = {
  full: { status: "green", glyph: "✓", word: "full" },
  partial: { status: "amber", glyph: "▲", word: "partial" },
  none: { status: "red", glyph: "✗", word: "none" },
};
function coverageOf(value) {
  return COVERAGE[String(value ?? "").toLowerCase()] ?? COVERAGE.partial;
}
const COVERAGE_LEGEND =
  "Coverage: full = pack-validated AND policy-covered · partial = one signal · none = none.";

// Apply a TYPE entry's font+size (caller sets fillColor). Local copy so the helpers below do not
// depend on the private setType above.
function applyType(doc, t) {
  doc.font(t.font).fontSize(t.size);
}

// ── mappingTable: signal → framework mapping, sized-to-content, NEVER overflow ──
// rows: [{ signal, framework, coverage('full'|'partial'|'none'), note? }]. Reuses table()
// internally (measure → grow → paginate). The coverage column carries the glyphed RAG word so it
// is legible without color (a11y). The legend is printed once above the table.
export function mappingTable(doc, { theme, rows = [] }) {
  const left = doc.page.margins.left;
  doc.x = left;
  applyType(doc, TYPE.footer);
  doc.fillColor(theme.muted).text(COVERAGE_LEGEND, left, doc.y, { width: PAGE.textWidth });
  doc.moveDown(0.4);
  doc.x = left;

  const tableRows = rows.map((r) => {
    const cov = coverageOf(r.coverage);
    return { ...r, coverageLabel: `${cov.glyph} ${cov.word}` };
  });
  table(doc, {
    theme,
    columns: [
      { key: "signal", header: "Signal" },
      { key: "framework", header: "Framework / control", width: 150 },
      { key: "coverageLabel", header: "Coverage", width: 78 },
    ],
    rows: tableRows,
  });
  doc.x = left;
}

// ── frameworkMatrix: control/article → RAG status + citation, NEVER overflow ────
// rows: [{ control, status('green'|'amber'|'red'), citation }]. Reuses ragRow() per row, which
// already renders the glyph + color + a text status (a11y) + the control label + the citation as
// detail. ragRow advances the cursor; rows never clip (one line each, wrap-safe in the detail).
export function frameworkMatrix(doc, { theme, rows = [] }) {
  const left = doc.page.margins.left;
  doc.x = left;
  for (const r of rows) {
    ragRow(doc, { theme, label: r.control, status: r.status, detail: r.citation, labelWidth: 168 });
  }
  doc.x = left;
}

// ── attestationRow: one model-id / hash attestation line (label → mono value) ──
// A single label/value line for the Model & Pipeline Attestation page: the label in muted Inter,
// the value in Mono (it is usually an id/version/SHA-256). Long values truncate head…tail; the
// FULL value lives in the sidecar evidence.json (design spec §4). Single-line, no wrap, manual
// y-step (PDFKit does not advance doc.y after a lineBreak:false draw).
export function attestationRow(doc, { theme, label, value, trunc = [22, 14] }) {
  const left = doc.page.margins.left;
  const y = doc.y;
  const labelW = 150;
  applyType(doc, TYPE.tableCell);
  doc.font(FONTS.body).fillColor(theme.muted).text(label, left, y, { width: labelW, lineBreak: false });
  const shown = trunc ? truncMid(value, trunc[0], trunc[1]) : String(value ?? "—");
  doc.font(FONTS.mono).fillColor(theme.ink)
    .text(shown, left + labelW + 8, y, { width: PAGE.textWidth - labelW - 8, lineBreak: false });
  doc.x = left;
  doc.y = y + TYPE.tableCell.leading + 2;
}
