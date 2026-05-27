// PROVE/pdf-report — Evidence Report como PDF descargable (el artefacto que un juez/CISO/CFO
// se lleva). Consume el objeto de buildEvidence() y lo renderiza en 4 secciones, incluyendo el
// comando REAL para que cualquiera verifique el timestamp por su cuenta. Implementa el patrón
// del IETF draft-marques-asqav-compliance-receipts (Mayo 2026): un "Compliance Receipt" firmado.
import PDFDocument from "pdfkit";
import QRCode from "qrcode";

const COLORS = { brand: "#5b21b6", ok: "#15803d", warn: "#b45309", crit: "#b91c1c", muted: "#6b7280" };
const sevColor = (s) => (s >= 8 ? COLORS.crit : s >= 5 ? COLORS.warn : COLORS.ok);

// Normaliza un finding (plano o tri-lens) a filas {lens, severity, summary, signals}.
function rowsOf(finding) {
  if (finding.trilens) {
    return Object.entries(finding.trilens).map(([lens, c]) => ({ url: finding.url, lens, ...c }));
  }
  return [{ url: finding.url, lens: finding.lens, severity: finding.severity, summary: finding.summary, signals: finding.signals }];
}

/**
 * Genera el Evidence Report en PDF.
 * @param {object} evidence  salida de buildEvidence().
 * @returns {Promise<Buffer>} bytes del PDF.
 */
export async function buildPDFReport(evidence) {
  const { payload = {}, contentHash, seal = {}, sealedAt } = evidence;
  const tsa = seal.rfc3161Tsa;

  // QR con los datos de verificación (hash + sello + momento) — escaneás y verificás.
  const qrPayload = JSON.stringify({ hash: contentHash, method: seal.method, sealedAt, tsaSerial: tsa?.serial ?? null });
  const qrPng = await QRCode.toBuffer(qrPayload, { errorCorrectionLevel: "M", margin: 1, width: 120 });

  const doc = new PDFDocument({ size: "A4", margin: 50, info: { Title: "Synthex Evidence Report", Author: "Apohara Synthex" } });
  const chunks = [];
  doc.on("data", (c) => chunks.push(c));
  const done = new Promise((res) => doc.on("end", () => res(Buffer.concat(chunks))));

  // ── Header ──
  doc.rect(0, 0, doc.page.width, 90).fill(COLORS.brand);
  // Marca ◆ dibujada como rombo (Helvetica estándar no tiene el glifo U+25C6).
  doc.fill("#ffffff").save().translate(56, 43).rotate(45).rect(0, 0, 11, 11).fill("#ffffff").restore();
  doc.fill("#ffffff").fontSize(22).font("Helvetica-Bold").text("SYNTHEX EVIDENCE REPORT", 78, 32);
  doc.fontSize(9).font("Helvetica").text("The evidence layer that lives inside Bright Data", 50, 62);
  doc.fill("#000000").moveDown(3);

  // ── Resumen ──
  doc.fontSize(11).font("Helvetica-Bold").text("Subject");
  doc.font("Helvetica").fontSize(10).fillColor(COLORS.muted)
    .text(`Target:  ${Array.isArray(payload.target) ? payload.target.join(", ") : payload.target ?? "—"}`)
    .text(`Lens:    ${payload.lens ?? "—"}`)
    .text(`Fetched: ${payload.fetchedAt ?? "—"}`)
    .text(`Sealed:  ${sealedAt ?? "—"}`)
    .text(`Sources: ${(payload.sources ?? []).length}  ·  Blocked pre-LLM (FORGE): ${(payload.blocked ?? []).length}`)
    .fillColor("#000000").moveDown();

  // ── Findings ──
  doc.fontSize(11).font("Helvetica-Bold").text("Findings").moveDown(0.3);
  const findings = payload.findings ?? [];
  if (!findings.length) {
    doc.font("Helvetica").fontSize(10).fillColor(COLORS.muted).text("No findings (all content blocked or empty).").fillColor("#000000");
  }
  for (const f of findings) {
    for (const r of rowsOf(f)) {
      doc.font("Helvetica-Bold").fontSize(10).fillColor(sevColor(r.severity ?? 0))
        .text(`[${(r.lens ?? "").toUpperCase()}]  severity ${r.severity ?? 0}/10`, { continued: false });
      doc.font("Helvetica").fontSize(9).fillColor("#000000").text(r.summary ?? "");
      if (r.signals?.length) doc.fontSize(8).fillColor(COLORS.muted).text(`signals: ${r.signals.join(" · ")}`).fillColor("#000000");
      doc.fontSize(7).fillColor(COLORS.muted).text(r.url ?? "").fillColor("#000000").moveDown(0.4);
    }
  }
  doc.moveDown(0.5);

  // ── Chain of Custody ──
  doc.font("Helvetica-Bold").fontSize(11).text("Chain of Custody").moveDown(0.3);
  doc.font("Courier").fontSize(8).fillColor("#000000")
    .text(`SHA-256      : ${contentHash}`, { width: 380 })
    .text(`HMAC-SHA256  : ${seal.hmacSha256 ?? "—"}`, { width: 380 })
    .text(`Seal method  : ${seal.method ?? "—"}`);
  if (tsa) {
    doc.text(`RFC 3161 TSA : ${tsa.authority} (${tsa.standard})`)
      .text(`  genTime    : ${tsa.genTime ?? "—"}`)
      .text(`  serial     : ${tsa.serial ?? "—"}`);
  } else {
    doc.fillColor(COLORS.warn).text("RFC 3161 TSA : none (HMAC-only fallback — no network at seal time)").fillColor("#000000");
  }
  // QR a la derecha del bloque de custodia.
  try { doc.image(qrPng, doc.page.width - 50 - 110, doc.y - 70, { width: 110 }); } catch { /* layout best-effort */ }
  doc.moveDown();

  // ── Verify it yourself ──
  doc.font("Helvetica-Bold").fontSize(11).fillColor("#000000").text("Verify it yourself").moveDown(0.3);
  doc.font("Helvetica").fontSize(8).fillColor(COLORS.muted)
    .text("RFC 3161 proves WHEN this content was sealed — not that the content is TRUE. " +
          "The HMAC proves integrity against the issuing key. Reproduce the checks offline:").fillColor("#000000").moveDown(0.3);
  const cmd = tsa
    ? `# 1. Decode the trusted timestamp token shipped in the report JSON (seal.rfc3161Tsa.token):\n` +
      `echo "<base64-token>" | base64 -d > synthex.tsr\n` +
      `# 2. Inspect the DigiCert RFC 3161 reply (works offline):\n` +
      `openssl ts -reply -in synthex.tsr -text\n` +
      `# 3. Confirm the messageImprint equals this SHA-256:\n` +
      `#    ${contentHash}\n` +
      `# (full chain validation: openssl ts -verify -in synthex.tsr -CAfile digicert-chain.pem)`
    : `# HMAC-only report. Recompute the seal over the canonical payload:\n` +
      `#   HMAC-SHA256(JSON.stringify(payload), <key>) == ${seal.hmacSha256 ?? "—"}\n` +
      `#   SHA-256(JSON.stringify(payload))            == ${contentHash}`;
  doc.font("Courier").fontSize(7.5).fillColor("#111827").text(cmd, { width: doc.page.width - 100 });

  // ── Footer ──
  doc.fontSize(7).fillColor(COLORS.muted)
    .text("Generated by Apohara Synthex · everything signed, nothing trusted", 50, doc.page.height - 60, { align: "center", width: doc.page.width - 100 });

  doc.end();
  return done;
}
