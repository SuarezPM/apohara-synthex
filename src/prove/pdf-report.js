// PROVE/pdf-report — Evidence Report PDF orchestrator (the artefact a CISO/CFO/General Counsel/
// underwriter takes away). Thin by design: it registers the brand fonts once, builds the verify
// QR, fixes the page order, and runs the buffered footer pass. Every page body lives in its own
// src/prove/report/page-<name>.js module and consumes the shared theme + components. The design
// system is Option C (dark cover · light interior); the locked spec is
// docs/internal/EVIDENCE_REPORT_DESIGN.md.
//
// HONESTIDAD VERIFICABLE: cada número sale de los datos del evidence. El sello lidera Ed25519;
// HMAC-SHA256 es checksum interno, no el headline. El Risk Score (P5) es una estimación INTERNA
// con fórmula publicada — mapping, NOT endorsement.
import PDFDocument from "pdfkit";
import QRCode from "qrcode";
import { existsSync } from "node:fs";

import { THEME, FONTS, FONT_FILES, PAGE, reportIdOf } from "./report/theme.js";
import { drawFooters, makeFooterRegistry } from "./report/components.js";
import { pageExecutiveSummary } from "./report/page-executive-summary.js";
import { pageCISO } from "./report/page-ciso.js";
import { pageCFO } from "./report/page-cfo.js";
import { pageCounsel } from "./report/page-counsel.js";
import { pageBroker } from "./report/page-broker.js";
import { pageDelta } from "./report/page-delta.js";
import { pageVerify } from "./report/page-verify.js";

// Re-export the Risk Score API from its module so existing test imports
// (`from "../src/prove/pdf-report.js"`) keep working unchanged.
export { riskScore, riskScoreWeighted } from "./report/risk-score.js";

// Register the embedded brand TTFs once. If a TTF is missing, fall back to the PDFKit built-in so
// the report still renders (design spec §2) — flagged via the return value for the report.
function registerFonts(doc) {
  const fallbacks = {
    [FONTS.body]: "Helvetica", [FONTS.medium]: "Helvetica", [FONTS.semibold]: "Helvetica-Bold",
    [FONTS.bold]: "Helvetica-Bold", [FONTS.mono]: "Courier", [FONTS.monoBold]: "Courier-Bold",
    [FONTS.pixel]: "Courier",
  };
  const embedded = [];
  for (const [name, file] of Object.entries(FONT_FILES)) {
    if (existsSync(file)) {
      try { doc.registerFont(name, file); embedded.push(name); continue; } catch { /* fall through */ }
    }
    // Alias the role name to a built-in so doc.font(name) never throws downstream.
    try { doc.registerFont(name, fallbacks[name] ?? "Helvetica"); } catch { /* PDFKit knows built-ins */ }
  }
  return embedded;
}

/**
 * Genera el Evidence Report en PDF (Option C: cover dark + interior light). Page order is fixed:
 * cover · CISO · CFO · Counsel · Broker · [Delta when delta_chain] · Verify — exactly 6 pages
 * without a delta chain (7 with one), preserving back-compat with the page-count tests.
 * @param {object} evidence  salida de buildEvidence()/runPipeline() (con timings opcional).
 * @param {object} [opts]
 * @param {Map|null} [opts.epssMap]      EPSS map (render-time, non-sealed) for the Broker page.
 * @param {object|null} [opts.c2paSidecar]  C2PA sidecar — present-gates the C2PA seal row.
 * @param {object|null} [opts.rekorBundle]  Sigstore Rekor v2 bundle — present-gates the Rekor row.
 * @returns {Promise<Buffer>} bytes del PDF.
 */
export async function buildPDFReport(evidence, opts = {}) {
  const { payload = {}, contentHash, seal = {}, sealedAt } = evidence;
  const tsa = seal.rfc3161Tsa;
  const c2paSidecar = opts.c2paSidecar ?? null;
  const rekorBundle = opts.rekorBundle ?? null;
  const reportId = reportIdOf(contentHash);

  // QR de verificación (hash + sello + momento) — escaneás y verificás. Dark-on-white para la
  // cover blanca (estándar, escaneable e imprimible).
  const qrPayload = JSON.stringify({ hash: contentHash, method: seal.method, sealedAt, tsaSerial: tsa?.serial ?? null });
  const qrPng = await QRCode.toBuffer(qrPayload, {
    errorCorrectionLevel: "M", margin: 1, width: 140,
    color: { dark: THEME.PAPER.ink, light: "#FFFFFF" },
  });

  // bufferPages:true → footers en pasada final sin auto-paginado. autoFirstPage:false → control
  // explícito del orden de páginas (sin página fantasma inicial). Márgenes desde el theme.
  const doc = new PDFDocument({
    size: PAGE.size, margins: PAGE.margins, bufferPages: true, autoFirstPage: false,
    info: { Title: "Synthex Evidence Report", Author: "Apohara Synthex" },
  });
  registerFonts(doc);

  const chunks = [];
  doc.on("data", (c) => chunks.push(c));
  const done = new Promise((res) => doc.on("end", () => res(Buffer.concat(chunks))));

  const registry = makeFooterRegistry();
  const ctx = { reportId, registry, qrPng, c2paSidecar, rekorBundle, epssMap: opts.epssMap ?? null };

  doc.addPage(); pageExecutiveSummary(doc, evidence, ctx);
  doc.addPage(); pageCISO(doc, evidence, ctx);
  doc.addPage(); pageCFO(doc, evidence, ctx);
  doc.addPage(); pageCounsel(doc, evidence, ctx);
  doc.addPage(); pageBroker(doc, evidence, ctx);
  if (payload?.delta_chain) {
    doc.addPage(); pageDelta(doc, evidence, ctx);
  }
  doc.addPage(); pageVerify(doc, evidence, ctx);

  drawFooters(doc, { theme: THEME, registry });

  doc.end();
  return done;
}
