// PROVE/pdf-report — Evidence Report como PDF descargable (el artefacto que un juez/CISO/CFO/
// General Counsel/broker se lleva). Consume el objeto de buildEvidence() + evidence.timings del
// pipeline y lo renderiza en 6 páginas con framing por comprador, incluyendo el comando REAL
// para que cualquiera verifique el timestamp por su cuenta. Implementa el patrón del IETF
// draft-marques-asqav-compliance-receipts (Mayo 2026): un "Compliance Receipt" firmado.
//
// HONESTIDAD VERIFICABLE: cada número de este reporte sale de los datos del evidence (dedup,
// timings, blocked, findings). El Risk Score (P5) es una estimación INTERNA de Synthex con
// fórmula publicada en la propia página — NO una calificación de un tercero ni de Munich Re.
import PDFDocument from "pdfkit";
import QRCode from "qrcode";
import { synthesizeOutput } from "./output.js";
import { cveIdsFromFinding, epssWeight } from "./epss.js";

const COLORS = { brand: "#5b21b6", ok: "#15803d", warn: "#b45309", crit: "#b91c1c", muted: "#6b7280", ink: "#111827", line: "#e5e7eb" };
const sevColor = (s) => (s >= 8 ? COLORS.crit : s >= 5 ? COLORS.warn : COLORS.ok);

// Mapa categoría del pre-filtro FORGE → OWASP (Top 10 LLM 2025 / Top 10 Web). Honesto: el
// pre-filtro es heurístico regex; esto solo etiqueta el vector con su clase OWASP de referencia.
const OWASP = {
  "prompt-injection": { code: "LLM01:2025", name: "Prompt Injection", sev: 9 },
  "secret-exfil": { code: "LLM02:2025", name: "Sensitive Information Disclosure", sev: 9 },
  "sqli": { code: "A03:2021", name: "Injection (SQLi)", sev: 8 },
  "xss": { code: "A03:2021", name: "Injection (XSS)", sev: 7 },
};
const owaspOf = (cat) => OWASP[cat] ?? { code: "—", name: cat ?? "uncategorized", sev: 8 };

// Normaliza un finding (plano o tri-lens) a filas {url, lens, severity, summary, signals}.
function rowsOf(finding) {
  if (finding.trilens) {
    return Object.entries(finding.trilens).map(([lens, c]) => ({ url: finding.url, lens, ...c }));
  }
  return [{ url: finding.url, lens: finding.lens, severity: finding.severity, summary: finding.summary, signals: finding.signals }];
}

// Aplana TODOS los findings del payload a filas, sin importar el shape.
function allRows(findings) {
  return findings.flatMap(rowsOf);
}

/**
 * Risk Score 0–100 — fórmula determinista, publicada y reproducible, ANCLADA en frameworks
 * públicos NOMBRADOS (mapping, NOT endorsement): el eje de severidad usa la escala 0–10 del
 * CVSS base score y las bandas se alinean a las severity ratings de CVSS (High ≥ 7.0); el
 * encuadre de cumplimiento se mapea a NIST AI RMF (Govern/Map/Measure/Manage) y a las categorías
 * de riesgo del EU AI Act. EPSS (exploit-prediction) queda documentado como input futuro de la
 * lente Security. NO es una evaluación de un tercero ni una calificación de suscripción (p.ej.
 * Munich Re), y ningún framework citado endosa el número — es un mapeo trazable, no una
 * certificación. Ver docs/compliance-mapping.md.
 *
 *   maxSev   = máxima severity entre findings (escala CVSS 0..10)  → 70% del peso
 *   blockTerm= min(blockedCount, 5) / 5 * 10  (0..10)              → 30% del peso
 *   score    = round( (maxSev*0.7 + blockTerm*0.3) * 10 )          → 0..100
 *
 * @returns {{score:number, band:string, maxSev:number, blocked:number}}
 */
export function riskScore(evidence) {
  const findings = evidence?.payload?.findings ?? [];
  const blocked = (evidence?.payload?.blocked ?? []).length;
  const sevs = allRows(findings).map((r) => Number(r.severity) || 0);
  const maxSev = sevs.length ? Math.max(...sevs) : 0;
  const blockTerm = (Math.min(blocked, 5) / 5) * 10;
  const score = Math.round((maxSev * 0.7 + blockTerm * 0.3) * 10);
  const band = score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW";
  return { score, band, maxSev, blocked };
}

/**
 * EPSS-weighted Risk Score — ADDITIVE, render-time, NON-SEALED enrichment (item R1). The base
 * riskScore() above is the single source of truth and is UNCHANGED; this layers an OPTIONAL EPSS
 * multiplier on the severity term when the maxSev finding's text names a CVE present in `epssMap`.
 * With a null/empty map (or no CVE match) it returns the base result with `weighted:false` — a
 * no-op equal to today's behavior. EPSS changes daily and is NEVER sealed (see src/prove/epss.js).
 * @param {object} evidence
 * @param {Map<string,{epss:number}>|null} epssMap
 * @returns {{score:number, band:string, maxSev:number, blocked:number, weighted:boolean,
 *            weightedScore?:number, weightedBand?:string, weightedMaxSev?:number, epss?:number, cve?:string}}
 */
export function riskScoreWeighted(evidence, epssMap) {
  const base = riskScore(evidence);
  if (!(epssMap instanceof Map) || epssMap.size === 0) return { ...base, weighted: false };
  const rows = allRows(evidence?.payload?.findings ?? []);
  // The maxSev band drives the base score; weight by the CVEs of ALL findings tied at maxSev
  // (not just the first) so the most-exploitable CVE wins per the epss.js contract.
  const topCves = rows
    .filter((r) => (Number(r.severity) || 0) === base.maxSev)
    .flatMap((r) => cveIdsFromFinding(r));
  const { factor, epss, cve } = epssWeight(epssMap, topCves);
  if (epss === null) return { ...base, weighted: false }; // maxSev finding names no in-map CVE
  const weightedMaxSev = Math.min(10, base.maxSev * factor);
  const blockTerm = (Math.min(base.blocked, 5) / 5) * 10;
  const weightedScore = Math.round((weightedMaxSev * 0.7 + blockTerm * 0.3) * 10);
  const weightedBand = weightedScore >= 70 ? "HIGH" : weightedScore >= 40 ? "MEDIUM" : "LOW";
  return { ...base, weighted: true, weightedScore, weightedBand, weightedMaxSev, epss, cve };
}

// ── helpers de layout ──────────────────────────────────────────────────────
// Marca ◆ dibujada como rombo (Helvetica estándar no tiene el glifo U+25C6).
function diamond(doc, x, y, size, color) {
  doc.save().translate(x, y).rotate(45).rect(0, 0, size, size).fill(color).restore();
}

// Cabecera estándar de cada página: banda de marca + título de sección + audiencia.
function pageHeader(doc, section, audience) {
  doc.rect(0, 0, doc.page.width, 84).fill(COLORS.brand);
  diamond(doc, 56, 40, 11, "#ffffff");
  doc.fill("#ffffff").fontSize(18).font("Helvetica-Bold").text("SYNTHEX EVIDENCE REPORT", 78, 28);
  doc.fontSize(9).font("Helvetica").fillColor("#ddd6fe").text(`${section}  ·  for ${audience}`, 78, 52);
  doc.fillColor(COLORS.ink);
  doc.x = doc.page.margins.left;
  doc.y = 110;
}

// Footer escrito en pasada final sobre páginas bufferizadas (bufferPages:true), de modo que
// dibujar dentro del margen inferior NO dispare el auto-paginado de PDFKit (continueOnNewPage).
function drawFooters(doc, total) {
  for (let i = 0; i < total; i++) {
    doc.switchToPage(i);
    // PDFKit auto-pagina si se escribe por debajo de maxY()=height-margins.bottom. Anulamos el
    // margen inferior de la página solo para estampar el footer al pie sin disparar nueva página.
    doc.page.margins.bottom = 0;
    doc.fontSize(7).fillColor(COLORS.muted).font("Helvetica")
      .text(`Apohara Synthex · everything signed, nothing trusted · page ${i + 1} of ${total}`,
        50, doc.page.height - 36, { align: "center", width: doc.page.width - 100, lineBreak: false });
  }
}

function sectionTitle(doc, text) {
  doc.font("Helvetica-Bold").fontSize(14).fillColor(COLORS.ink).text(text);
  doc.moveTo(doc.page.margins.left, doc.y + 2).lineTo(doc.page.width - doc.page.margins.right, doc.y + 2)
    .strokeColor(COLORS.line).lineWidth(1).stroke();
  doc.moveDown(0.8);
}

function kv(doc, label, value, valueColor) {
  const x = doc.page.margins.left;
  doc.font("Helvetica-Bold").fontSize(10).fillColor(COLORS.muted).text(label, x, doc.y, { continued: true, width: 160 });
  doc.font("Helvetica").fillColor(valueColor ?? COLORS.ink).text(`  ${value}`);
}

// ── páginas ──────────────────────────────────────────────────────────────
function pageExecutiveSummary(doc, ev, qrPng) {
  const { payload = {}, contentHash, seal = {}, sealedAt } = ev;
  const tsa = seal.rfc3161Tsa;
  pageHeader(doc, "Executive Summary", "Decision makers");
  sectionTitle(doc, "What this report proves");

  doc.font("Helvetica").fontSize(10).fillColor(COLORS.ink).text(
    "Synthex turned web data into court-grade evidence: every source was fetched, screened for " +
    "malicious content before reaching the LLM, classified, and cryptographically sealed. " +
    "The seal proves WHEN and that the bytes are UNCHANGED — not that the underlying claims are true.",
    { width: doc.page.width - 100 }).moveDown(0.8);

  kv(doc, "Target", Array.isArray(payload.target) ? payload.target.join(", ") : (payload.target ?? "—"));
  kv(doc, "Lens", payload.lens ?? "—");
  kv(doc, "Fetched", payload.fetchedAt ?? "—");
  kv(doc, "Sealed", sealedAt ?? "—");
  kv(doc, "Sources", String((payload.sources ?? []).length));
  kv(doc, "Blocked pre-LLM (FORGE)", String((payload.blocked ?? []).length), (payload.blocked ?? []).length ? COLORS.warn : COLORS.ok);
  doc.moveDown(0.8);

  sectionTitle(doc, "Cryptographic seal");
  doc.font("Courier").fontSize(8.5).fillColor(COLORS.ink)
    .text(`SHA-256      : ${contentHash}`, { width: 360 })
    .text(`HMAC-SHA256  : ${seal.hmacSha256 ?? "—"}`, { width: 360 })
    .text(`Seal method  : ${seal.method ?? "—"}`);
  if (tsa) {
    doc.text(`RFC 3161 TSA : ${tsa.authority ?? "DigiCert"} (${tsa.standard})`)
      .text(`  genTime    : ${tsa.genTime ?? "—"}`)
      .text(`  serial     : ${tsa.serial ?? "—"}`);
  } else {
    doc.fillColor(COLORS.warn).text("RFC 3161 TSA : none (HMAC-only — no network at seal time)").fillColor(COLORS.ink);
  }
  // QR de verificación a la derecha del bloque del sello.
  try { doc.image(qrPng, doc.page.width - 50 - 118, doc.y - 92, { width: 118 }); } catch { /* layout best-effort */ }
  doc.moveDown(2);

  doc.font("Helvetica-Oblique").fontSize(8).fillColor(COLORS.muted).text(
    "Scan the QR or follow page 6 to verify this seal yourself, offline, with OpenSSL.",
    { width: doc.page.width - 100 });
}

function pageCISO(doc, ev) {
  const { payload = {} } = ev;
  const blocked = payload.blocked ?? [];
  pageHeader(doc, "Security Briefing", "CISO");
  sectionTitle(doc, "Threats blocked by FORGE (pre-LLM)");

  doc.font("Helvetica").fontSize(10).fillColor(COLORS.ink).text(
    "FORGE is a deterministic regex pre-filter that runs BEFORE any LLM call. It blocks injection " +
    "and exfiltration vectors so they never reach (or poison) the model. Categories are mapped to " +
    "their OWASP reference class. The pre-filter is heuristic, not formally verified.",
    { width: doc.page.width - 100 }).moveDown(0.8);

  if (!blocked.length) {
    doc.font("Helvetica-Bold").fontSize(11).fillColor(COLORS.ok).text("No malicious content detected in this batch.").fillColor(COLORS.ink);
    doc.font("Helvetica").fontSize(9).fillColor(COLORS.muted).moveDown(0.4)
      .text("All fetched sources passed the FORGE pre-filter and were forwarded to classification.");
  } else {
    // Cabecera de tabla.
    const x = doc.page.margins.left;
    doc.font("Helvetica-Bold").fontSize(9).fillColor(COLORS.muted);
    doc.text("OWASP", x, doc.y, { continued: true, width: 90 });
    doc.text("CATEGORY", { continued: true, width: 230 });
    doc.text("SEVERITY", { continued: false });
    doc.moveTo(x, doc.y + 1).lineTo(doc.page.width - doc.page.margins.right, doc.y + 1).strokeColor(COLORS.line).stroke();
    doc.moveDown(0.4);

    for (const b of blocked) {
      const o = owaspOf(b.reason);
      doc.font("Helvetica-Bold").fontSize(9).fillColor(COLORS.ink).text(o.code, x, doc.y, { continued: true, width: 90 });
      doc.font("Helvetica").text(o.name, { continued: true, width: 230 });
      doc.font("Helvetica-Bold").fillColor(sevColor(o.sev)).text(`${o.sev}/10  BLOCKED`, { continued: false });
      doc.fillColor(COLORS.muted).font("Helvetica").fontSize(7.5).text(b.url ?? "—").fillColor(COLORS.ink).moveDown(0.4);
    }
  }

  doc.moveDown(0.6);
  sectionTitle(doc, "Classification severity (per lens)");
  const rows = allRows(payload.findings ?? []);
  if (!rows.length) {
    doc.font("Helvetica").fontSize(9).fillColor(COLORS.muted).text("No findings classified.").fillColor(COLORS.ink);
  }
  for (const r of rows) {
    doc.font("Helvetica-Bold").fontSize(9.5).fillColor(sevColor(r.severity ?? 0))
      .text(`[${String(r.lens ?? "").toUpperCase()}]  severity ${r.severity ?? 0}/10`);
    doc.font("Helvetica").fontSize(9).fillColor(COLORS.ink).text(r.summary ?? "");
    if (r.signals?.length) doc.fontSize(7.5).fillColor(COLORS.muted).text(`signals: ${r.signals.join(" · ")}`).fillColor(COLORS.ink);
    doc.moveDown(0.4);
  }
}

function pageCFO(doc, ev) {
  const { payload = {} } = ev;
  const dedup = payload.dedup ?? null;
  const timings = ev.timings ?? null;
  pageHeader(doc, "Cost & Efficiency", "CFO");
  sectionTitle(doc, "Token cost saved (deduplication)");

  doc.font("Helvetica").fontSize(9.5).fillColor(COLORS.ink).text(
    "FORGE deduplicates fetched documents by full SHA-256 before classification: every duplicate " +
    "block removed is one fewer LLM call paid for. The ratio below is exact (not estimated).",
    { width: doc.page.width - 100 }).moveDown(0.6);

  if (dedup) {
    const pct = (dedup.dedupRatio * 100).toFixed(1);
    kv(doc, "Unique blocks", String(dedup.uniqueBlocks ?? "—"));
    kv(doc, "Duplicate blocks", String(dedup.duplicateBlocks ?? 0), (dedup.duplicateBlocks ?? 0) ? COLORS.ok : COLORS.muted);
    kv(doc, "Dedup ratio", `${pct}%  (LLM calls avoided)`, (dedup.duplicateBlocks ?? 0) ? COLORS.ok : COLORS.muted);
    kv(doc, "Bytes saved", `${(dedup.bytesSaved ?? 0).toLocaleString()} bytes not sent to the model`);
  } else {
    doc.font("Helvetica").fontSize(9).fillColor(COLORS.muted)
      .text("Dedup stats not present in this evidence object (no FORGE pass recorded).").fillColor(COLORS.ink);
  }

  doc.moveDown(0.6);
  sectionTitle(doc, "Latency per stage (wall-clock)");
  doc.font("Helvetica").fontSize(9).fillColor(COLORS.muted).text(
    "Measured by the pipeline (evidence.timings), outside the sealed payload so it never affects " +
    "verification.", { width: doc.page.width - 100 }).fillColor(COLORS.ink).moveDown(0.5);

  if (timings && Object.keys(timings).length) {
    const x = doc.page.margins.left;
    const entries = Object.entries(timings);
    const maxMs = Math.max(...entries.map(([, v]) => Number(v) || 0), 1);
    const barW = 240;
    for (const [stage, ms] of entries) {
      const v = Number(ms) || 0;
      doc.font("Helvetica-Bold").fontSize(9).fillColor(COLORS.ink).text(stage, x, doc.y, { continued: false, width: 80 });
      const barY = doc.y - 11;
      const w = Math.max(2, (v / maxMs) * barW);
      doc.rect(x + 90, barY, barW, 9).fill(COLORS.line);
      doc.rect(x + 90, barY, w, 9).fill(COLORS.brand);
      doc.fillColor(COLORS.ink).font("Helvetica").fontSize(8.5).text(`${v} ms`, x + 90 + barW + 8, barY);
      doc.moveDown(0.5);
    }
    const total = entries.reduce((a, [, v]) => a + (Number(v) || 0), 0).toFixed(1);
    doc.moveDown(0.4).font("Helvetica-Bold").fontSize(9).fillColor(COLORS.ink).text(`Total: ${total} ms`);
  } else {
    doc.font("Helvetica").fontSize(9).fillColor(COLORS.muted)
      .text("No per-stage timings present in this evidence object.").fillColor(COLORS.ink);
  }
}

function pageCounsel(doc, ev) {
  const { payload = {}, contentHash, seal = {}, sealedAt } = ev;
  const tsa = seal.rfc3161Tsa;
  pageHeader(doc, "Compliance Trace", "General Counsel");
  sectionTitle(doc, "EU AI Act — Article 12 (record-keeping / logging)");

  doc.font("Helvetica").fontSize(9.5).fillColor(COLORS.ink).text(
    "Article 12 requires high-risk AI systems to automatically record events ('logs') enabling " +
    "traceability. This report is itself such a record: an immutable, timestamped log of the data " +
    "lifecycle, sealed so any tampering is detectable.",
    { width: doc.page.width - 100 }).moveDown(0.6);

  const trace = [
    ["Traceability of inputs", `${(payload.sources ?? []).length} source URL(s) recorded`, true],
    ["Pre-processing log", `${(payload.blocked ?? []).length} block(s) by FORGE pre-filter, with category`, true],
    ["Classification output", `${(payload.findings ?? []).length} finding record(s) retained`, (payload.findings ?? []).length > 0],
    ["Integrity of records", `HMAC-SHA256 over canonical payload (${seal.hmacSha256 ? "present" : "absent"})`, !!seal.hmacSha256],
    ["Timekeeping (independent)", tsa ? `RFC 3161 TSA — ${tsa.authority ?? "DigiCert"}, ${tsa.genTime ?? "—"}` : "HMAC-only (no third-party time source)", !!tsa],
    ["Tamper-evidence", `SHA-256 content hash: ${(contentHash ?? "").slice(0, 24)}…`, !!contentHash],
    ["Record timestamp", sealedAt ?? "—", !!sealedAt],
  ];

  // Columnas posicionadas en X fija (sin continued+width estrecho, que en PDFKit dispara
  // saltos de página espurios al recalcular el wrap de la cadena continuada).
  const cx = doc.page.margins.left;
  for (const [req, detail, ok] of trace) {
    const rowY = doc.y;
    doc.font("Helvetica-Bold").fontSize(10).fillColor(ok ? COLORS.ok : COLORS.warn)
      .text(ok ? "OK" : "!!", cx, rowY, { lineBreak: false });
    doc.fillColor(COLORS.ink).text(req, cx + 26, rowY, { width: 168, lineBreak: false });
    doc.font("Helvetica").fillColor(COLORS.muted).fontSize(9)
      .text(detail, cx + 198, rowY, { width: doc.page.width - 100 - 198 });
    doc.fillColor(COLORS.ink).moveDown(0.4);
  }

  doc.moveDown(0.5);
  doc.font("Helvetica-Oblique").fontSize(8).fillColor(COLORS.muted).text(
    "This is an evidentiary record, not legal advice. Mapping to Article 12 is provided as a " +
    "good-faith aid; applicability depends on whether the deploying system is classified high-risk.",
    { width: doc.page.width - 100 }).fillColor(COLORS.ink);
}

function pageBroker(doc, ev, epssMap = null) {
  const { payload = {} } = ev;
  const r = riskScore(ev);
  pageHeader(doc, "Risk Snapshot", "Broker / Underwriter");
  sectionTitle(doc, "Synthex Risk Score (CVSS 0–10 severity scale · NIST AI RMF / EU AI Act framing · mapping, not endorsement)");

  // Gauge numérico grande, coloreado por banda.
  const x = doc.page.margins.left;
  const bandColor = r.band === "HIGH" ? COLORS.crit : r.band === "MEDIUM" ? COLORS.warn : COLORS.ok;
  doc.font("Helvetica-Bold").fontSize(64).fillColor(bandColor).text(String(r.score), x, doc.y);
  const numBottom = doc.y;
  doc.font("Helvetica").fontSize(12).fillColor(COLORS.muted).text("/ 100", x + 96, numBottom - 30);
  doc.font("Helvetica-Bold").fontSize(16).fillColor(bandColor).text(`${r.band} RISK`, x + 96, numBottom - 12);
  doc.fillColor(COLORS.ink).moveDown(0.6);

  // Barra de progreso 0..100.
  const barY = doc.y;
  const barW = doc.page.width - 100;
  doc.rect(x, barY, barW, 10).fill(COLORS.line);
  doc.rect(x, barY, (r.score / 100) * barW, 10).fill(bandColor);
  doc.fillColor(COLORS.ink).y = barY + 22;

  sectionTitle(doc, "How this number is computed (honest formula)");
  doc.font("Courier").fontSize(8.5).fillColor(COLORS.ink).text(
    "maxSev    = max severity across all findings .......... " + `${r.maxSev}/10\n` +
    "blockTerm = min(blockedCount, 5) / 5 * 10 ............. " + `${((Math.min(r.blocked, 5) / 5) * 10).toFixed(1)}/10  (blocked=${r.blocked})\n` +
    "score     = round( (maxSev*0.70 + blockTerm*0.30) * 10 ) = " + `${r.score}`,
    { width: doc.page.width - 100 }).moveDown(0.8);

  // EPSS enrichment (R1) — OPT-IN, NON-SEALED, render-time only. Printed ONLY when an epssMap is
  // supplied AND the top finding names a CVE present in it. Never alters the sealed score above.
  const w = epssMap ? riskScoreWeighted(ev, epssMap) : null;
  if (w && w.weighted) {
    doc.font("Courier").fontSize(8.5).fillColor(COLORS.muted).text(
      `EPSS enrichment (FIRST.org · non-sealed · mapping, not endorsement):\n` +
      `  ${w.cve}  epss=${w.epss.toFixed(3)}  ->  severity term x${(1 + 0.3 * w.epss).toFixed(3)}  ->  weighted score ${w.weightedScore}/100 (${w.weightedBand})`,
      { width: doc.page.width - 100 },
    ).fillColor(COLORS.ink).moveDown(0.6);
  }

  // Disclaimer EXPLÍCITO (requisito de honestidad).
  doc.rect(x, doc.y, doc.page.width - 100, 64).fill("#fef3c7");
  doc.fillColor("#92400e").font("Helvetica-Bold").fontSize(9).text("DISCLAIMER", x + 10, doc.y + 8, { width: doc.page.width - 120 });
  doc.font("Helvetica").fontSize(8.5).text(
    "This Risk Score is computed by Synthex from the data in this report using the deterministic " +
    "formula shown above. Its severity axis is the CVSS 0–10 base-score scale and its bands align " +
    "to CVSS severity ratings; the compliance framing maps to NIST AI RMF and EU AI Act risk " +
    "categories. This is a MAPPING, NOT an ENDORSEMENT: it is NOT a Munich Re assessment, NOT an " +
    "insurance rating, and NOT underwriting advice. No third party or framework body has reviewed " +
    "or endorsed this number. See docs/compliance-mapping.md.",
    x + 10, doc.y + 2, { width: doc.page.width - 120 });
  doc.fillColor(COLORS.ink).y += 8;

  // 2.6 — closing synthesis: the one-line verdict + the 3 questions this evidence raises.
  // Read from the sealed payload when present; recompute deterministically for legacy reports.
  const out = (ev.payload?.verdict && Array.isArray(ev.payload?.questions))
    ? { verdict: ev.payload.verdict, questions: ev.payload.questions }
    : synthesizeOutput(ev.payload ?? {});
  doc.moveDown(0.8);
  sectionTitle(doc, "Verdict");
  doc.font("Helvetica-Bold").fontSize(11).fillColor(bandColor).text(out.verdict, { width: doc.page.width - 100 });
  doc.fillColor(COLORS.ink).moveDown(0.6);
  sectionTitle(doc, "3 questions this evidence raises");
  doc.font("Helvetica").fontSize(10).fillColor(COLORS.ink);
  out.questions.slice(0, 3).forEach((q, i) => {
    doc.text(`${i + 1}.  ${q}`, { width: doc.page.width - 100 }).moveDown(0.25);
  });
}

function pageDelta(doc, ev) {
  const { payload = {} } = ev;
  const dc = payload.delta_chain ?? {};
  pageHeader(doc, "Delta Evidence Chain", "Watch & Prove");

  sectionTitle(doc, "TSA chain (RFC 3161)");
  doc.font("Helvetica").fontSize(10).fillColor(COLORS.ink).text(
    "Each scrape of the same target is sealed with an independent DigiCert RFC 3161 " +
    "timestamp. The chain below proves both readings existed at the times shown — neither " +
    "can be back-dated without breaking the cryptographic chain.",
    { width: doc.page.width - 100 }).moveDown(0.6);

  const prev = dc.previous_tsa_serial ?? null;
  const curr = dc.current_tsa_serial ?? null;
  doc.font("Courier").fontSize(9).fillColor(COLORS.ink);
  doc.text(`previous_tsa_serial : ${prev ?? "— (cold start — first reading)"}`);
  doc.text(`current_tsa_serial  : ${curr ?? "— (TSA unavailable this run)"}`);
  doc.moveDown(0.6);

  sectionTitle(doc, "Diff summary");
  const ds = dc.diff_summary ?? { added: 0, removed: 0, changed: 0 };
  const tableY = doc.y;
  const cx = doc.page.margins.left;
  // Mini-tabla 3 columnas.
  const cells = [
    { label: "ADDED", value: ds.added ?? 0, color: COLORS.ok },
    { label: "REMOVED", value: ds.removed ?? 0, color: COLORS.crit },
    { label: "CHANGED", value: ds.changed ?? 0, color: COLORS.warn },
  ];
  const cellW = (doc.page.width - 100) / 3;
  for (let i = 0; i < cells.length; i++) {
    const c = cells[i];
    const x = cx + i * cellW;
    doc.rect(x + 4, tableY, cellW - 8, 56).fill("#f9fafb");
    doc.font("Helvetica-Bold").fontSize(9).fillColor(COLORS.muted).text(c.label, x + 12, tableY + 8, { width: cellW - 24 });
    doc.font("Helvetica-Bold").fontSize(28).fillColor(c.color).text(String(c.value), x + 12, tableY + 22, { width: cellW - 24 });
    doc.fillColor(COLORS.ink);
  }
  doc.y = tableY + 64;
  doc.moveDown(0.8);

  sectionTitle(doc, "Knowledge graph status (Cognee)");
  const kgStatus = dc.kg_status ?? "skipped";
  const kgColor = kgStatus === "ingested" ? COLORS.ok : kgStatus === "unreachable" ? COLORS.warn : COLORS.muted;
  doc.font("Helvetica-Bold").fontSize(10).fillColor(kgColor).text(`status: ${kgStatus.toUpperCase()}`);
  if (dc.kg_skip_reason) {
    doc.font("Helvetica").fontSize(9).fillColor(COLORS.muted).text(`reason: ${dc.kg_skip_reason}`);
  }
  doc.fillColor(COLORS.ink).moveDown(0.6);

  doc.font("Helvetica-Oblique").fontSize(8).fillColor(COLORS.muted).text(
    "What this proves: the bytes of the target changed between the two timestamps shown. " +
    "What this does NOT prove: the truthfulness of either reading. Both snapshots are sealed " +
    "with HMAC-SHA256 + RFC 3161 — verify with bin/decode-evidence.js.",
    { width: doc.page.width - 100 }).fillColor(COLORS.ink);
}

function pageVerify(doc, ev) {
  const { contentHash, seal = {} } = ev;
  const tsa = seal.rfc3161Tsa;
  pageHeader(doc, "Verify It Yourself", "Anyone");
  sectionTitle(doc, "Reproduce the proof offline");

  doc.font("Helvetica").fontSize(10).fillColor(COLORS.ink).text(
    "RFC 3161 proves WHEN this content was sealed — not that the content is TRUE. The HMAC proves " +
    "integrity against the issuing key. Reproduce the checks yourself with OpenSSL:",
    { width: doc.page.width - 100 }).moveDown(0.6);

  const cmd = tsa
    ? `# 1. Decode the trusted timestamp token shipped in the report JSON (seal.rfc3161Tsa.token):\n` +
      `echo "<base64-token>" | base64 -d > synthex.tsr\n\n` +
      `# 2. Inspect the DigiCert RFC 3161 reply (works offline):\n` +
      `openssl ts -reply -in synthex.tsr -text\n\n` +
      `# 3. Confirm the messageImprint in that output equals this SHA-256:\n` +
      `#    ${contentHash}\n\n` +
      `# 4. Full chain validation (needs the DigiCert CA chain):\n` +
      `openssl ts -verify -in synthex.tsr -CAfile digicert-chain.pem -sha256`
    : `# HMAC-only report (no network at seal time). Recompute the seal over the canonical payload:\n` +
      `#   HMAC-SHA256(JSON.stringify(payload), <key>) == ${seal.hmacSha256 ?? "—"}\n` +
      `#   SHA-256(JSON.stringify(payload))            == ${contentHash}\n\n` +
      `# With the key in $KEY and payload.json on disk:\n` +
      `openssl dgst -sha256 -hmac "$KEY" payload.json\n` +
      `openssl dgst -sha256 payload.json`;

  doc.rect(doc.page.margins.left, doc.y, doc.page.width - 100, tsa ? 200 : 150).fill("#0f172a");
  doc.fillColor("#e2e8f0").font("Courier").fontSize(8).text(cmd, doc.page.margins.left + 12, doc.y + 10, { width: doc.page.width - 124 });
  doc.fillColor(COLORS.ink).moveDown(2);

  sectionTitle(doc, "The SHA-256 you must match");
  doc.font("Courier").fontSize(10).fillColor(COLORS.brand).text(contentHash ?? "—", { width: doc.page.width - 100 });
  doc.fillColor(COLORS.ink);
}

/**
 * Genera el Evidence Report en PDF de 6 páginas (framing 4-buyer + verify).
 * @param {object} evidence  salida de buildEvidence()/runPipeline() (con timings opcional).
 * @returns {Promise<Buffer>} bytes del PDF.
 */
export async function buildPDFReport(evidence, opts = {}) {
  const { payload = {}, contentHash, seal = {}, sealedAt } = evidence;
  const tsa = seal.rfc3161Tsa;

  // QR con los datos de verificación (hash + sello + momento) — escaneás y verificás.
  const qrPayload = JSON.stringify({ hash: contentHash, method: seal.method, sealedAt, tsaSerial: tsa?.serial ?? null });
  const qrPng = await QRCode.toBuffer(qrPayload, { errorCorrectionLevel: "M", margin: 1, width: 140 });

  // bufferPages:true permite escribir los footers al final sin que PDFKit auto-pagine.
  // autoFirstPage:false → controlamos las 6 páginas explícitamente (sin página fantasma inicial).
  // margins: top 50 (la banda de marca vive arriba); bottom 30 deja holgura para que las páginas
  // densas (CFO/Counsel) quepan en una sola página sin que PDFKit auto-pagine. El footer se
  // estampa aparte (drawFooters) anulando el margen inferior, así que no compite por ese espacio.
  const doc = new PDFDocument({ size: "A4", margins: { top: 50, bottom: 30, left: 50, right: 50 },
    bufferPages: true, autoFirstPage: false,
    info: { Title: "Synthex Evidence Report", Author: "Apohara Synthex" } });
  const chunks = [];
  doc.on("data", (c) => chunks.push(c));
  const done = new Promise((res) => doc.on("end", () => res(Buffer.concat(chunks))));

  // 6 páginas base + 1 página opcional Delta (cuando hay delta_chain v0.6.0+).
  // Reports v0.5.0 sin delta_chain → 6 páginas (back-compat 100%).
  doc.addPage(); pageExecutiveSummary(doc, evidence, qrPng);
  doc.addPage(); pageCISO(doc, evidence);
  doc.addPage(); pageCFO(doc, evidence);
  doc.addPage(); pageCounsel(doc, evidence);
  doc.addPage(); pageBroker(doc, evidence, opts.epssMap ?? null);
  if (evidence?.payload?.delta_chain) {
    doc.addPage(); pageDelta(doc, evidence);
  }
  doc.addPage(); pageVerify(doc, evidence);

  drawFooters(doc, doc.bufferedPageRange().count);

  doc.end();
  return done;
}
