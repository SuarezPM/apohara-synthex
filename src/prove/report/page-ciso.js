// PROVE/report/page-ciso — CISO Security Briefing (interior, light paper). Phase-2b rebuild on
// the PAPER design system + shared components. The page reads ONLY the sealed evidence object —
// every row is reconstructed from payload.decisions[], so a verifier could recompute it.
//
// What it shows, honestly:
//   1. the 3-tier injection-defense ledger (L1 regex REVIEW-only · L2 injection-guard opt-in ·
//      L3 alignment-check — the only BLOCK authority post-D5), each row LIVE/DEGRADED/DEMO STUB.
//   2. the L3 describing-vs-executing adjudication: the flagged content (executing → BLOCK) vs
//      the benign control (an OWASP doc that DESCRIBES injection → correctly ALLOW). This is the
//      false-positive killer — describing/teaching an attack is not executing it.
//   3. a per-signal MAPPING table to OWASP LLM Top 10 2025 + OWASP Agentic ASI + MITRE ATLAS +
//      NIST AI RMF, with the full/partial/none coverage legend (mapping, not endorsement).
//   4. a one-line STIX 2.1 export reference for SOC ingestion.
//
// PDFKit pitfall honored: single-line draws (lineBreak:false) STEP doc.y manually by a fixed
// amount; only wrapping blocks (body/table/codeBox) read doc.y afterwards. Tables NEVER overflow
// (the shared table()/mappingTable() measure → grow → paginate).
import { PAPER, FONTS, TYPE, PAGE } from "./theme.js";
import { pageOpen, sectionTitle, body } from "./interior.js";
import { truncMid, mappingTable, codeBox } from "./components.js";
import { guardLedger } from "./guard-ledger.js";

// Mode → RAG-ish accent for a ledger row. LIVE green · DEGRADED amber · DEMO STUB violet ·
// not-run muted. Color is paired with the literal mode text below (a11y: never color alone).
const modeColor = (m) =>
  m === "LIVE" ? PAPER.green
    : m.startsWith("DEGRADED") ? PAPER.amber
      : m.startsWith("DEMO") ? PAPER.violet
        : PAPER.muted;

// Per-signal framework mapping for an indirect prompt-injection caught in scraped HTML. EXACT
// citations from the verified research pack (OWASP LLM Top 10 2025 · OWASP Agentic ASI Top 10 ·
// MITRE ATLAS · NIST AI RMF · EU AI Act 2024/1689). Coverage uses the honest legend: full =
// pack-validated AND policy-covered · partial = one signal · none = none. Every mapping is an
// aid, NOT an endorsement — no body reviewed these.
const MAPPING_ROWS = [
  {
    signal: "Indirect prompt injection in scraped HTML (executing) — L3 BLOCK",
    framework: "OWASP LLM01:2025 Prompt Injection (Indirect)",
    coverage: "full",
  },
  {
    signal: "Agent instructed to exfiltrate secrets via a tool call",
    framework: "OWASP ASI01 Agent Goal Hijack · ASI02 Tool Misuse",
    coverage: "full",
  },
  {
    signal: "LLM-targeted injection technique (adversarial input)",
    framework: "MITRE ATLAS AML.T0051 LLM Prompt Injection",
    coverage: "full",
  },
];
// NIST AI RMF + EU AI Act compliance mapping lives on the General Counsel page (Compliance Trace);
// the CISO page focuses on the THREAT catalogs (OWASP LLM/Agentic + MITRE ATLAS).

export function pageCISO(doc, ev, ctx = {}) {
  const { payload = {} } = ev;
  const decisions = Array.isArray(payload.decisions) ? payload.decisions : [];
  const ledger = guardLedger(decisions);
  const l3 = decisions.filter((d) => d.stage === "ALIGNMENT_CHECK");

  pageOpen(doc, {
    persona: "● Security Briefing · for CISO",
    title: "Three layers screen what your agents ingest",
    reportId: ctx.reportId,
    registry: ctx.registry,
  });

  // ── 1. The 3-tier ledger ──────────────────────────────────────────────────────
  sectionTitle(doc, "Injection defense — 3 layers, from the sealed decision log");
  body(doc,
    "Reconstructed from the sealed decisions[]. L1 regex is REVIEW-only (it seals a signal, never drops a " +
    "doc); L2 is an opt-in detector; L3 AlignmentCheck holds the only BLOCK authority.");
  doc.moveDown(0.35);

  const lx = doc.page.margins.left;
  const ledgerTextW = PAGE.textWidth - 152;
  for (const led of ledger) {
    const rowY = doc.y;
    // mode badge + tier: single-line draws at the PINNED rowY (PDFKit advances doc.y after a
    // lineBreak:false draw, so never read doc.y between these — draw both at rowY).
    doc.font(FONTS.semibold).fontSize(9).fillColor(modeColor(led.mode))
      .text(led.mode, lx, rowY, { width: 148, lineBreak: false });
    doc.font(FONTS.semibold).fontSize(9).fillColor(PAPER.ink)
      .text(led.tier, lx + 152, rowY, { width: ledgerTextW, lineBreak: false });
    // detail wraps under the tier label; this is the only block that reads doc.y for height.
    const detailY = rowY + 12;
    doc.font(FONTS.body).fontSize(8).fillColor(PAPER.muted)
      .text(led.detail, lx + 152, detailY, { width: ledgerTextW, lineGap: 1 });
    doc.fillColor(PAPER.ink);
    // doc.y now sits below the wrapped detail; clear, fixed air before the next row so the
    // mode badge of the next tier can never collide with this detail.
    doc.y = Math.max(doc.y, detailY + 10) + 6;
    doc.x = lx;
  }
  doc.x = lx;

  // ── 2. L3 describing-vs-executing — catch + benign control ──────────────────────
  doc.moveDown(0.2);
  sectionTitle(doc, "L3 verdict — describing vs executing (the false-positive killer)");

  if (!l3.length) {
    body(doc,
      "No document entered the REVIEW band carrying an injection signal in this batch, so L3 had " +
      "nothing to adjudicate. Describing-vs-executing only runs on the bounded injection subset — " +
      "never in bulk.", PAPER.muted);
  } else {
    body(doc,
      "L3 answers one question — does the scraped text DESCRIBE an attack (documentation) or INSTRUCT " +
      "the reading agent to EXECUTE one? Executing is dropped before classify; describing is kept:");
    doc.moveDown(0.45);

    for (const r of l3) {
      const isBlock = r.outcome === "BLOCK";
      const accent = isBlock ? PAPER.red : PAPER.green;
      const glyph = isBlock ? "✗" : "✓";
      const tag = isBlock ? "EXECUTING → BLOCK (dropped before classify)" : "DESCRIBING → ALLOW (benign control, kept)";
      const modelId = String(r.model_id ?? "—");
      const liveTag = modelId.includes("(DEMO STUB)") ? "DEMO STUB" : (r.degraded ? "DEGRADED" : "LIVE");
      const modelClean = modelId.replace(/\s*\(DEMO STUB\)\s*/i, "").trim() || "—"; // liveTag already says it

      // verdict line — single line; the provenance below is drawn at a fixed offset.
      const y0 = doc.y;
      doc.font(FONTS.semibold).fontSize(9.5).fillColor(accent)
        .text(`${glyph} ${tag}`, lx, y0, { width: PAGE.textWidth, lineBreak: false });

      // url + verdict provenance — WRAPS (long line), so doc.y advances correctly after.
      const conf = r.confidence != null ? `conf ${r.confidence}` : "conf —";
      doc.font(FONTS.mono).fontSize(7.5).fillColor(PAPER.muted)
        .text(`${truncMid(r.url, 38, 14)}  ·  ${liveTag} · ${modelClean} · ${conf}`,
          lx, y0 + 16, { width: PAGE.textWidth, lineGap: 1.5 });

      // rationale (truncated for the seal) — wraps; read doc.y after.
      doc.moveDown(0.3);
      doc.font(FONTS.body).fontSize(8.5).fillColor(PAPER.ink)
        .text(truncMid(r.rationale, 160, 0), lx, doc.y, { width: PAGE.textWidth, lineGap: 2 });
      doc.fillColor(PAPER.ink);
      doc.moveDown(0.75);
      doc.x = lx;
    }
  }
  doc.x = lx;

  // ── 3. Per-signal framework mapping ─────────────────────────────────────────────
  doc.moveDown(0.2);
  sectionTitle(doc, "Signal → framework mapping (mapping aid, not endorsement)");
  body(doc,
    "An indirect injection caught in scraped HTML maps across the LLM/agentic threat catalogs. " +
    "No standards body reviewed these mappings — they are a good-faith aid for your control matrix.",
    PAPER.muted);
  doc.moveDown(0.4);
  mappingTable(doc, { theme: PAPER, rows: MAPPING_ROWS });
  doc.x = lx;

  // ── 4. STIX 2.1 export reference ────────────────────────────────────────────────
  sectionTitle(doc, "Hand this to your SOC — STIX 2.1 export");
  body(doc, "The sealed decision log exports as STIX 2.1 bundles (indicator SDOs) for your SIEM/TIP:", PAPER.muted);
  doc.moveDown(0.25);
  codeBox(doc, { theme: PAPER, lines: "synthex stix-export <evidence.json> > incident.stix.json" });
  doc.x = lx;
}
