// PROVE/report/page-counsel — General Counsel · Compliance Trace (interior, light). Phase-2b
// redesign: a multi-framework COMPLIANCE MATRIX mapping THIS sealed audit trail to EU AI Act
// (Regulation (EU) 2024/1689) Art 11 / 12 / 13 and the four NIST AI RMF functions, each with a
// RAG status driven by the real evidence object + the article/function citation. Then the three
// cryptographic anchors the matrix rests on: tamper-evidence (Ed25519 + SHA-256 contentHash),
// independent timekeeping (RFC 3161 TSA), and the transparency anchor (Sigstore Rekor, present-
// gated). HONESTY: every mapping is "mapping, not endorsement / certification"; no body reviewed
// these. RAG status is computed from the evidence, never asserted.
import { PAPER, FONTS, PAGE } from "./theme.js";
import { pageOpen, sectionTitle, body } from "./interior.js";
import { frameworkMatrix, rekorLogIndex } from "./components.js";

export function pageCounsel(doc, ev, ctx = {}) {
  const { payload = {}, contentHash, seal = {}, sealedAt } = ev;
  const tsa = seal.rfc3161Tsa;
  const sig = seal.signature;
  const left = doc.page.margins.left;

  pageOpen(doc, {
    persona: "● Compliance Trace · for General Counsel",
    title: "The sealed log, mapped to the frameworks",
    reportId: ctx.reportId,
    registry: ctx.registry,
  });

  // ── Intro: what this page IS, in one honest paragraph ────────────────────────
  body(doc,
    "This report is itself an evidentiary record: an automatic, timestamped log of the data " +
    "lifecycle, sealed so any tampering is detectable. The matrix below maps that sealed log to " +
    "the relevant articles of the EU AI Act — Regulation (EU) 2024/1689 — and to the NIST AI RMF " +
    "functions. Each mapping is a good-faith aid, not an endorsement or certification; no framework " +
    "body has reviewed this report.");
  doc.moveDown(0.6);

  // ── EU AI Act matrix ─────────────────────────────────────────────────────────
  // Status is computed from the evidence, never asserted. Art 12 is the load-bearing claim:
  // the sealed audit trail IS the automatic, lifetime log the article requires — state it plainly.
  sectionTitle(doc, "EU AI Act — Regulation (EU) 2024/1689");

  const hasTrail = !!contentHash && !!seal.hmacSha256;
  const euRows = [
    {
      control: "Art 11 — Technical Documentation",
      status: (payload.decisions ?? []).length ? "green" : "amber",
      citation:
        "Defenses, model ids and pipeline stages are documented on the Model & Pipeline " +
        "Attestation page (Reg. (EU) 2024/1689, Annex IV scope).",
    },
    {
      control: "Art 12 — Record-Keeping (logging)",
      status: hasTrail ? "green" : "amber",
      citation:
        "Art 12 requires automatic logging over the system lifetime — this sealed, timestamped " +
        "audit trail IS that log: inputs, pre-filter blocks and classifier outputs, sealed.",
    },
    {
      control: "Art 13 — Transparency to Deployers",
      status: "green",
      citation:
        "The verdict, sources and seal stack are disclosed to the deployer; system prompts are " +
        "NOT exposed (Art 13 does not require it).",
    },
  ];
  frameworkMatrix(doc, { theme: PAPER, rows: euRows });
  doc.x = left;
  doc.moveDown(0.5);

  // ── NIST AI RMF matrix ───────────────────────────────────────────────────────
  sectionTitle(doc, "NIST AI RMF — GOVERN / MAP / MEASURE / MANAGE");

  const blockedAny = (payload.blocked ?? []).length > 0 ||
    (payload.decisions ?? []).some((d) => String(d.outcome).toUpperCase() === "BLOCK");
  const nistRows = [
    {
      control: "GOVERN",
      status: "amber",
      citation:
        "Sealing + record-keeping policy is encoded in the pipeline; organisational governance " +
        "is the deployer's responsibility (one signal of two).",
    },
    {
      control: "MAP",
      status: (payload.sources ?? []).length ? "green" : "amber",
      citation:
        `Context mapped: ${(payload.sources ?? []).length} source URL(s) and their surfaces are ` +
        "recorded in the sealed payload.",
    },
    {
      control: "MEASURE — MS-2.5",
      status: (payload.findings ?? []).length || blockedAny ? "green" : "amber",
      citation:
        "MS-2.5 (robustness): the 3-tier injection defense measures and records the catch on " +
        "every scraped document; see the Security Briefing page.",
    },
    {
      control: "MANAGE",
      status: "amber",
      citation:
        "Risks are surfaced and bounded (REVIEW/BLOCK) but residual-risk acceptance is a human " +
        "decision outside this record (one signal of two).",
    },
  ];
  frameworkMatrix(doc, { theme: PAPER, rows: nistRows });
  doc.x = left;
  doc.moveDown(0.6);

  // ── Cryptographic anchors the matrix rests on ────────────────────────────────
  sectionTitle(doc, "What anchors this record");

  // Tamper-evidence — Ed25519 over the canonical payload + the SHA-256 content hash.
  anchorRow(doc, {
    label: "Tamper-evidence",
    ok: !!sig || !!contentHash,
    detail: sig
      ? `Ed25519 signature (keyId ${sig.keyId ?? "—"}) over the canonical payload; SHA-256 content ` +
        `hash ${shortHash(contentHash)}. Any byte change breaks both.`
      : `SHA-256 content hash ${shortHash(contentHash)} + HMAC-SHA256 internal checksum. Any byte ` +
        "change breaks the hash.",
  });

  // Independent timekeeping — RFC 3161 TSA (third-party time, not our clock).
  anchorRow(doc, {
    label: "Independent timekeeping",
    ok: !!tsa,
    detail: tsa
      ? `RFC 3161 trusted timestamp from ${tsa.authority ?? "DigiCert"} at ${tsa.genTime ?? "—"} ` +
        `(serial ${shortSerial(tsa.serial)}). Proves WHEN — a third-party clock, not ours.`
      : "HMAC-only seal — no third-party time source was reached on this run. The 'when' is " +
        "self-asserted, not independently timestamped.",
  });

  // Transparency anchor — Sigstore Rekor v2 (present-gated; honest when absent).
  const logIndex = rekorLogIndex(ctx.rekorBundle);
  anchorRow(doc, {
    label: "Transparency anchor",
    ok: logIndex != null,
    detail: logIndex != null
      ? `Anchored in the public Sigstore Rekor v2 transparency log (logIndex ${logIndex}) — ` +
        "an append-only, independently auditable record of inclusion."
      : "Not anchored in a public transparency log on this run (optional). The seal and timestamp " +
        "above stand on their own.",
  });
  doc.x = left;
  doc.moveDown(0.6);

  // ── Honest disclaimer (the General Counsel line) ─────────────────────────────
  doc.x = left;
  doc.font(FONTS.body).fontSize(8.5).fillColor(PAPER.muted).text(
    "This is an evidentiary record and a framework-mapping aid — NOT legal advice and NOT a " +
    "certification. The seal proves WHEN these bytes existed and that they are unchanged, not that " +
    "the underlying claims are true. Identity is self-signed, not a public trust-list certificate. " +
    "Article applicability depends on whether the deploying system is classified high-risk under " +
    "Regulation (EU) 2024/1689. No framework body has reviewed or endorsed this report.",
    left, doc.y, { width: PAGE.textWidth, oblique: true });
  doc.fillColor(PAPER.ink).x = left;
}

// ── anchorRow: one cryptographic-anchor line — RAG glyph + label + wrapping detail ──
// Single-line label drawn lineBreak:false (manual step is unnecessary because the WRAPPING detail
// block below it advances doc.y honestly). We draw the glyph + label, then the detail as a real
// wrapping block whose final doc.y drives the next row — never stacking via a lineBreak:false read.
function anchorRow(doc, { label, ok, detail }) {
  const left = doc.page.margins.left;
  const y = doc.y;
  const color = ok ? PAPER.green : PAPER.amber;
  doc.font(FONTS.monoBold).fontSize(9).fillColor(color)
    .text(ok ? "✓ OK" : "▲ PARTIAL", left, y, { width: 70, lineBreak: false });
  doc.font(FONTS.semibold).fontSize(9.5).fillColor(PAPER.ink)
    .text(label, left + 76, y, { width: 150, lineBreak: false });
  // Wrapping block: its own doc.y advance is what we trust (PDFKit advances after a wrap).
  doc.font(FONTS.body).fontSize(8.5).fillColor(PAPER.muted)
    .text(detail, left + 232, y, { width: PAGE.textWidth - 232 });
  doc.fillColor(PAPER.ink).x = left;
  doc.moveDown(0.5);
}

const shortHash = (h) => {
  const s = String(h ?? "");
  return s ? `${s.slice(0, 16)}…${s.slice(-8)}` : "—";
};
const shortSerial = (s) => {
  const v = String(s ?? "");
  return v ? `${v.slice(0, 12)}…` : "—";
};
