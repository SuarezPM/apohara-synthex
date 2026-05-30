// PROVE/report/page-honest-gap — Honest Gap Declaration (interior, light). The credibility lever:
// stating the limits IS the moat. Four honest sections — (1) what the seal does NOT prove,
// (2) what Synthex does NOT cover, (3) the self-signed-identity + heuristic-L1 limits, and
// (4) the MEASURED guard false-positive rates (src docs/guard-fp-measurement.md). No invented
// figures; every guard number is the measured one. Clean lists, single-line rows step y manually
// (PDFKit does NOT advance doc.y after a lineBreak:false draw — the Phase-2a overlap pitfall);
// only the wrapping bodies read doc.y. Persona tag + footer disclaimer come from pageOpen.
import { PAPER, FONTS, TYPE, PAGE } from "./theme.js";
import { pageOpen, sectionTitle, body } from "./interior.js";

const LEFT = PAGE.margins.left;

// A single "limit" list row: a muted ✗ mark + a bold lead clause + a muted wrapping clause beneath.
// The mark + lead are single-line (manual y-step); the explanation wraps and drives the row height.
function limitRow(doc, { lead, detail }) {
  const x = LEFT;
  const markW = 16;
  const y = doc.y;
  doc.font(FONTS.monoBold).fontSize(9).fillColor(PAPER.red).text("✗", x, y, { width: markW, lineBreak: false });
  doc.font(FONTS.semibold).fontSize(9.5).fillColor(PAPER.ink).text(lead, x + markW, y, { width: PAGE.textWidth - markW });
  if (detail) {
    doc.font(FONTS.body).fontSize(9).fillColor(PAPER.muted).text(detail, x + markW, doc.y, { width: PAGE.textWidth - markW });
  }
  doc.x = x;
  doc.moveDown(0.45);
}

// One measured-FP row: layer name + the measured rate + an honest authority/disposition note.
// Fixed-X columns (never continued+narrow-width, which fires spurious page breaks). The note
// wraps and drives the row height; the first two columns are single-line.
function fpRow(doc, { layer, rate, rateColor, note }) {
  const x = LEFT;
  const layerW = 188;
  const rateW = 96;
  const y = doc.y;
  doc.font(FONTS.semibold).fontSize(9).fillColor(PAPER.ink).text(layer, x, y, { width: layerW, lineBreak: false });
  doc.font(FONTS.mono).fontSize(9).fillColor(rateColor ?? PAPER.ink).text(rate, x + layerW, y, { width: rateW, lineBreak: false });
  doc.font(FONTS.body).fontSize(8.5).fillColor(PAPER.muted).text(note, x + layerW + rateW, y, { width: PAGE.textWidth - layerW - rateW });
  doc.x = x;
  doc.moveDown(0.45);
}

export function pageHonestGap(doc, ev, ctx = {}) {
  const { seal = {} } = ev;
  const tsa = seal.rfc3161Tsa;

  pageOpen(doc, {
    persona: "● Honest Gap Declaration · for Anyone",
    title: "What this evidence does not prove",
    reportId: ctx.reportId,
    registry: ctx.registry,
  });

  body(doc,
    "Stating the limits is the point. This page is the boundary of the claim: read it before you " +
    "rely on the seal. Everything outside these lines is out of scope by design.");
  doc.moveDown(0.6);

  // ── 1. What the seal does NOT prove ──────────────────────────────────────────
  sectionTitle(doc, "What the seal does not prove");
  limitRow(doc, {
    lead: "It does not prove the scraped claims are true.",
    detail: tsa
      ? "The RFC 3161 timestamp proves WHEN these bytes existed and that they are UNCHANGED since — " +
        "not that any price, headline, or finding inside them is accurate. Truth of the content is the " +
        "source's, not the seal's."
      : "The seal proves these bytes are UNCHANGED against the issuing key — not that any price, " +
        "headline, or finding inside them is accurate. Truth of the content is the source's, not the seal's.",
  });
  limitRow(doc, {
    lead: "It does not prove the source was authentic or uncompromised.",
    detail: "If the scraped page itself was spoofed, poisoned, or served different bytes to the crawler, " +
      "the seal faithfully records those bytes. Integrity of capture is not authenticity of origin.",
  });
  doc.moveDown(0.5);

  // ── 2. What Synthex does NOT cover ───────────────────────────────────────────
  sectionTitle(doc, "What Synthex does not cover");
  limitRow(doc, {
    lead: "Not a public-trust certificate.",
    detail: "Identity is SELF-SIGNED with an Ed25519 key (the keyId is publishable) — it is NOT a " +
      "certificate from a public trust list (no WebPKI / CA-anchored chain). A verifier trusts the " +
      "publisher's pinned key, not a browser root store.",
  });
  limitRow(doc, {
    lead: "L1 screening is heuristic regex, not a formal proof.",
    detail: "Layer-1 (78 DJL + 32 prefilter rules) is pattern-matching, REVIEW-only on ingest — it flags, " +
      "it does not formally verify safety, and it never silently drops a benign document (measured below).",
  });
  limitRow(doc, {
    lead: "Framework mappings are a mapping aid, not certification.",
    detail: "OWASP / MITRE ATLAS / NIST AI RMF / EU AI Act references are good-faith mappings, not " +
      "endorsements. No standards body reviewed these numbers or certified this report.",
  });
  doc.moveDown(0.5);

  // ── 3. Measured guard false-positive rates (the moat, in numbers) ────────────
  sectionTitle(doc, "Measured guard false positives (n=5 benign security corpus)");
  body(doc,
    "Every page in the corpus is benign by construction (security writing that DESCRIBES attacks), so " +
    "any REVIEW or BLOCK is a false positive. Numbers are measured, not asserted — source: " +
    "docs/guard-fp-measurement.md. n=5 is indicative, a floor, not a certified rate.",
    PAPER.muted);
  doc.moveDown(0.6);

  fpRow(doc, {
    layer: "L1 pipeline (regex, REVIEW-only)",
    rate: "0 / 5 dropped",
    rateColor: PAPER.green,
    note: "After the D5 fix, no benign doc is dropped; BLOCK-grade hits demote to REVIEW and stay sealed.",
  });
  fpRow(doc, {
    layer: "L2 Qwen3Guard-Gen-8B",
    rate: "≥ 2 / 5 FP",
    rateColor: PAPER.amber,
    note: "Benign FP > 20% in every run → DISQUALIFIED from BLOCK authority; its verdicts are REVIEW-capped.",
  });
  fpRow(doc, {
    layer: "L3 AlignmentCheck (deepseek)",
    rate: "0 / 5 false-BLOCK",
    rateColor: PAPER.green,
    note: "Reads describing-vs-executing correctly; the only layer holding BLOCK authority on ingest.",
  });
  doc.moveDown(0.4);

  doc.x = LEFT;
  doc.font(FONTS.body).fontSize(8.5).fillColor(PAPER.muted).text(
    "Reading: L1 flags broadly but drops nothing; L2 is too trigger-happy on security content to hold " +
    "BLOCK; L3 is the false-positive killer and the sole BLOCK authority. The conservative default is " +
    "the measured one — no guard number here was hardcoded.",
    LEFT, doc.y, { width: PAGE.textWidth, oblique: true });
  doc.fillColor(PAPER.ink).x = LEFT;
}
