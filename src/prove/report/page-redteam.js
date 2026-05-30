// PROVE/report/page-redteam — Red-Team Board Briefing (interior, light paper). Renders the sealed
// 5-lens adversarial red-team (src/redteam/) as an evidence page: per-persona risk + one grounded
// concern, the aggregate Risk Score band AND the PROCEED/CAUTION/DO-NOT-PROCEED verdict surfaced as
// TWO DISTINCT AXES (never one), and the Top-3 board questions.
//
// HONESTY (binding, mirrors src/redteam/personas.js M4/D11): these are 5 distinct PROMPTS over ONE
// frontier reasoner, NOT 5 independent models — angle-coverage + per-lens sealing, never a claim of
// statistical independence. Every row here is reconstructed from payload.decisions[] (the sealed
// stage:"REDTEAM_<lens>" rows), so a verifier could recompute it. The two axes are computed from the
// SAME 0–100 score but at DIFFERENT thresholds, and are labeled as separate axes everywhere they
// appear so a CRITICAL band + a DO-NOT-PROCEED verdict never reads as a circular restatement:
//   · band    ≥80 CRITICAL · ≥60 HIGH · ≥40 MEDIUM · else LOW   (severity-of-concern axis, gauge)
//   · verdict ≥70 DO NOT PROCEED · ≥40 CAUTION · else PROCEED   (board-decision axis, lead scale)
// These thresholds are kept byte-identical to the sealed aggregate in src/redteam/index.js; if the
// payload carries a sealed aggregate we render IT verbatim and only fall back to recomputation.
//
// PDFKit pitfall honored throughout (per the design audit): doc.y does NOT advance after a
// lineBreak:false draw, so single-line draws STEP y by a fixed amount and only WRAPPING blocks read
// doc.y afterward; doc.x is reset to the left margin before every wrapping block; the shared table()
// measures → grows → paginates and never overflows.
import { PAPER, FONTS, PAGE } from "./theme.js";
import { pageOpen, sectionTitle, body } from "./interior.js";
import { table, truncMid } from "./components.js";

// Sealed per-lens decision rows carry stage:"REDTEAM_<KEY>" (src/redteam/index.js). Match the
// prefix, never an exact key list, so a new lens flows through without a render change.
const REDTEAM_STAGE = /^REDTEAM_/;

// ── Axis #1 — concern-severity band (0–100 gauge). Thresholds = src/redteam/index.js aggregate() ──
const bandOf = (score) =>
  score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW";
const bandColorOf = (band) =>
  band === "CRITICAL" || band === "HIGH" ? PAPER.red : band === "MEDIUM" ? PAPER.amber : PAPER.green;

// ── Axis #2 — board-decision verdict (lead scale). Thresholds = src/redteam/index.js aggregate() ──
const verdictOf = (score) =>
  score >= 70 ? "DO NOT PROCEED" : score >= 40 ? "CAUTION" : "PROCEED";
const verdictColorOf = (verdict) =>
  verdict.startsWith("DO NOT") ? PAPER.red : verdict.startsWith("CAUTION") ? PAPER.amber : PAPER.green;
const verdictGlyphOf = (verdict) =>
  verdict.startsWith("DO NOT") ? "✗" : verdict.startsWith("CAUTION") ? "▲" : "✓";

// Recompute the aggregate from the sealed lens rows using the SAME blend as src/redteam/index.js
// (mean·0.5 + worst·0.5). Verbatim formula so a verifier recomputes the exact published number.
function aggregateFromLenses(lensRows) {
  const risks = lensRows.map((l) => Number(l.risk) || 0);
  if (!risks.length) return { score: 0, band: "LOW", verdict: "PROCEED" };
  const avg = risks.reduce((a, b) => a + b, 0) / risks.length;
  const max = Math.max(...risks);
  const score = Math.round(avg * 0.5 + max * 0.5);
  return { score, band: bandOf(score), verdict: verdictOf(score) };
}

// First grounded concern for a lens (the one that survived grounding.js — fabricated figures are
// already dropped upstream). Falls back to the truncated rationale, then a present-gated dash.
function leadConcern(row) {
  const concerns = Array.isArray(row.concerns) ? row.concerns.filter((c) => typeof c === "string") : [];
  if (concerns.length) return concerns[0];
  if (typeof row.rationale === "string" && row.rationale.trim()) return truncMid(row.rationale, 120, 0);
  return "—";
}

// Top-3 board questions: prefer the sealed aggregate's list; else rebuild it the SAME way
// src/redteam/index.js does — highest-risk lenses first, their grounded concerns, capped at 3.
function topQuestionsFrom(payload, lensRows) {
  const sealed = payload?.redteam?.topQuestions ?? payload?.redteam_top_questions;
  if (Array.isArray(sealed) && sealed.length) {
    return sealed.filter((q) => typeof q === "string").slice(0, 3);
  }
  return lensRows
    .slice()
    .sort((a, b) => (Number(b.risk) || 0) - (Number(a.risk) || 0))
    .flatMap((l) => (Array.isArray(l.concerns) ? l.concerns : []).map((c) => `[${l.persona ?? "lens"}] ${c}`))
    .filter((q) => typeof q === "string")
    .slice(0, 3);
}

// Mode tag for a lens row: a degraded lens contributed risk 0 (fail-safe) — never blame it for a
// clean score. Color paired with literal text (a11y: never color alone).
const lensMode = (row) => (row.degraded === true ? "DEGRADED" : "LIVE");
const lensModeColor = (row) => (row.degraded === true ? PAPER.amber : PAPER.green);

export function pageRedteam(doc, ev, ctx = {}) {
  const { payload = {} } = ev;
  const decisions = Array.isArray(payload.decisions) ? payload.decisions : [];
  const lensRows = decisions.filter((d) => REDTEAM_STAGE.test(String(d?.stage ?? "")));
  const left = doc.page.margins.left;

  pageOpen(doc, {
    persona: "● Red-Team · for the Board",
    title: "Five adversarial lenses, one sealed verdict",
    reportId: ctx.reportId,
    registry: ctx.registry,
  });

  // ── No red-team run for this evidence — render an honest note, nothing fabricated. ──
  if (!lensRows.length) {
    sectionTitle(doc, "No red-team run for this evidence");
    body(doc,
      "The 5-lens adversarial red-team (src/redteam) is an on-demand, high-stakes pass — it is NEVER " +
      "run in bulk, so most evidence records carry no red-team rows. This evidence object has no " +
      "stage:\"REDTEAM_*\" decisions sealed in payload.decisions[], so there is no risk score, verdict, " +
      "or board question to report here. Run `synthex redteam <document>` to seal one.", PAPER.muted);
    doc.x = left;
    return;
  }

  // Honest framing FIRST — 5 prompts, 1 model. Prompt-diversity, not model-diversity.
  body(doc,
    "Five skeptical lenses (CFO · Market · Legal · Competitor · Execution) red-team the same document. " +
    "These are 5 distinct PROMPTS over ONE frontier reasoner — angle-coverage and per-lens sealing, " +
    "NOT 5 independent models and not a claim of statistical independence. Each row below is " +
    "reconstructed from the sealed payload.decisions[].", PAPER.muted);
  doc.moveDown(0.4);

  // Prefer a sealed aggregate if the integrator stores one; else recompute from the lens rows with
  // the published formula (kept byte-identical to src/redteam/index.js so a verifier recomputes it).
  const sealedAgg = payload?.redteam ?? null;
  const recomputed = aggregateFromLenses(lensRows);
  const score = Number.isFinite(Number(sealedAgg?.score)) ? Number(sealedAgg.score) : recomputed.score;
  const band = typeof sealedAgg?.band === "string" ? sealedAgg.band : bandOf(score);
  // A fully-degraded red-team seals an INCONCLUSIVE verdict (src/redteam/index.js): honor a sealed
  // verdict string verbatim; only derive PROCEED/CAUTION/DO-NOT-PROCEED when none was sealed.
  const verdict = typeof sealedAgg?.verdict === "string" ? sealedAgg.verdict : verdictOf(score);
  const allDegraded = lensRows.every((l) => l.degraded === true);

  // ── Axis #1 — Risk Score band on the 0–100 gauge (concern-severity axis) ───────
  sectionTitle(doc, "Red-Team Risk Score — band on the 0–100 gauge (concern-severity axis)");
  const gaugeColor = bandColorOf(band);
  const gaugeTop = doc.y;
  doc.font(FONTS.bold).fontSize(46).fillColor(gaugeColor).text(String(score), left, gaugeTop, { lineBreak: false });
  doc.font(FONTS.body).fontSize(12).fillColor(PAPER.muted).text("/ 100", left + 78, gaugeTop + 22, { lineBreak: false });
  doc.font(FONTS.semibold).fontSize(13).fillColor(gaugeColor)
    .text(`Band · ${band}`, left + 78, gaugeTop + 4, { lineBreak: false });
  // Step past the single-line gauge block manually (lineBreak:false leaves doc.y unmoved).
  const barY = gaugeTop + 56;
  const barW = PAGE.textWidth;
  doc.rect(left, barY, barW, 9).fill(PAPER.rule);
  doc.rect(left, barY, (Math.min(score, 100) / 100) * barW, 9).fill(gaugeColor);
  doc.x = left;
  doc.y = barY + 18;
  doc.font(FONTS.body).fontSize(8).fillColor(PAPER.muted).text(
    "Band thresholds: ≥80 CRITICAL · ≥60 HIGH · ≥40 MEDIUM · else LOW. Score = round(mean·0.5 + " +
    "worst·0.5) over the per-lens risks below (deterministic; reproducible from the sealed rows).",
    left, doc.y, { width: PAGE.textWidth, lineGap: 1.5 });
  doc.x = left;
  doc.moveDown(0.6);

  // ── Axis #2 — board-decision verdict on the lead scale (SEPARATE axis from the band) ──
  sectionTitle(doc, "Board verdict — decision axis (separate axis from the band above)");
  const vColor = allDegraded ? PAPER.muted : verdictColorOf(verdict);
  const vGlyph = allDegraded ? "•" : verdictGlyphOf(verdict);
  const vy = doc.y;
  doc.font(FONTS.monoBold).fontSize(11).fillColor(vColor)
    .text(`${vGlyph} ${verdict}`, left, vy, { width: 240, lineBreak: false });
  doc.font(FONTS.body).fontSize(9).fillColor(PAPER.muted)
    .text("Verdict thresholds: ≥70 DO NOT PROCEED · ≥40 CAUTION · else PROCEED — a different scale " +
      "from the 0–100 band above, so a CRITICAL band and a DO-NOT-PROCEED verdict are not the same axis.",
      left + 248, vy, { width: PAGE.textWidth - 248, lineGap: 2 });
  const capBottom = doc.y; // caption wraps → advance past whichever is taller
  doc.x = left;
  doc.y = Math.max(vy + 20, capBottom) + 8;
  if (allDegraded) {
    body(doc,
      "Every lens degraded (the reasoner was unreachable): the all-zero risk would aggregate to a " +
      "clean PROCEED, so the red-team seals INCONCLUSIVE rather than a dangerous all-clear.", PAPER.muted);
    doc.moveDown(0.2);
  }

  // ── Per-lens verdicts — risk + one grounded concern, NEVER overflow (shared table) ──
  sectionTitle(doc, "Per-lens verdicts — risk + one grounded concern");
  const rows = lensRows.map((r) => ({
    lens: `${lensMode(r)} · ${String(r.name ?? r.persona ?? "lens")}`,
    risk: `${Number(r.risk) || 0}`,
    concern: leadConcern(r),
  }));
  table(doc, {
    theme: PAPER,
    columns: [
      { key: "lens", header: "Lens", width: 150 },
      { key: "risk", header: "Risk", width: 46, align: "right" },
      { key: "concern", header: "Top grounded concern" },
    ],
    rows,
  });
  doc.x = left;
  doc.font(FONTS.body).fontSize(7.5).fillColor(PAPER.muted).text(
    "Risk is each lens's own 0–100 rating (0 = no concern, 100 = deal-breaker). A DEGRADED lens " +
    "contributed risk 0 (fail-safe — a dead lens cannot inflate the verdict). Concerns are grounded " +
    "against the window the model saw; fabricated figures were dropped before sealing.",
    left, doc.y, { width: PAGE.textWidth, lineGap: 1.5 });
  doc.x = left;
  doc.moveDown(0.6);

  // ── Top-3 board questions (verbatim from the sealed red-team) ───────────────────
  sectionTitle(doc, "Top-3 questions this red-team raises for the board");
  const questions = topQuestionsFrom(payload, lensRows);
  if (!questions.length) {
    body(doc,
      "No grounded concern survived grounding across the lenses, so the red-team raised no board " +
      "question for this document.", PAPER.muted);
  } else {
    questions.forEach((q, i) => {
      doc.x = left;
      doc.font(FONTS.body).fontSize(9).fillColor(PAPER.ink)
        .text(`${i + 1}.  ${q}`, left, doc.y, { width: PAGE.textWidth, lineGap: 2 });
      doc.moveDown(0.2);
    });
  }
  doc.x = left;
}
