// PROVE/report/page-honest-gap — Honest Gap Declaration (interior, light). What it does NOT
// prove · what is NOT covered · self-signed limit · L1 heuristic-not-formal · measured guard FP.
// Phase-2b SCAFFOLD STUB: renders the persona tag + H1 + a one-line "(section being built)"
// placeholder via the shared interior helpers so the full PDF always builds while content fans out.
import { PAPER } from "./theme.js";
import { pageOpen, body } from "./interior.js";

export function pageHonestGap(doc, ev, ctx = {}) {
  pageOpen(doc, {
    persona: "● Honest Gap Declaration · for Anyone",
    title: "What this evidence does not prove",
    reportId: ctx.reportId,
    registry: ctx.registry,
  });
  body(doc, "(section being built)", PAPER.muted);
  doc.x = doc.page.margins.left;
}
