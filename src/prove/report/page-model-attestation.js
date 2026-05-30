// PROVE/report/page-model-attestation — Compliance / Model-Risk Model & Pipeline Attestation
// (interior, light). Model ids + versions + hashes (L2 guard, classify, L3) · policy/rubric
// SHA-256 · guard_mode · SR 11-7 / NYDFS map. Phase-2b SCAFFOLD STUB: renders the persona tag +
// H1 + a one-line "(section being built)" placeholder via the shared interior helpers so the
// full PDF always builds while the content fans out.
import { PAPER } from "./theme.js";
import { pageOpen, body } from "./interior.js";

export function pageModelAttestation(doc, ev, ctx = {}) {
  pageOpen(doc, {
    persona: "● Model & Pipeline Attestation · for Model-Risk",
    title: "Every model named, versioned, and hashed",
    reportId: ctx.reportId,
    registry: ctx.registry,
  });
  body(doc, "(section being built)", PAPER.muted);
  doc.x = doc.page.margins.left;
}
