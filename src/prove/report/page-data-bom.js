// PROVE/report/page-data-bom — CISO Data-BOM (interior, light). Per-source provenance table
// (URL · Bright Data surface · fetched · SHA-256 · bytes · dedup · L1/L2/L3 verdict). Phase-2b
// SCAFFOLD STUB: renders the persona tag + H1 + a one-line "(section being built)" placeholder
// via the shared interior helpers so the full PDF always builds while the content fans out.
import { PAPER } from "./theme.js";
import { pageOpen, body } from "./interior.js";

export function pageDataBom(doc, ev, ctx = {}) {
  pageOpen(doc, {
    persona: "● Data-BOM · for CISO",
    title: "Per-source data bill of materials",
    reportId: ctx.reportId,
    registry: ctx.registry,
  });
  body(doc, "(section being built)", PAPER.muted);
  doc.x = doc.page.margins.left;
}
