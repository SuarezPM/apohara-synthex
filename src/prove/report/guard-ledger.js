// PROVE/report/guard-ledger — the 3-tier injection-defense ledger (CISO page). Moved out of
// pdf-report.js INTACT. Builds one summary row per layer from the SEALED payload.decisions[]
// (L1 djl/prefilter REVIEW-only · L2 INJECTION_GUARD opt-in · L3 ALIGNMENT_CHECK describing-vs
// -executing). Each row honestly labeled LIVE / DEGRADED (fail-safe REVIEW) / DEMO STUB / not run.
import { truncMid } from "./components.js";

// Etiqueta de modo de una fila de decisión: DEMO STUB > DEGRADED > LIVE. Nunca implica que una
// capa stubbeada corrió en vivo.
export function decisionMode(row) {
  const label = `${row?.model_id ?? ""} ${row?.guard_model ?? ""}`;
  if (label.includes("(DEMO STUB)")) return "DEMO STUB";
  if (row?.degraded) return "DEGRADED (fail-safe REVIEW)";
  return "LIVE";
}

// Construye el ledger 3-tier. Present-gated: capa sin filas → "not run (opt-in)". L3 trae el
// veredicto describing-vs-executing + la rationale truncada.
export function guardLedger(decisions = []) {
  const ds = Array.isArray(decisions) ? decisions : [];
  const l1 = ds.filter((d) => d.layer === "djl" || d.layer === "prefilter");
  const l2 = ds.filter((d) => d.stage === "INJECTION_GUARD");
  const l3 = ds.filter((d) => d.stage === "ALIGNMENT_CHECK");

  const summarize = (rows, outcomeKey = "outcome") => {
    const counts = rows.reduce((m, r) => ({ ...m, [r[outcomeKey]]: (m[r[outcomeKey]] ?? 0) + 1 }), {});
    return Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(" · ");
  };

  const rows = [
    l1.length
      ? { tier: "L1 regex (DJL/prefilter)", detail: `${summarize(l1)} — REVIEW-only on ingest`, mode: decisionMode(l1[0]) }
      : { tier: "L1 regex (DJL/prefilter)", detail: "no BLOCK-grade hits this batch", mode: "not run" },
    l2.length
      ? { tier: "L2 injection-guard", detail: `${summarize(l2)} (${l2[0].guard_model ?? "guard"})`, mode: decisionMode(l2[0]) }
      : { tier: "L2 injection-guard", detail: "not run (opt-in · SYNTHEX_GUARD_URL)", mode: "not run (opt-in)" },
  ];
  if (l3.length) {
    for (const r of l3) {
      rows.push({
        tier: "L3 alignment-check",
        detail: `${r.outcome} (conf ${r.confidence ?? "—"}) — ${truncMid(r.rationale, 70, 0)}`,
        mode: decisionMode(r),
      });
    }
  } else {
    rows.push({ tier: "L3 alignment-check", detail: "not run (no REVIEW-band doc to adjudicate)", mode: "not run" });
  }
  return rows;
}
