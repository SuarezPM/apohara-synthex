// PROVE/report/page-model-attestation — Compliance / Model-Risk Model & Pipeline Attestation
// (interior, light). Answers the model-risk buyer's first question: WHICH models ran, and under
// what build identity? Every model named, versioned, hashed — sourced from the SEALED
// payload.decisions[] (L2 INJECTION_GUARD · L3 ALIGNMENT_CHECK) and payload.policy_bundle_version,
// not invented. Each model is honestly labeled LIVE / DEGRADED / DEMO STUB from its own row
// (the "(DEMO STUB)" marker in model_id/guard_model + the degraded flag). The describing-vs
// -executing policy + classify-prompt versions are surfaced as the rubric SHA-256 line. Maps to
// SR 11-7 + NYDFS Part 500 (23 NYCRR 500) as a model-risk MAPPING aid — NOT a certification.
import { PAPER, FONTS, PAGE } from "./theme.js";
import { pageOpen, sectionTitle, body } from "./interior.js";
import { table, attestationRow, frameworkMatrix } from "./components.js";

// Honest run-mode for one model from its sealed row. DEMO STUB > DEGRADED > LIVE. Never implies a
// stubbed layer ran in vivo; the "(DEMO STUB)" marker is carried in the model id by the pipeline.
function modeOf({ id = "", degraded = false } = {}) {
  if (String(id).includes("(DEMO STUB)")) return { label: "DEMO STUB", color: PAPER.violet };
  if (degraded) return { label: "DEGRADED", color: PAPER.amber };
  return { label: "LIVE", color: PAPER.green };
}

// Strip the "(DEMO STUB)" suffix so the id column stays clean; the mode column carries the honesty.
const cleanId = (s) => String(s ?? "—").replace(/\s*\(DEMO STUB\)\s*$/, "").trim() || "—";

export function pageModelAttestation(doc, ev, ctx = {}) {
  const { payload = {} } = ev;
  const decisions = Array.isArray(payload.decisions) ? payload.decisions : [];
  const pbv = payload.policy_bundle_version ?? {};

  // First row of each kind from the sealed ledger (build identity is stable across rows of a layer).
  const l2 = decisions.find((d) => d.stage === "INJECTION_GUARD") ?? null;
  const l3 = decisions.find((d) => d.stage === "ALIGNMENT_CHECK") ?? null;
  const classify = decisions.find((d) => d.stage === "CLASSIFY" || d.layer === "classify") ?? null;

  pageOpen(doc, {
    persona: "● Model & Pipeline Attestation · for Compliance / Model Risk",
    title: "Every model named, versioned, and hashed",
    reportId: ctx.reportId,
    registry: ctx.registry,
  });

  body(doc,
    "The model-risk control question for any AI pipeline: which models actually ran, and under " +
    "what build identity? Every model below is read from the sealed decision ledger — its id, " +
    "version, and provider are part of the signed record, not asserted here. Each is labeled by " +
    "its real run mode.");
  doc.moveDown(0.6);

  // ── 1) Models that ran — build identity table ────────────────────────────────
  sectionTitle(doc, "Models that ran (build identity, from sealed decisions)");

  const modelRows = [];

  // L2 — injection guard (Qwen3Guard via Featherless).
  modelRows.push(
    l2
      ? {
          stage: "L2 · injection guard",
          model: cleanId(l2.guard_model),
          version: l2.guard_version ?? "—",
          provider: l2.guard_provider ?? "—",
          mode: modeOf({ id: l2.guard_model }).label,
        }
      : { stage: "L2 · injection guard", model: "—", version: "—", provider: "—", mode: "not run" },
  );

  // Classify model — present-gated. The demo classifier is a deterministic JS function (no live
  // model id in decisions[]); label that honestly rather than inventing a model name.
  modelRows.push(
    classify
      ? {
          stage: "Classify · tier model",
          model: cleanId(classify.model_id),
          version: classify.version ?? "—",
          provider: classify.provider ?? "—",
          mode: modeOf({ id: classify.model_id, degraded: classify.degraded }).label,
        }
      : { stage: "Classify · tier model", model: "function classifier (demo)", version: "—", provider: "in-process", mode: "DEMO STUB" },
  );

  // L3 — alignment-check reasoner (describing-vs-executing).
  modelRows.push(
    l3
      ? {
          stage: "L3 · alignment reasoner",
          model: cleanId(l3.model_id),
          version: l3.version ?? "—",
          provider: l3.provider ?? "—",
          mode: modeOf({ id: l3.model_id, degraded: l3.degraded }).label,
        }
      : { stage: "L3 · alignment reasoner", model: "—", version: "—", provider: "—", mode: "not run" },
  );

  table(doc, {
    theme: PAPER,
    columns: [
      { key: "stage", header: "Stage", width: 116 },
      { key: "model", header: "Model id", trunc: [26, 6] },
      { key: "version", header: "Version", width: 96, mono: true },
      { key: "provider", header: "Provider", width: 70 },
      { key: "mode", header: "Mode", width: 64 },
    ],
    rows: modelRows,
  });
  doc.x = doc.page.margins.left;
  doc.moveDown(0.3);

  // Honest run-mode legend (a11y: the Mode column is a text label, never color alone).
  doc.font(FONTS.body).fontSize(7.5).fillColor(PAPER.muted).text(
    "Mode: LIVE = real model call this run · DEGRADED = model unreachable, failed safe to REVIEW · " +
    "DEMO STUB = deterministic offline stand-in (this reproducible demo run). The full, untruncated " +
    "model ids and hashes live in the sidecar evidence.json.",
    doc.page.margins.left, doc.y, { width: PAGE.textWidth });
  doc.fillColor(PAPER.ink);
  doc.x = doc.page.margins.left;
  doc.moveDown(0.7);

  // ── 2) Build hashes & guard config — attestation lines ───────────────────────
  sectionTitle(doc, "Build hashes & guard configuration");

  // L2 weight/model hash (null in this run → honest "not pinned this run").
  attestationRow(doc, {
    theme: PAPER,
    label: "L2 guard model_hash",
    value: l2?.model_hash ?? "not pinned (stub — no live weights this run)",
    trunc: l2?.model_hash ? [22, 14] : null,
  });
  attestationRow(doc, { theme: PAPER, label: "L2 guard_mode", value: l2?.guard_mode ?? "—", trunc: null });
  attestationRow(doc, {
    theme: PAPER,
    label: "L2 guard_score (this doc)",
    value: l2 && l2.guard_score != null ? `${l2.guard_score} (REVIEW-capped — measured 40% benign FP, BLOCK disqualified)` : "—",
    trunc: null,
  });
  doc.moveDown(0.3);
  doc.x = doc.page.margins.left;

  // ── 3) Policy / rubric versions (SHA-256-derived) ────────────────────────────
  sectionTitle(doc, "Policy & rubric versions (content-addressed)");
  body(doc,
    "Each guard/classifier policy is content-addressed: the version string embeds a SHA-256 of the " +
    "rubric text, so any change to the describing-vs-executing policy or the pre-filter rules yields " +
    "a new, auditable id in the signed record.", PAPER.muted);
  doc.moveDown(0.4);
  doc.x = doc.page.margins.left;

  attestationRow(doc, { theme: PAPER, label: "DJL policy bundle", value: pbv.djl ?? "—", trunc: null });
  attestationRow(doc, { theme: PAPER, label: "Prefilter policy bundle", value: pbv.prefilter ?? "—", trunc: null });
  attestationRow(doc, {
    theme: PAPER,
    label: "L2 guard policy bundle",
    value: pbv.injectionGuard ?? l2?.policy_bundle_version ?? "—",
    trunc: null,
  });
  attestationRow(doc, {
    theme: PAPER,
    label: "L3 align-check rubric",
    value: l3?.version ?? "—",
    trunc: null,
  });
  doc.moveDown(0.5);
  doc.x = doc.page.margins.left;

  // ── 4) Model-risk mapping (SR 11-7 · NYDFS Part 500) ─────────────────────────
  sectionTitle(doc, "Model-risk mapping (aid, not certification)");
  frameworkMatrix(doc, {
    theme: PAPER,
    rows: [
      {
        control: "OCC/Fed SR 11-7 — model inventory & identity",
        status: "green",
        citation: "every model id + version + policy hash is in the signed record",
      },
      {
        control: "SR 11-7 — ongoing monitoring (degraded-state log)",
        status: "amber",
        citation: "fail-safe REVIEW + degraded:true sealed; not a full validation programme",
      },
      {
        control: "NYDFS Part 500 (23 NYCRR 500) — audit trail",
        status: "green",
        citation: "tamper-evident, timestamped decision ledger per run",
      },
    ],
  });
  doc.x = doc.page.margins.left;
  doc.moveDown(0.3);

  // Honest disclaimer — mapping, not endorsement / certification. No body reviewed these numbers.
  doc.font(FONTS.body).fontSize(8).fillColor(PAPER.muted).text(
    "This attestation maps the sealed model-identity record to SR 11-7 (Model Risk Management) and " +
    "NYDFS Part 500 as a good-faith MODEL-RISK AID — it is a mapping, not an endorsement or " +
    "certification. No regulator or framework body has reviewed these models or this report. " +
    "Applicability depends on the deploying institution's own model-risk programme.",
    doc.page.margins.left, doc.y, { width: PAGE.textWidth, oblique: true });
  doc.fillColor(PAPER.ink);
  doc.x = doc.page.margins.left;
}
