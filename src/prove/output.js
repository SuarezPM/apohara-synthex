// PROVE/output — the Evidence Report's closing synthesis: "3 questions this evidence
// raises" + a one-line verdict. DETERMINISTIC, derived ONLY from the (sealed) findings +
// blocked + lens, so a verifier can recompute it from the same payload — it carries no
// information not already in the seal. Zero deps, zero LLM, no pdfkit import (safe to pull
// into the pipeline graph). When sealed into payload.{questions,verdict}, it is covered by
// the canonical pre-image like every other field.

// Flatten findings (single-lens or trilens) to {lens, severity, signals, url} rows.
function toRows(findings) {
  const out = [];
  for (const f of Array.isArray(findings) ? findings : []) {
    if (f && f.trilens && typeof f.trilens === "object") {
      for (const [lens, sub] of Object.entries(f.trilens)) {
        out.push({ lens, severity: Number(sub?.severity) || 0, signals: Array.isArray(sub?.signals) ? sub.signals : [], url: f.url });
      }
    } else {
      out.push({ lens: f?.lens, severity: Number(f?.severity) || 0, signals: Array.isArray(f?.signals) ? f.signals : [], url: f?.url });
    }
  }
  return out;
}

/**
 * Synthesize the report's closing {questions, verdict} from a payload.
 * @param {{findings?:Array, blocked?:Array, lens?:string}} payload
 * @returns {{questions:string[], verdict:string}} exactly 3 questions + a one-line verdict.
 */
export function synthesizeOutput(payload = {}) {
  const findings = Array.isArray(payload.findings) ? payload.findings : [];
  const blocked = Array.isArray(payload.blocked) ? payload.blocked.length : 0;
  const lens = payload.lens ?? "security";
  const rows = toRows(findings);
  const findingCount = findings.length;
  const maxSev = rows.length ? Math.max(...rows.map((r) => r.severity)) : 0;
  const band = maxSev >= 7 ? "HIGH" : maxSev >= 4 ? "MEDIUM" : "LOW";
  const top = rows.length ? [...rows].sort((a, b) => b.severity - a.severity)[0] : null;
  const topSignal = top && top.signals.length ? top.signals[0] : null;

  const verdict =
    `${band} RISK — max severity ${maxSev}/10 across ${findingCount} classified source(s)` +
    (blocked ? `, ${blocked} blocked pre-LLM` : "") +
    (topSignal ? `; lead signal: ${topSignal}.` : ".");

  const questions = [
    `Which of the ${findingCount} classified source(s) most changes our ${lens} exposure, and who owns the response?`,
    blocked
      ? `What would have reached the model if the ${blocked} pre-LLM block(s) had not fired?`
      : `Do the surfaced signals cross our escalation threshold under the ${lens} policy?`,
    `Is the sealed evidence (hash + timestamp + signature) sufficient to defend the highest-severity finding in an audit?`,
  ];

  return { questions, verdict };
}
