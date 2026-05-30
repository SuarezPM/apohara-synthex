// PROVE/stix — export an Evidence Report as a STIX 2.1 bundle.
//
// STIX 2.1 (OASIS) is the lingua franca of threat-intel platforms (MISP, OpenCTI,
// TAXII feeds). This maps a sealed Evidence Report's findings → STIX indicators +
// a wrapping report, and — crucially — ties every object back to the sealed
// evidence via `external_references` carrying the report `contentHash` (and the
// Ed25519 `keyId` when present). A consumer can pull the bundle into their SIEM
// AND re-verify it against the original sealed report. Pure JSON mapping, zero deps.
//
// We do NOT invent object types or smuggle non-spec fields into core SDOs: only
// the standard STIX 2.1 vocabulary (indicator, report, bundle) + the standard
// `external_references` extension point for the seal linkage.
import { randomUUID } from "node:crypto";

// STIX timestamps are RFC 3339 / ISO-8601 with a 'Z'. Reuse the report's own
// fetchedAt when present (keeps the bundle tied to the evidence's own clock);
// fall back to now for legacy reports without it.
function stixTime(evidence) {
  const t = evidence?.payload?.fetchedAt;
  if (typeof t === "string" && t.length) return t;
  return new Date().toISOString();
}

// STIX single-quoted pattern strings escape backslash then quote.
function escPattern(s) {
  return String(s ?? "").replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

function clampConfidence(severity) {
  const n = Math.round((Number(severity) || 0) * 10);
  return Math.max(0, Math.min(100, n));
}

// Flatten a finding into {summary, severity, signals} rows. A single-lens finding
// yields one row; a lens="all" (trilens) finding yields one row per lens.
function findingRows(f) {
  if (f && f.trilens && typeof f.trilens === "object") {
    return Object.entries(f.trilens).map(([lens, sub]) => ({
      url: f.url,
      lens,
      summary: sub?.summary ?? "",
      severity: sub?.severity ?? 0,
      signals: Array.isArray(sub?.signals) ? sub.signals : [],
    }));
  }
  return [{
    url: f?.url,
    lens: f?.lens,
    summary: f?.summary ?? "",
    severity: f?.severity ?? 0,
    signals: Array.isArray(f?.signals) ? f.signals : [],
  }];
}

/**
 * Build a STIX 2.1 bundle from an Evidence Report.
 * @param {object} evidence  a full report ({payload, contentHash, seal}).
 * @param {{newId?:()=>string, now?:string}} [opts]  injectable id/time for deterministic tests.
 * @returns {object} a STIX 2.1 bundle.
 */
export function toStixBundle(evidence, opts = {}) {
  const newId = typeof opts.newId === "function" ? opts.newId : () => randomUUID();
  const created = opts.now ?? stixTime(evidence);
  const payload = evidence?.payload ?? {};
  const contentHash = evidence?.contentHash ?? null;
  const keyId = evidence?.seal?.signature?.keyId ?? null;
  const target = payload.target ?? "unknown-target";

  // The seal linkage every object carries — lets a consumer re-verify against the
  // original sealed report (NOT an endorsement; a pointer to the evidence).
  const sealRef = {
    source_name: "apohara-synthex-evidence",
    description: `Sealed Evidence Report contentHash${keyId ? ` (Ed25519 keyId ${keyId})` : ""}`,
    external_id: contentHash ?? "unsealed",
  };

  const findings = Array.isArray(payload.findings) ? payload.findings : [];
  const indicators = [];
  for (const f of findings) {
    for (const row of findingRows(f)) {
      if (!row.url) continue;
      indicators.push({
        type: "indicator",
        spec_version: "2.1",
        id: `indicator--${newId()}`,
        created,
        modified: created,
        name: (row.summary || `${row.lens ?? "intel"} signal`).slice(0, 250),
        description: row.signals.length ? `Signals: ${row.signals.join(", ")}` : undefined,
        indicator_types: ["anomalous-activity"],
        pattern_type: "stix",
        pattern: `[url:value = '${escPattern(row.url)}']`,
        valid_from: created,
        confidence: clampConfidence(row.severity),
        labels: row.signals.length ? row.signals.map(String) : [String(row.lens ?? "intel")],
        external_references: [sealRef],
      });
    }
  }

  const report = {
    type: "report",
    spec_version: "2.1",
    id: `report--${newId()}`,
    created,
    modified: created,
    name: `Apohara Synthex Evidence — ${target}`,
    description: `STIX 2.1 export of a sealed Synthex Evidence Report (lens: ${payload.lens ?? "n/a"}).`,
    report_types: ["threat-report"],
    published: created,
    object_refs: indicators.map((i) => i.id),
    confidence: indicators.length
      ? Math.max(...indicators.map((i) => i.confidence))
      : 0,
    external_references: [sealRef],
  };

  return {
    type: "bundle",
    id: `bundle--${newId()}`,
    spec_version: "2.1",
    objects: [report, ...indicators],
  };
}
