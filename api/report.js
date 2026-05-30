// Vercel serverless function: recibe un Evidence Report (JSON) y devuelve el PDF descargable.
import { buildPDFReport } from "../src/prove/pdf-report.js";
import { cveIdsFromFinding, fetchEpss } from "../src/prove/epss.js";

export const config = { maxDuration: 30 };

// R1 — OPT-IN EPSS enrichment (SYNTHEX_EPSS_ENABLED). Collects CVE ids from the findings and
// fetches FIRST.org EPSS at RENDER time (never sealed). fetchEpss is fail-safe (empty Map on any
// error), so the PDF always renders; with the flag unset there is no network and no behavior change.
async function maybeEpssMap(evidence) {
  if (!process.env.SYNTHEX_EPSS_ENABLED) return null;
  const findings = Array.isArray(evidence?.payload?.findings) ? evidence.payload.findings : [];
  const ids = findings.flatMap((f) => (f?.trilens
    ? Object.values(f.trilens).flatMap(cveIdsFromFinding)
    : cveIdsFromFinding(f)));
  if (ids.length === 0) return null;
  return fetchEpss(ids);
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });
  try {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const evidence = body.evidence ?? body;
    if (!evidence || !evidence.contentHash) return res.status(400).json({ error: "evidence inválido" });
    const epssMap = await maybeEpssMap(evidence);
    const pdf = await buildPDFReport(evidence, { epssMap });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=synthex-evidence.pdf");
    res.status(200).send(pdf);
  } catch (e) {
    console.error("[report] error:", e);
    res.status(500).json({ error: "report failed" });
  }
}
