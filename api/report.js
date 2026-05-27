// Vercel serverless function: recibe un Evidence Report (JSON) y devuelve el PDF descargable.
import { buildPDFReport } from "../src/prove/pdf-report.js";

export const config = { maxDuration: 30 };

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });
  try {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const evidence = body.evidence ?? body;
    if (!evidence || !evidence.contentHash) return res.status(400).json({ error: "evidence inválido" });
    const pdf = await buildPDFReport(evidence);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=synthex-evidence.pdf");
    res.status(200).send(pdf);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}
