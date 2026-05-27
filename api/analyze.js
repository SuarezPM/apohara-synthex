// Vercel serverless function: corre el pipeline Synthex y devuelve el Evidence Report.
// Modo LIVE si el entorno tiene los secrets (Bright Data + AI/ML) → scrape REAL vía REST.
// Si faltan, cae a modo DEMO (snapshot cacheado), etiquetado honestamente (no se simula live).
import { runPipeline } from "../src/pipeline.js";
import { verifyEvidence } from "../src/prove/evidence-report.js";
import { httpFetcher } from "../src/fetch/http-client.js";
import { runDemo } from "../demo/demo.js";
import { assertSafeTarget, rateLimit, clientIp } from "../src/guard.js";

export const config = { maxDuration: 60 };

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });
  try {
    const { target, lens = "all" } = (req.body && typeof req.body === "object" ? req.body : {});
    const hasSecrets = !!process.env.BRIGHT_DATA_TOKEN && !!process.env.AIML_API_KEY;

    let mode, evidence, verifyKey;
    if (hasSecrets && target) {
      // Endpoint público live → guard anti-abuso: rate-limit por IP + SSRF/allowlist.
      const rl = rateLimit(clientIp(req));
      if (!rl.ok) return res.status(429).json({ error: `rate limit: ${rl.max} req/10min por IP` });
      try { assertSafeTarget(target); }
      catch (e) { return res.status(400).json({ error: e.message }); }
      verifyKey = process.env.SYNTHEX_HMAC_KEY || "synthex-dev";
      evidence = await runPipeline(target, { lens, fetcher: httpFetcher(), hmacKey: verifyKey, requestTsa: true });
      mode = "live";
    } else {
      verifyKey = process.env.SYNTHEX_HMAC_KEY || "synthex-demo";
      evidence = await runDemo({ requestTsa: true });
      mode = "demo"; // sin secrets en el deploy → snapshot cacheado, NO live (honestidad)
    }

    const verify = verifyEvidence(evidence, { hmacKey: verifyKey });
    res.status(200).json({ mode, evidence, verify });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}
