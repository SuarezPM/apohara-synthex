// Vercel serverless function: corre el pipeline Synthex y devuelve el Evidence Report.
// Modo LIVE si el entorno tiene los secrets (Bright Data + AI/ML) → scrape REAL vía REST.
// Si faltan, cae a modo DEMO (snapshot cacheado), etiquetado honestamente (no se simula live).
import { runPipeline } from "../src/pipeline.js";
import { verifyEvidence } from "../src/prove/evidence-report.js";
import { httpFetcher } from "../src/fetch/http-client.js";
import { runDemo } from "../demo/demo.js";
import { assertSafeTarget, rateLimit, clientIp } from "../src/guard.js";
import { classify } from "../src/classify/aiml-client.js";
import { pickModel } from "../src/classify/tiers.js";

export const config = { maxDuration: 60 };

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });
  try {
    const { target, lens = "all", tier } = (req.body && typeof req.body === "object" ? req.body : {});
    const hasSecrets = !!process.env.BRIGHT_DATA_TOKEN && !!process.env.AIML_API_KEY;

    // v0.6.0: tier opt-in via playground. tier=free/oss/paid resuelve a model id
    // concreto via pickModel(). Sin tier → comportamiento v0.5 (DEFAULT_MODEL).
    let modelOverride = null;
    if (tier) {
      try { modelOverride = pickModel({ tier }); }
      catch (e) { return res.status(400).json({ error: e.message }); }
    }

    let mode, evidence, verifyKey;
    if (hasSecrets && target) {
      // Endpoint público live → guard anti-abuso: rate-limit por IP + SSRF/allowlist.
      const rl = rateLimit(clientIp(req));
      if (!rl.ok) return res.status(429).json({ error: `rate limit: ${rl.max} req/10min por IP` });
      try { assertSafeTarget(target); }
      catch (e) { return res.status(400).json({ error: e.message }); }
      verifyKey = process.env.SYNTHEX_HMAC_KEY || "synthex-dev";
      const opts = { lens, fetcher: httpFetcher(), hmacKey: verifyKey, requestTsa: true };
      // Si el playground pidió tier, inyectamos classifier custom con el model resuelto.
      if (modelOverride) {
        opts.classifier = (text, l, copts = {}) => classify(text, l, { ...copts, model: modelOverride });
      }
      evidence = await runPipeline(target, opts);
      mode = "live";
    } else {
      verifyKey = process.env.SYNTHEX_HMAC_KEY || "synthex-demo";
      evidence = await runDemo({ requestTsa: true });
      mode = "demo"; // sin secrets en el deploy → snapshot cacheado, NO live (honestidad)
    }

    const verify = verifyEvidence(evidence, { hmacKey: verifyKey });
    res.status(200).json({ mode, tier: tier ?? "default", model: modelOverride ?? "default", evidence, verify });
  } catch (e) {
    console.error("[analyze] error:", e); // detalle server-side; al cliente, mensaje genérico
    res.status(500).json({ error: "pipeline failed" });
  }
}
