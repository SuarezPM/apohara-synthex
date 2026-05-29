// Vercel serverless function: corre el pipeline y transmite el progreso por Server-Sent Events.
// Cada stage del pipeline emite {stage, status:"start"|"done", ms} → la UI dibuja progress bars
// cinematic en tiempo real. Al final emite un evento "result" con {mode, evidence, verify}.
// Mismo guard (rate-limit + SSRF) y modos live/demo que /api/analyze.
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

  // Parity con api/analyze.js: el tier del playground llega también al stream.
  const { target, lens = "all", tier } = (req.body && typeof req.body === "object" ? req.body : {});
  const hasSecrets = !!process.env.BRIGHT_DATA_TOKEN && !!process.env.AIML_API_KEY;

  // SSE headers
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);

  try {
    // Resolver tier ANTES de abrir el pipeline (headers SSE ya enviados — no podemos usar
    // res.status(400); errores van via SSE 'error' event + res.end()).
    let modelOverride = null;
    if (tier) {
      try { modelOverride = pickModel({ tier }); }
      catch (e) { send("error", { error: e.message }); return res.end(); }
    }
    let mode, evidence, verifyKey;
    if (hasSecrets && target) {
      const rl = rateLimit(clientIp(req));
      if (!rl.ok) { send("error", { error: `rate limit: ${rl.max} req/10min por IP` }); return res.end(); }
      try { assertSafeTarget(target); }
      catch (e) { send("error", { error: e.message }); return res.end(); }
      verifyKey = process.env.SYNTHEX_HMAC_KEY || "synthex-dev";
      mode = "live";
      send("mode", { mode, tier: tier ?? "default", model: modelOverride ?? "default", target, lens });
      const opts = {
        lens, fetcher: httpFetcher(), hmacKey: verifyKey, requestTsa: true,
        emitter: (evt) => send("stage", evt),
      };
      if (modelOverride) {
        opts.classifier = (text, l, copts = {}) => classify(text, l, { ...copts, model: modelOverride, tier });
      }
      evidence = await runPipeline(target, opts);
    } else {
      verifyKey = process.env.SYNTHEX_HMAC_KEY || "synthex-demo";
      mode = "demo"; // sin secrets → snapshot cacheado, NO live (honestidad)
      send("mode", { mode });
      evidence = await runDemo({ requestTsa: true, emitter: (evt) => send("stage", evt) });
    }

    const verify = await verifyEvidence(evidence, { hmacKey: verifyKey });
    send("result", { mode, evidence, verify });
    res.end();
  } catch (e) {
    console.error("[stream] error:", e);
    send("error", { error: "pipeline failed" });
    res.end();
  }
}
