// Vercel serverless function: corre el pipeline y transmite el progreso por Server-Sent Events.
// Cada stage del pipeline emite {stage, status:"start"|"done", ms} → la UI dibuja progress bars
// cinematic en tiempo real. Al final emite un evento "result" con {mode, evidence, verify}.
// Mismo guard (rate-limit + SSRF) y modos live/demo que /api/analyze.
import { runPipeline } from "../src/pipeline.js";
import { verifyEvidence } from "../src/prove/evidence-report.js";
import { httpFetcher } from "../src/fetch/http-client.js";
import { runDemo } from "../demo/demo.js";
import { assertSafeTarget, rateLimit, clientIp } from "../src/guard.js";

export const config = { maxDuration: 60 };

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });

  const { target, lens = "all" } = (req.body && typeof req.body === "object" ? req.body : {});
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
    let mode, evidence, verifyKey;
    if (hasSecrets && target) {
      const rl = rateLimit(clientIp(req));
      if (!rl.ok) { send("error", { error: `rate limit: ${rl.max} req/10min por IP` }); return res.end(); }
      try { assertSafeTarget(target); }
      catch (e) { send("error", { error: e.message }); return res.end(); }
      verifyKey = process.env.SYNTHEX_HMAC_KEY || "synthex-dev";
      mode = "live";
      send("mode", { mode, target, lens });
      evidence = await runPipeline(target, {
        lens, fetcher: httpFetcher(), hmacKey: verifyKey, requestTsa: true,
        emitter: (evt) => send("stage", evt),
      });
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
