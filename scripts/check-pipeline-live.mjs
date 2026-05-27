// Pipeline LIVE end-to-end: scrape real (Bright Data) → FORGE → CLASSIFY (AI/ML real) → PROVE (TSA real).
import { runPipeline } from "../src/pipeline.js";
import { verifyEvidence } from "../src/prove/evidence-report.js";

const target = process.argv[2] || "https://example.com";
const lens = process.argv[3] || "security";
const hmacKey = process.env.SYNTHEX_HMAC_KEY || "synthex-dev";

try {
  console.log(`\n⬡ SYNTHEX pipeline LIVE — target=${target} lens=${lens}\n`);
  const ev = await runPipeline(target, { lens, hmacKey });
  console.log("sources:", ev.payload.sources);
  console.log("dedup:", JSON.stringify(ev.payload.dedup));
  console.log("findings:", JSON.stringify(ev.payload.findings, null, 2));
  console.log("seal.method:", ev.seal.method);
  console.log("verify:", JSON.stringify(verifyEvidence(ev, { hmacKey })));
} catch (e) {
  console.error("ERR:", e.message);
}
process.exit(0);
