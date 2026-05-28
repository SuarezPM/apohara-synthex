// Genera el Sample Evidence Report en /samples/ desde el pipeline REAL (runDemo → buildEvidence →
// buildPDFReport). El sello (HMAC-SHA256 + RFC 3161 TSA DigiCert) se genera EN VIVO; los datos son
// el snapshot cacheado del demo. Antes de escribir el PDF, verifica hashOk+hmacOk para que el
// sample quede atado a la garantía (no es solo "un PDF con páginas").
//
//   node scripts/gen-sample-report.mjs        # → samples/synthex-evidence-report.{pdf,json}
import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { runDemo } from "../demo/demo.js";
import { verifyEvidence } from "../src/prove/evidence-report.js";
import { buildPDFReport } from "../src/prove/pdf-report.js";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(repoRoot, "samples");
const hmacKey = process.env.SYNTHEX_HMAC_KEY || "synthex-demo";

const ev = await runDemo({ requestTsa: true });
const v = verifyEvidence(ev, { hmacKey });
if (!v.hashOk || !v.hmacOk) {
  console.error("✗ verificación falló — NO se escribe el sample:", v);
  process.exit(1);
}

mkdirSync(outDir, { recursive: true });
const pdf = await buildPDFReport(ev);
writeFileSync(join(outDir, "synthex-evidence-report.pdf"), pdf);
writeFileSync(join(outDir, "synthex-evidence-report.json"), JSON.stringify(ev, null, 2) + "\n");

const tsa = v.tsaOk === true ? "OK (RFC 3161 · DigiCert)" : v.tsaOk === null ? "sin TSA" : "FALLO";
console.log(`✓ samples/synthex-evidence-report.pdf  (${pdf.length} bytes)`);
console.log(`  hashOk=${v.hashOk}  hmacOk=${v.hmacOk}  TSA=${tsa}  método=${ev.seal.method}`);
