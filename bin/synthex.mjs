#!/usr/bin/env node
// CLI de Apohara Synthex — corre el pipeline (o el demo determinista) desde la terminal y emite un
// Evidence Report verificable. Sin dependencias externas: parser de argv mínimo.
//
//   node bin/synthex.mjs --demo                         # demo cacheado, SIN secrets, verificable
//   node bin/synthex.mjs --demo finance                 # demo con otra lente
//   node bin/synthex.mjs "Competitor X" gtm             # pipeline real (requiere secrets de Bright Data/AIML)
//   node bin/synthex.mjs https://example.com security --dedup=semantic   # dedup near-dup (opt-in)
import { runPipeline } from "../src/pipeline.js";
import { runDemo } from "../demo/demo.js";
import { verifyEvidence } from "../src/prove/evidence-report.js";

/**
 * Parser argv mínimo. Soporta `--flag` (boolean), `--key=value`, y posicionales.
 * @param {string[]} argv  argumentos crudos (sin node ni el script).
 * @returns {{positional:string[], flags:Record<string,string|true>}}
 */
export function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (const a of argv) {
    if (a.startsWith("--")) {
      const [k, v] = a.slice(2).split("=");
      flags[k] = v === undefined ? true : v;
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

const USAGE = `apohara-synthex — Evidence layer over Bright Data

  node bin/synthex.mjs --demo [lens]                  demo cacheado (sin secrets), verificable
  node bin/synthex.mjs <target> [lens] [--dedup=semantic|exact]

  lens: gtm | finance | security | supply-chain | all   (default: security; demo: gtm)
  --dedup=semantic   near-duplicate clustering (lossy, opt-in; descarga modelo en 1er uso)
  --help             muestra esta ayuda
`;

function printVerification(ev, hmacKey) {
  const v = verifyEvidence(ev, { hmacKey });
  console.error("\n── Verificación ──");
  console.error("  hash :", v.hashOk ? "OK" : "FALLO");
  console.error("  HMAC :", v.hmacOk ? "OK" : "FALLO");
  console.error(
    "  TSA  :",
    v.tsaOk === true ? "OK (RFC 3161 · DigiCert)" : v.tsaOk === null ? "sin TSA (fallback HMAC-only)" : "FALLO",
  );
  console.error(`  método de sello: ${ev.seal.method}\n`);
  return v;
}

export async function main(argv) {
  const { positional, flags } = parseArgs(argv);
  if (flags.help || flags.h) {
    console.log(USAGE);
    return 0;
  }
  const hmacKey = process.env.SYNTHEX_HMAC_KEY || "synthex-demo";
  let ev;
  if (flags.demo) {
    const lens = positional[0] || "gtm";
    ev = await runDemo({ requestTsa: true, lens });
  } else {
    const target = positional[0];
    if (!target) {
      console.error(USAGE);
      return 1;
    }
    const lens = positional[1] || "security";
    const dedupMode = flags.dedup === "semantic" ? "semantic" : "exact";
    ev = await runPipeline(target, { lens, dedupMode, hmacKey, requestTsa: true });
  }
  // El reporte va a stdout (parseable); la verificación a stderr (no contamina el JSON).
  console.log(JSON.stringify(ev, null, 2));
  printVerification(ev, hmacKey);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then((code) => process.exit(code ?? 0));
}
