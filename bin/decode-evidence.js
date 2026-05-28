#!/usr/bin/env node
// decode-evidence — CLI offline para inspeccionar un Evidence Report sellado.
//
//   node bin/decode-evidence.js <path-to-evidence.json>
//
// - Verifica HMAC (auto-detecta schema_version vía N3: v1 legacy O v2 canonicalize).
// - Verifica TSA RFC 3161 si el evidence trae token (no requiere red en v=1 sin TSA).
// - Imprime el audit trail `decisions[]` formateado por stage cuando schema_version >= 2.
// - Cierra el gap de "tab Audit UI fuera de scope" — el dato sellado se inspecciona aquí
//   sin abrir el browser ni levantar la UI.
//
// Cero dependencias externas — solo node:fs y módulos de Synthex (verifyEvidence).
import { readFileSync } from "node:fs";
import { verifyEvidence } from "../src/prove/evidence-report.js";

const USAGE = `decode-evidence — inspeccioná un Evidence Report sellado.

  node bin/decode-evidence.js <path-to-evidence.json>

Env:
  SYNTHEX_HMAC_KEY   clave HMAC para verificar (default: "synthex-demo")
`;

function printDecisionsTable(decisions) {
  if (!Array.isArray(decisions) || decisions.length === 0) {
    console.log("\n── Decisions ──\n  (vacío — ningún doc bloqueado por DJL ni prefilter)\n");
    return;
  }
  console.log("\n── Decisions (audit trail por stage) ──");
  console.log("  " + ["STAGE", "LAYER", "OUTCOME", "RULE", "URL"].map((s) => s.padEnd(12)).join(""));
  console.log("  " + "─".repeat(62));
  for (const d of decisions) {
    const rule = Array.isArray(d.rule_matched) ? d.rule_matched.join(",") : String(d.rule_matched ?? "—");
    console.log("  " + [d.stage, d.layer, d.outcome, rule, d.url ?? ""].map((s) => String(s).slice(0, 12).padEnd(12)).join(""));
  }
  console.log();
}

function printSummary(ev) {
  const p = ev.payload ?? {};
  const schemaVer = p.schema_version ?? 1;
  console.log("── Evidence Report ──");
  console.log(`  schema_version : ${schemaVer}`);
  console.log(`  target         : ${Array.isArray(p.target) ? p.target.join(", ") : (p.target ?? "—")}`);
  console.log(`  lens           : ${p.lens ?? "—"}`);
  console.log(`  fetchedAt      : ${p.fetchedAt ?? "—"}`);
  console.log(`  sources        : ${(p.sources?.length ?? 0)}`);
  console.log(`  findings       : ${(p.findings?.length ?? 0)}`);
  console.log(`  blocked        : ${(p.blocked?.length ?? 0)}`);
  if (schemaVer >= 2) {
    const pbv = p.policy_bundle_version ?? {};
    console.log(`  policy_bundle  : djl=${pbv.djl ?? "—"}  prefilter=${pbv.prefilter ?? "—"}`);
  }
  console.log(`  contentHash    : ${ev.contentHash}`);
  console.log(`  seal method    : ${ev.seal?.method ?? "—"}`);
  console.log(`  sealedAt       : ${ev.sealedAt ?? "—"}`);
}

function printVerify(ev, hmacKey) {
  const v = verifyEvidence(ev, { hmacKey });
  console.log("\n── Verification ──");
  console.log(`  hash : ${v.hashOk ? "OK" : "FAIL"}`);
  console.log(`  HMAC : ${v.hmacOk === true ? "OK" : v.hmacOk === false ? "FAIL" : "skipped (no key)"}`);
  console.log(`  TSA  : ${v.tsaOk === true ? "OK (RFC 3161 · DigiCert)" : v.tsaOk === null ? "skipped (no TSA in payload)" : "FAIL"}`);
  return v;
}

export async function main(argv) {
  const args = argv.filter((a) => !a.startsWith("--"));
  if (args.length === 0 || argv.includes("--help") || argv.includes("-h")) {
    console.log(USAGE);
    return args.length === 0 ? 1 : 0;
  }
  const path = args[0];
  const raw = readFileSync(path, "utf8");
  const ev = JSON.parse(raw);
  const hmacKey = process.env.SYNTHEX_HMAC_KEY || "synthex-demo";

  printSummary(ev);
  if (ev.payload?.schema_version >= 2) printDecisionsTable(ev.payload.decisions ?? []);
  const v = printVerify(ev, hmacKey);
  return v.hashOk && v.hmacOk !== false ? 0 : 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then((code) => process.exit(code ?? 0)).catch((e) => {
    console.error("decode-evidence error:", e.message);
    process.exit(1);
  });
}
