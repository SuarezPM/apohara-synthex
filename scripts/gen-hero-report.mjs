// Reproducibly regenerate the canonical HERO Evidence Report PDF from the COMMITTED sidecars, so the
// C2PA + Rekor seal rows are LOAD-BEARING in every build — not an ad-hoc one-off.
//
// The known gap this closes (P0.1): buildPDFReport() present-gates the Rekor + C2PA rows on
// opts.c2paSidecar / opts.rekorBundle, but no committed caller passed them — so a fresh reproducible
// build dropped both rows silently and the verify page fell to the "not present" branch. This script
// is that caller, committed.
//
// Inputs (all committed under samples/): the full-seal evidence + the C2PA sidecar + the Rekor anchor.
//   node scripts/gen-hero-report.mjs   → samples/synthex-hero-report.pdf
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { buildPDFReport } from "../src/prove/pdf-report.js";
import { sealRows, rekorLogIndex } from "../src/prove/report/components.js";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const samples = join(repoRoot, "samples");
const read = (f) => JSON.parse(readFileSync(join(samples, f), "utf8"));

const evidence = read("synthex-hero-evidence.json");
const c2paSidecar = read("synthex-hero.c2pa.json");
const rekorBundle = read("synthex-hero-rekor-anchor.json");

// Guard: the hero MUST carry the real asymmetric seal, or the rows we surface would be empty theatre.
if (!evidence?.seal?.signature) {
  console.error("✗ hero evidence has no Ed25519 signature — refusing to write a hero without the real seal");
  process.exit(1);
}

const pdf = await buildPDFReport(evidence, { c2paSidecar, rekorBundle });
writeFileSync(join(samples, "synthex-hero-report.pdf"), pdf);

// Echo exactly what the seal block surfaces, so an operator/CI sees the rows are present, not dark.
// (PDFKit subset-CID fonts make grepping the PDF useless — assert on sealRows() in-process instead.)
const rows = sealRows({ seal: evidence.seal, contentHash: evidence.contentHash, c2paSidecar, rekorBundle });
const labels = rows.map((r) => r[0]).filter(Boolean);
const logIndex = rekorLogIndex(rekorBundle);
console.log(`✓ samples/synthex-hero-report.pdf (${pdf.length} bytes)`);
console.log(`  seal rows: ${labels.join(" · ")}`);
console.log(`  Rekor logIndex: ${logIndex} · C2PA sidecar: ${c2paSidecar ? "present" : "ABSENT"}`);

if (logIndex == null || !c2paSidecar) {
  console.error("✗ Rekor or C2PA row would be DARK — the hero is not surfacing the full seal");
  process.exit(1);
}
