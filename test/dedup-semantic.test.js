// Tests del dedup semántico OPT-IN. La vía por defecto (exact, SHA-256) NO debe cambiar de
// comportamiento (no-regresión lossless). La vía semántica se verifica GATED (SEMANTIC_LIVE=1)
// porque descarga el modelo all-MiniLM-L6-v2 en el primer uso (~25 MB). El test de seguridad de
// deploy (api/ jamás importa @xenova) corre SIEMPRE.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { dedupe } from "../src/forge/dedup.js";

const __dir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dir, "..");

const ITEMS = [
  { url: "a", content: "El competidor recortó su plan Pro de 99 a 79 al mes." },
  { url: "b", content: "El competidor recortó su plan Pro de 99 a 79 al mes." }, // exacto-duplicado de a
  { url: "c", content: "Está contratando 8 ejecutivos de ventas enterprise en EMEA." },
];

test("dedup-semantic: no-regresión — dedupe(items) sin opts == dedupe(items,{mode:'exact'})", () => {
  const plain = dedupe(ITEMS);
  const explicit = dedupe(ITEMS, { mode: "exact" });
  assert.deepEqual(plain, explicit); // byte-idéntico: la firma nueva no altera el default
  assert.equal(plain.stats.uniqueBlocks, 2);
  assert.equal(plain.stats.duplicateBlocks, 1); // a≡b exacto
  assert.equal(plain.stats.mode, undefined); // exact no etiqueta mode (shape histórico intacto)
});

test("dedup-semantic: dedupe() rechaza mode no soportado con error claro (semantic es async)", () => {
  assert.throws(() => dedupe(ITEMS, { mode: "semantic" }), /dedupeSemantic/);
});

test("dedup-semantic: SEGURIDAD deploy — ningún archivo en api/ importa @xenova ni dedup-semantic", () => {
  const apiDir = join(repoRoot, "api");
  const offenders = [];
  for (const f of readdirSync(apiDir)) {
    if (!f.endsWith(".js") && !f.endsWith(".mjs")) continue;
    const src = readFileSync(join(apiDir, f), "utf8");
    if (/@xenova|transformers|dedup-semantic/.test(src)) offenders.push(f);
  }
  assert.deepEqual(offenders, [], `api/ debe estar libre de transformers (bundle serverless limpio); ofensores: ${offenders}`);
});

// --- Integración semántica REAL (gated): descarga el modelo, corre inferencia. ---
test("dedup-semantic LIVE: agrupa near-dups (paráfrasis) y separa lo distinto", { skip: process.env.SEMANTIC_LIVE !== "1" }, async () => {
  const { dedupeSemantic } = await import("../src/forge/dedup-semantic.js");
  const docs = [
    { url: "p1", content: "El competidor bajó el precio del plan Pro a 79 dólares mensuales." },
    { url: "p2", content: "El plan Pro del competidor ahora cuesta 79 USD al mes tras un recorte." }, // paráfrasis de p1
    { url: "q1", content: "La empresa contrató ocho ejecutivos de ventas enterprise en la región EMEA." }, // distinto
  ];
  const r = await dedupeSemantic(docs, { threshold: 0.7 });
  assert.equal(r.stats.mode, "semantic");
  assert.ok(r.stats.duplicateBlocks >= 1, `esperaba clustering de la paráfrasis, got ${JSON.stringify(r.stats)}`);
  assert.ok(r.unique.some((d) => d.url === "q1"), "el doc distinto (q1) debe quedar como único");
});
