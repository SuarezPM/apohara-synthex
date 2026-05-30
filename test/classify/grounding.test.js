// Tests del grounding verifier — puro JS, sin red. Verifica cifras nombradas contra
// la ventana [0,charsSeen) que el LLM vio: dentro → VERIFIED, sólo más allá → UNVERIFIED,
// en ningún lado → DROPPED. Señales sin cifra pasan sin tocar (conservador).
import { test } from "node:test";
import assert from "node:assert/strict";
import { ground, extractFigures } from "../../src/classify/grounding.js";

test("extractFigures: normaliza monedas/escalas/% a tokens canónicos", () => {
  assert.ok(extractFigures("$1,500,000 raised").has("1500000"));
  assert.ok(extractFigures("1.5M ARR").has("1500000"));     // 1.5M == 1,500,000
  assert.ok(extractFigures("$42 BILLION acquisition").has("42000000000"));
  assert.ok(extractFigures("grew 20%").has("20%"));
  assert.ok(extractFigures("10k API calls").has("10000"));
  assert.equal(extractFigures("no numbers here at all").size, 0);
});

test("extractFigures: $1,500,000 y 1.5M producen el MISMO token (number-normalization)", () => {
  const a = extractFigures("$1,500,000");
  const b = extractFigures("1.5M");
  assert.ok([...a].some((t) => b.has(t)), "deben compartir el token canónico 1500000");
});

test("ground: cifra presente en la ventana → VERIFIED (señal conservada)", () => {
  const r = ground(
    { lens: "gtm", severity: 7, summary: "s", signals: ["price cut to $79", "10k API calls"] },
    "Competitor X cut its Pro plan to $79/mo and launched a free tier with 10k API calls.",
    { charsSeen: 100 },
  );
  assert.equal(r.outcome, "VERIFIED");
  assert.equal(r.counts.dropped, 0);
  assert.ok(r.signals.includes("10k API calls"));
});

test("ground: cifra inventada (en ningún lado del source) → DROPPED del finding", () => {
  const r = ground(
    { lens: "finance", severity: 8, summary: "s", signals: ["$999 BILLION fabricated number"] },
    "the page says nothing about money",
    { charsSeen: 32 },
  );
  assert.equal(r.outcome, "DROPPED");
  assert.equal(r.counts.dropped, 1);
  assert.equal(r.signals.length, 0, "la señal fabricada se elimina del finding");
  assert.ok(r.droppedSignals.includes("$999 BILLION fabricated number"));
});

test("ground (M3): cifra resoluble SOLO más allá de charsSeen → UNVERIFIED (NO VERIFIED)", () => {
  const src = "x".repeat(8100) + " acquired for $42 BILLION";
  const r = ground(
    { lens: "finance", severity: 5, summary: "s", signals: ["$42 BILLION acquisition"] },
    src,
    { charsSeen: 8000 },
  );
  // El AC del plan: (r.signals||[]).some(s=>s.unverified===true) || r.outcome==="UNVERIFIED"
  assert.equal(r.outcome, "UNVERIFIED");
  assert.equal(r.counts.unverified, 1);
  assert.equal(r.counts.verified, 0);
  assert.ok(r.unverifiedSignals.includes("$42 BILLION acquisition"));
  // la señal se conserva (no se dropea) pero queda marcada como no-verificada en la fila sellada
  assert.ok(r.signals.includes("$42 BILLION acquisition"));
});

test("ground: señales sin cifra pasan sin tocar (no se dropean paráfrasis válidas)", () => {
  const r = ground(
    { lens: "gtm", severity: 6, summary: "s", signals: ["hiring", "enterprise-sales", "EMEA"] },
    "Competitor X is hiring enterprise account executives across EMEA.",
    { charsSeen: 100 },
  );
  assert.equal(r.adjudicated, 0, "ninguna señal tiene cifra → nada que adjudicar");
  assert.deepEqual(r.signals, ["hiring", "enterprise-sales", "EMEA"], "se conservan tal cual");
  assert.equal(r.outcome, "VERIFIED");
});

test("ground: charsSeen sellado refleja la frontera de verificación", () => {
  const r = ground({ signals: [] }, "abc", {});
  assert.equal(r.charsSeen, 3, "sin charsSeen explícito usa min(len, 8000)");
  const r2 = ground({ signals: [] }, "x".repeat(20000), {});
  assert.equal(r2.charsSeen, 8000, "se capea a la ventana del LLM (8000)");
});
