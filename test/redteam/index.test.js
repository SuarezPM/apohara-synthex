// Tests del orquestador red-team — runner INYECTADO (cero red). Verifica: 5 lentes selladas
// (stage REDTEAM_*), agregación → verdict, grounding por-lente (cifra fabricada → DROPPED),
// y degradación fail-safe (una lente caída no infla el verdict).
import { test } from "node:test";
import assert from "node:assert/strict";
import { redTeam } from "../../src/redteam/index.js";

const SRC = "Revenue was $48.2 million in 2025 with a net loss of $61.4 million. Going-concern doubt disclosed.";

test("redTeam: 5 lentes selladas (REDTEAM_*) + verdict agregado + cada lente sella model_id", async () => {
  // runner inyectado: riesgo alto por lente → verdict DO NOT PROCEED / CAUTION.
  const runner = async ({ persona }) =>
    JSON.stringify({ risk: 75, concerns: [`${persona}: going concern`], rationale: "r" });
  const r = await redTeam(SRC, { runner });
  assert.equal(r.perLens.length, 5);
  assert.deepEqual(r.perLens.map((l) => l.stage).sort(), ["REDTEAM_CFO", "REDTEAM_Competitor", "REDTEAM_Execution", "REDTEAM_Legal", "REDTEAM_Market"]);
  assert.ok(r.perLens.every((l) => typeof l.model_id === "string"));
  assert.ok(["PROCEED", "CAUTION", "DO NOT PROCEED"].includes(r.verdict));
  assert.equal(r.verdict, "DO NOT PROCEED"); // todas risk 75 → score 75 → DO NOT PROCEED
  assert.equal(r.band, "HIGH");
  assert.ok(r.topQuestions.length <= 3);
});

test("redTeam: grounding por-lente DROPEA una cifra fabricada", async () => {
  // El concern cita una cifra que NO está en el source → grounding la dropea.
  const runner = async ({ persona }) =>
    JSON.stringify({ risk: 40, concerns: persona === "CFO" ? ["$999 BILLION fabricated loss"] : ["going concern"], rationale: "r" });
  const r = await redTeam(SRC, { runner });
  const cfo = r.perLens.find((l) => l.persona === "CFO");
  assert.ok(cfo.droppedConcerns.includes("$999 BILLION fabricated loss"), "la cifra fabricada se dropea");
  assert.ok(!cfo.concerns.includes("$999 BILLION fabricated loss"));
});

test("redTeam: grounding CONSERVA una cifra presente en el source", async () => {
  const runner = async ({ persona }) =>
    JSON.stringify({ risk: 50, concerns: persona === "CFO" ? ["net loss of $61.4 million"] : [], rationale: "r" });
  const r = await redTeam(SRC, { runner });
  const cfo = r.perLens.find((l) => l.persona === "CFO");
  assert.ok(cfo.concerns.includes("net loss of $61.4 million"), "la cifra presente se conserva (VERIFIED)");
});

test("redTeam: una lente caída (runner lanza) degrada a risk 0, no rompe ni infla", async () => {
  let n = 0;
  const runner = async ({ persona }) => {
    n++;
    if (persona === "Legal") throw new Error("model down");
    return JSON.stringify({ risk: 30, concerns: [], rationale: "r" });
  };
  const r = await redTeam(SRC, { runner });
  const legal = r.perLens.find((l) => l.persona === "Legal");
  assert.equal(legal.degraded, true);
  assert.equal(legal.risk, 0);
  assert.equal(n, 5, "las 5 lentes se ejecutan");
  assert.equal(r.degraded, false, "no TODAS degradadas → el verdict sigue válido");
});

test("redTeam: TODAS las lentes caídas → degraded:true, verdict PROCEED (risk 0)", async () => {
  const runner = async () => { throw new Error("all down"); };
  const r = await redTeam(SRC, { runner });
  assert.equal(r.degraded, true);
  assert.equal(r.score, 0);
  assert.equal(r.verdict, "PROCEED");
});
