// Tests del gate INV-15 (prior-art, no cableado al pipeline). `node --test`.
// INV-15 gate tests (prior art, not wired into the pipeline).
import { test } from "node:test";
import assert from "node:assert/strict";
import { computeJcrRisk, shouldUseDensePrefill } from "../../experimental/inv15-gate.js";

test("inv15: judge con 9 candidatos y shuffle => riesgo alto + dense prefill", () => {
  const risk = computeJcrRisk({ role: "judge", candidateCount: 9, reuseRate: 0, layoutShuffled: true });
  assert.ok(risk > 0.7, `risk=${risk}`);
  assert.equal(shouldUseDensePrefill("judge", risk), true);
});

test("inv15: usuario normal => riesgo bajo, sin dense prefill", () => {
  const risk = computeJcrRisk({ role: "user", candidateCount: 1 });
  assert.ok(risk < 0.7, `risk=${risk}`);
  assert.equal(shouldUseDensePrefill("user", risk), false);
});
