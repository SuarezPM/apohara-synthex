// Tests de la síntesis de cierre del Evidence Report (2.6): "3 questions" + verdict de una línea,
// determinista a partir de findings + blocked + lens (cero LLM, recomputable por un verificador).
import { test } from "node:test";
import assert from "node:assert/strict";
import { synthesizeOutput } from "../../src/prove/output.js";

test("synthesizeOutput: exactamente 3 preguntas + verdict string", () => {
  const out = synthesizeOutput({
    lens: "security",
    blocked: [],
    findings: [
      { lens: "security", severity: 8, signals: ["leaked-creds"] },
      { lens: "security", severity: 5, signals: ["cve"] },
    ],
  });
  assert.equal(out.questions.length, 3);
  assert.ok(out.questions.every((q) => typeof q === "string" && q.length > 0));
  assert.equal(typeof out.verdict, "string");
  assert.match(out.verdict, /HIGH RISK/);
  assert.match(out.verdict, /8\/10/);
  assert.match(out.verdict, /leaked-creds/);
});

test("synthesizeOutput: determinista (mismas entradas → misma salida)", () => {
  const p = { lens: "finance", blocked: [{}], findings: [{ severity: 3, signals: ["x"] }] };
  assert.deepEqual(synthesizeOutput(p), synthesizeOutput(p));
});

test("synthesizeOutput: bandas LOW/MEDIUM/HIGH según maxSev", () => {
  assert.match(synthesizeOutput({ findings: [{ severity: 2, signals: [] }] }).verdict, /LOW RISK/);
  assert.match(synthesizeOutput({ findings: [{ severity: 5, signals: [] }] }).verdict, /MEDIUM RISK/);
  assert.match(synthesizeOutput({ findings: [{ severity: 9, signals: [] }] }).verdict, /HIGH RISK/);
});

test("synthesizeOutput: blocked>0 cambia la 2da pregunta", () => {
  const withBlock = synthesizeOutput({ findings: [{ severity: 5, signals: [] }], blocked: [{}, {}] });
  assert.match(withBlock.questions[1], /2 pre-LLM block/);
  const noBlock = synthesizeOutput({ findings: [{ severity: 5, signals: [] }], blocked: [] });
  assert.match(noBlock.questions[1], /escalation threshold/);
});

test("synthesizeOutput: trilens toma la severity máxima entre lentes", () => {
  const out = synthesizeOutput({
    findings: [{ trilens: { gtm: { severity: 3, signals: [] }, security: { severity: 9, signals: ["s"] } } }],
  });
  assert.match(out.verdict, /9\/10/);
});

test("synthesizeOutput: sin findings → LOW, 0 sources, sin throw", () => {
  const out = synthesizeOutput({ findings: [], blocked: [] });
  assert.equal(out.questions.length, 3);
  assert.match(out.verdict, /LOW RISK/);
  assert.match(out.verdict, /0 classified source/);
});
