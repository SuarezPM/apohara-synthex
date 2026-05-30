// Tests de las 5 lentes adversariales (prompt-diversity, no model-diversity).
import { test } from "node:test";
import assert from "node:assert/strict";
import { PERSONAS, parsePersonaVerdict } from "../../src/redteam/personas.js";

test("personas: exactamente 5 lentes con keys esperadas", () => {
  assert.equal(PERSONAS.length, 5);
  assert.deepEqual(PERSONAS.map((p) => p.key).sort(), ["CFO", "Competitor", "Execution", "Legal", "Market"]);
  assert.ok(PERSONAS.every((p) => typeof p.system === "string" && p.system.length > 40));
});

test("parsePersonaVerdict: JSON válido → {risk clampado, concerns[], rationale}", () => {
  const v = parsePersonaVerdict('{"risk":85,"concerns":["going concern","$61.4M loss"],"rationale":"bad"}');
  assert.equal(v.risk, 85);
  assert.deepEqual(v.concerns, ["going concern", "$61.4M loss"]);
  assert.equal(v.rationale, "bad");
});

test("parsePersonaVerdict: risk se clampa a [0,100], basura → 0 / []", () => {
  assert.equal(parsePersonaVerdict('{"risk":200}').risk, 100);
  assert.equal(parsePersonaVerdict('{"risk":-5}').risk, 0);
  assert.equal(parsePersonaVerdict("not json").risk, 0);
  assert.deepEqual(parsePersonaVerdict("{}").concerns, []);
});

test("parsePersonaVerdict: concerns no-string se filtran, máx 5", () => {
  const v = parsePersonaVerdict('{"risk":10,"concerns":["a",2,null,"b","c","d","e","f"]}');
  assert.deepEqual(v.concerns, ["a", "b", "c", "d", "e"]);
});
