// Tests de cobertura DJL: cada rule_id matches positive y NO matches negative.
// Gate: cobertura >= 95% (74/78). Hard block: cualquier divergencia en severity >= 8.
// Escape hatch: SYNTHEX_ALLOW_SEV8_DIVERGENCE=1 (solo para debug, no para CI).
import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, RULES } from "../src/forge/djl.js";
import { RULE_FIXTURES } from "./djl-fixtures.js";

test("DJL coverage: cada regla matchea su positive y no matchea su negative (gate ≥95%)", () => {
  const ruleById = Object.fromEntries(RULES.map((r) => [r.id, r]));
  const divergences = [];
  const fixtureIds = Object.keys(RULE_FIXTURES);

  for (const ruleId of fixtureIds) {
    const rule = ruleById[ruleId];
    const fx = RULE_FIXTURES[ruleId];
    if (!rule) {
      divergences.push({ ruleId, kind: "missing_rule" });
      continue;
    }
    if (!rule.re.test(fx.positive)) {
      divergences.push({ ruleId, kind: "positive_miss", severity: rule.severity, fixture: fx.positive.slice(0, 80) });
    }
    if (rule.re.test(fx.negative)) {
      divergences.push({ ruleId, kind: "negative_fp", severity: rule.severity, fixture: fx.negative.slice(0, 80) });
    }
  }

  // Hard block: cualquier divergencia en severity >= 8 falla independiente del % global.
  const sev8 = divergences.filter((d) => (d.severity ?? 0) >= 8);
  if (sev8.length > 0 && process.env.SYNTHEX_ALLOW_SEV8_DIVERGENCE !== "1") {
    assert.fail(
      `HARD BLOCK: ${sev8.length} divergencias en severity>=8 (sin escape hatch):\n${JSON.stringify(sev8, null, 2)}`,
    );
  }

  // Test gate: paridad ≥ 95% (rule-level: una regla "diverge" si tiene CUALQUIER divergencia).
  const totalRules = fixtureIds.length;
  const divergedRules = new Set(divergences.map((d) => d.ruleId)).size;
  const passedRules = totalRules - divergedRules;
  const passRate = passedRules / totalRules;
  assert.ok(
    passRate >= 0.95,
    `Paridad ${(passRate * 100).toFixed(1)}% (${passedRules}/${totalRules}) < 95%.\nDivergencias:\n${JSON.stringify(divergences, null, 2)}`,
  );

  // Honesto: si hubo alguna divergencia (incluso si bajo el threshold), reportarlo en stdout.
  if (divergences.length > 0) {
    console.log(`  DJL parity divergences (under 95% threshold, no hard block):\n${JSON.stringify(divergences, null, 2)}`);
  }
});

test("DJL fixtures: todas las reglas tienen fixture (no missing, no extra)", () => {
  const ruleIds = new Set(RULES.map((r) => r.id));
  const fixtureIds = new Set(Object.keys(RULE_FIXTURES));
  const missing = [...ruleIds].filter((id) => !fixtureIds.has(id));
  const extra = [...fixtureIds].filter((id) => !ruleIds.has(id));
  assert.deepEqual(missing, [], `Reglas sin fixture: ${missing.join(", ")}`);
  assert.deepEqual(extra, [], `Fixtures sin regla: ${extra.join(", ")}`);
  assert.equal(ruleIds.size, 78, "Esperaba 78 reglas DJL");
  assert.equal(fixtureIds.size, 78, "Esperaba 78 fixtures");
});

