// Tests de paridad DJL vs fixtures Aegis (Commit D Synthex v4).
// Para cada rule_id en RULE_FIXTURES: evaluate(positive) MUST match, evaluate(negative) MUST NOT match.
// Test gate: paridad >= 95% (74/78). Hard block: cualquier divergencia en severity >= 8.
// Escape hatch: SYNTHEX_ALLOW_SEV8_DIVERGENCE=1 (solo para debug, no para CI).
//
// T4 AC#N4: assert mecánico que el sha pin del header djl.js === header djl-fixtures.js
// (anti-drift estructural — fail fast si alguien actualiza uno sin el otro).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { evaluate, RULES } from "../src/forge/djl.js";
import { RULE_FIXTURES } from "./djl-fixtures.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

test("DJL parity: cada regla matchea su positive y no matchea su negative (gate ≥95%)", () => {
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

test("T4 AC#N4: sha pin del header djl.js === sha pin del header djl-fixtures.js", () => {
  const djlSrc = readFileSync(join(__dirname, "..", "src", "forge", "djl.js"), "utf8");
  const fixSrc = readFileSync(join(__dirname, "djl-fixtures.js"), "utf8");
  const re = /@\s*([a-f0-9]{40})\b/;
  const djlSha = djlSrc.match(re)?.[1];
  const fixSha = fixSrc.match(re)?.[1];
  assert.ok(djlSha, "djl.js sin sha pin SHA-1/SHA-256 de 40 chars en header");
  assert.ok(fixSha, "djl-fixtures.js sin sha pin SHA-1/SHA-256 de 40 chars en header");
  assert.strictEqual(djlSha, fixSha, `Sha pin drift: djl.js=${djlSha} vs djl-fixtures.js=${fixSha}`);
});
