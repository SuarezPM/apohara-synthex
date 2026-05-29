// Coverage proof — every rule in src/forge/prefilter.js fires on its designed positive
// fixture in test/forge/prefilter-fixtures.js, and every negative fixture passes through
// without false-positives. Run by `npm test`; also drives the second corpus in
// `scripts/measure-coverage.mjs` (the first corpus is the Aegis 156-doc set which
// targets DJL; this corpus targets prefilter specifically).
import { test } from "node:test";
import assert from "node:assert/strict";
import { RULES, classify } from "../../src/forge/prefilter.js";
import { PREFILTER_FIXTURES } from "./prefilter-fixtures.js";

test("prefilter coverage: every rule has a positive + negative fixture", () => {
  const fixtureIds = new Set(Object.keys(PREFILTER_FIXTURES));
  const ruleIds = new Set(RULES.map((r) => r.id));
  for (const id of ruleIds) {
    assert.ok(fixtureIds.has(id), `missing fixture for rule ${id}`);
  }
  for (const id of fixtureIds) {
    assert.ok(ruleIds.has(id), `fixture ${id} has no matching rule`);
  }
  assert.equal(fixtureIds.size, ruleIds.size);
});

test("prefilter coverage: every rule fires on its positive fixture (100% rule coverage)", () => {
  const unfired = [];
  for (const rule of RULES) {
    const fixture = PREFILTER_FIXTURES[rule.id];
    const result = classify(fixture.positive);
    const matchedIds = new Set(result.matched.map((m) => m.id));
    if (!matchedIds.has(rule.id)) {
      unfired.push({ id: rule.id, fixture: fixture.positive.slice(0, 80), matched: [...matchedIds] });
    }
  }
  assert.equal(unfired.length, 0, `${unfired.length} rule(s) did not fire on their positive fixture: ${JSON.stringify(unfired, null, 2)}`);
});

test("prefilter coverage: every negative fixture passes through without a hit", () => {
  const falsePositives = [];
  for (const rule of RULES) {
    const fixture = PREFILTER_FIXTURES[rule.id];
    const result = classify(fixture.negative);
    if (result.matched.length > 0) {
      falsePositives.push({ rule: rule.id, negative: fixture.negative.slice(0, 80), matched: result.matched.map((m) => m.id) });
    }
  }
  assert.equal(falsePositives.length, 0, `${falsePositives.length} negative fixture(s) triggered a rule unexpectedly: ${JSON.stringify(falsePositives, null, 2)}`);
});

test("prefilter coverage: dedicated corpus achieves 100% rule fire rate (measured)", () => {
  // Same calculation as scripts/measure-coverage.mjs but scoped to the prefilter corpus.
  const fired = new Set();
  for (const { positive } of Object.values(PREFILTER_FIXTURES)) {
    for (const m of classify(positive).matched) fired.add(m.id);
  }
  const pct = +(100 * fired.size / RULES.length).toFixed(1);
  assert.equal(pct, 100, `expected 100% rule coverage on the prefilter dedicated corpus, got ${pct}% (${fired.size}/${RULES.length})`);
});
