// Control-FP discipline for the sealed 5-lens red-team — the adversarial analogue of the
// L2/L3 false-positive gate: how many lenses scream high-risk on a genuinely NEUTRAL document?
// The answer must be LOW. A routine vendor status page / product update carries no
// going-concern, no litigation, no customer concentration, no eroding moat, no key-person
// dependency — so the lenses should NOT trip, the aggregate must NOT be "DO NOT PROCEED",
// and at most one lens may mildly flag.
//
// ZERO network: we inject a deterministic, CONTENT-DERIVED runner (no live deepseek). The
// runner is honest — it does not hardcode risk 0; it derives each lens's risk from whether
// the lens's own adversarial-trigger keywords actually appear in the document the model saw.
// On the neutral control there are no triggers, so risk stays low BECAUSE the doc is neutral.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { redTeam } from "../../src/redteam/index.js";

const CONTROL = JSON.parse(
  readFileSync(new URL("../fixtures/redteam-benign-control.json", import.meta.url), "utf8"),
);

// Each lens's adversarial-trigger lexicon. A neutral document hits NONE of these, so the
// content-derived runner returns low risk for every lens — the LOW verdict emerges from the
// document, not from a fabricated constant. (The same runner WOULD raise risk on an S-1 with
// "going-concern", "lawsuit", etc. — proven by the positive-control test below.)
const LENS_TRIGGERS = Object.freeze({
  CFO: ["going-concern", "going concern", "net loss", "burn rate", "accumulated deficit", "dilution", "default on", "covenant breach"],
  Market: ["customer concentration", "largest customers accounted", "demand collapse", "losing market share", "pricing power eroding"],
  Legal: ["lawsuit", "litigation", "infringement", "injunction", "regulatory investigation", "non-compliance", "subpoena"],
  Competitor: ["eroding moat", "no differentiation", "incumbents bundling", "commoditized", "switching costs are low"],
  Execution: ["key-person", "founder departure", "missed deliverables", "high attrition", "supply shortage", "cannot scale"],
});

// Deterministic, content-derived per-lens runner. risk = base(no signal) + 18 per trigger hit,
// clamped to [0,100]. Concerns are SHORT and grounded (we echo the matched trigger phrase, which
// is present in the document, so the grounding verifier keeps non-figure signals as-is).
function makeContentRunner(text) {
  const lower = String(text ?? "").toLowerCase();
  return async ({ persona }) => {
    const triggers = LENS_TRIGGERS[persona] ?? [];
    const hits = triggers.filter((t) => lower.includes(t));
    const risk = Math.max(0, Math.min(100, 8 + hits.length * 18));
    return JSON.stringify({
      risk,
      concerns: hits.map((h) => `${persona}: ${h}`),
      rationale: hits.length ? "STUB: adversarial signal present." : "STUB: no adversarial signal in the document.",
    });
  };
}

const HIGH_RISK = 60; // a lens "screams high-risk" at/above this (matches index.js HIGH band start)

test("control-FP: neutral document → verdict is NOT 'DO NOT PROCEED' (offline, zero network)", async () => {
  const runner = makeContentRunner(CONTROL.text);
  const r = await redTeam(CONTROL.text, { runner });

  assert.equal(r.perLens.length, 5, "all 5 lenses run");
  assert.equal(r.degraded, false, "not degraded — the runner answered every lens");
  assert.notEqual(r.verdict, "DO NOT PROCEED", "a neutral doc must NOT aggregate to DO NOT PROCEED");
  assert.ok(["PROCEED", "CAUTION"].includes(r.verdict), `verdict in {PROCEED,CAUTION}, got ${r.verdict}`);
});

test("control-FP: few/no lenses return high risk on the neutral control (FP discipline)", async () => {
  const runner = makeContentRunner(CONTROL.text);
  const r = await redTeam(CONTROL.text, { runner });

  const highRiskLenses = r.perLens.filter((l) => l.risk >= HIGH_RISK);
  const maxAllowed = CONTROL.expected.max_high_risk_lenses; // 1
  assert.ok(
    highRiskLenses.length <= maxAllowed,
    `at most ${maxAllowed} lens may scream high-risk on neutral content; got ${highRiskLenses.length} (${highRiskLenses.map((l) => `${l.persona}=${l.risk}`).join(", ")})`,
  );
  // On THIS control the document trips zero triggers → every lens stays at the low base.
  assert.equal(highRiskLenses.length, 0, "this control trips no adversarial lens");
  assert.ok(r.score < 40, `aggregate score must land in the LOW band (<40), got ${r.score}`);
  assert.equal(r.band, "LOW");
});

test("control-FP: each lens is still sealed (REDTEAM_*) + grounded — discipline, not silence", async () => {
  const runner = makeContentRunner(CONTROL.text);
  const r = await redTeam(CONTROL.text, { runner });

  assert.deepEqual(
    r.perLens.map((l) => l.stage).sort(),
    ["REDTEAM_CFO", "REDTEAM_Competitor", "REDTEAM_Execution", "REDTEAM_Legal", "REDTEAM_Market"],
  );
  assert.ok(r.perLens.every((l) => typeof l.model_id === "string" && l.model_id.length > 0));
  assert.ok(r.perLens.every((l) => typeof l.grounding === "string"));
  assert.ok(r.topQuestions.length <= 3);
});

// Positive control: the SAME content-derived runner is not blind — feed it a document that
// genuinely contains adversarial signal and at least one lens screams high-risk. This proves
// the neutral-control LOW verdict is a property of the DOCUMENT, not of a runner that always
// returns 0 (which would make the FP test vacuous).
test("control-FP: runner is not blind — an adversarial doc DOES trip a lens (sanity)", async () => {
  const adversarial =
    "The auditor disclosed substantial going-concern doubt. A pending patent-infringement lawsuit " +
    "seeks an injunction. The two largest customers accounted for 41% of revenue, and incumbents " +
    "bundling competing features have left the moat eroding. The company depends on a single key-person.";
  const runner = makeContentRunner(adversarial);
  const r = await redTeam(adversarial, { runner });

  const highRiskLenses = r.perLens.filter((l) => l.risk >= HIGH_RISK);
  assert.ok(highRiskLenses.length >= 1, "an adversarial document must trip at least one lens (runner is content-aware)");
});
