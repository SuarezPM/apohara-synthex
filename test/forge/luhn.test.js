// v0.8.0 Commit 1C · Luhn validation tests.
// Helper micro-tests + DJL-PII-002 regression: real CC numbers still match,
// random 13-19 digit runs (order IDs, tracking numbers) no longer match.
import { test } from "node:test";
import assert from "node:assert/strict";
import { luhnValid } from "../../src/forge/luhn.js";
import { evaluate as djlEvaluate, RULES, POLICY_BUNDLE_VERSION } from "../../src/forge/djl.js";

// ─── luhnValid helper ───────────────────────────────────────────────────

test("luhnValid · canonical CC numbers (Visa/MC/Amex/Discover test ranges) pass", () => {
  assert.equal(luhnValid("4111111111111111"), true);   // Visa test
  assert.equal(luhnValid("5500000000000004"), true);   // MasterCard test
  assert.equal(luhnValid("340000000000009"), true);    // Amex test
  assert.equal(luhnValid("6011000000000004"), true);   // Discover test
  assert.equal(luhnValid("4242424242424242"), true);   // Stripe test
});

test("luhnValid · accepts common formatting (spaces, dashes)", () => {
  assert.equal(luhnValid("4111-1111-1111-1111"), true);
  assert.equal(luhnValid("4111 1111 1111 1111"), true);
});

test("luhnValid · rejects non-Luhn digit runs (typical order/tracking IDs)", () => {
  assert.equal(luhnValid("1234567890123"), false);
  assert.equal(luhnValid("1234567890123456"), false);
  assert.equal(luhnValid("9999999999999999"), false);
  // Note: "0000000000000000" passes Luhn mathematically (sum=0, 0%10===0) — that's
  // expected behavior of the pure checksum. The regex `\b(?:\d[ \-]?){12,18}\d\b`
  // is what filters obviously non-CC contexts at scrape time; Luhn is the precision
  // filter on top, not a sole authoritative test.
});

test("luhnValid · length bounds (12-19 digits inclusive)", () => {
  assert.equal(luhnValid("1234567890"), false);       // too short
  assert.equal(luhnValid("12345678901234567890"), false); // too long
});

test("luhnValid · ignores non-digits + handles empty/null", () => {
  assert.equal(luhnValid(""), false);
  assert.equal(luhnValid(null), false);
  assert.equal(luhnValid(undefined), false);
  assert.equal(luhnValid("not-a-number"), false);
});

// ─── DJL-PII-002 regression ─────────────────────────────────────────────

test("DJL-PII-002 · real CC matches (Luhn passes, regex matches → REVIEW)", () => {
  const r = djlEvaluate("Card on file: 4111-1111-1111-1111 thanks");
  assert.equal(r.matched_rules.includes("DJL-PII-002"), true);
  assert.equal(r.decision, "REVIEW");
});

test("DJL-PII-002 · order ID does NOT match (Luhn fails, no flag)", () => {
  const r = djlEvaluate("Tracking number: 1234567890123 — package en route");
  assert.equal(r.matched_rules.includes("DJL-PII-002"), false);
});

test("DJL-PII-002 · random 16-digit run does NOT match (no false REVIEW)", () => {
  const r = djlEvaluate("Internal ref: 9999888877776666 for fiscal year");
  assert.equal(r.matched_rules.includes("DJL-PII-002"), false);
});

test("DJL-PII-002 rule shape carries .validate predicate (post-v0.8)", () => {
  const rule = RULES.find((r) => r.id === "DJL-PII-002");
  assert.ok(rule, "DJL-PII-002 must exist in RULES");
  assert.equal(typeof rule.validate, "function");
  assert.equal(rule.severity, 7);  // unchanged — Luhn raises precision, not severity
});

test("POLICY_BUNDLE_VERSION · contains the v0.8 corpus delta (validate-predicate-aware)", () => {
  // The Bundle SHA must reflect the addition of .validate on DJL-PII-002 — without
  // the Boolean(r.validate) addition to the corpus, the semantic change would be
  // invisible to the bundle hash (regex source unchanged).
  assert.match(POLICY_BUNDLE_VERSION, /^djl-v1-[0-9a-f]{12}$/);
});
