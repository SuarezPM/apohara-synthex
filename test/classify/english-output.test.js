// Regression: the classifier system prompts MUST force English-only output and carry NO
// Spanish placeholders. Bug: Spanish-heavy scraped content made some lenses answer in Spanish.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildClassifySystem, buildBatchedSystem, LENSES } from "../../src/classify/aiml-client.js";

const NONCE = "test-nonce-1234";

test("single-lens system prompt enforces English-only output", () => {
  const s = buildClassifySystem("security", LENSES.security, NONCE);
  assert.match(s, /ENGLISH ONLY/, "must explicitly demand English");
  assert.match(s, /<1-2 sentences>/, "summary placeholder is English");
  assert.doesNotMatch(s, /frases|señal|Devolvé|Sos un/i, "no Spanish prompt text or placeholders");
  assert.match(s, new RegExp(NONCE), "binds the spotlight nonce");
});

test("batched system prompt enforces English-only output for every lens", () => {
  const lenses = Object.keys(LENSES);
  const s = buildBatchedSystem(lenses, NONCE);
  assert.match(s, /ENGLISH ONLY/);
  assert.match(s, /<1-2 sentences>/);
  assert.doesNotMatch(s, /frases|señal|Devolvé|Analizá/i, "no Spanish prompt text or placeholders");
  for (const l of lenses) assert.ok(s.includes(`"${l}"`), `lens ${l} is present in the shape`);
});
