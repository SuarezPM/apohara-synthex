// Unit tests para src/classify/tiers.js (T0.3 del PRD v0.6.0).
// Cubre los 3 tiers + override por opts.model + tier desconocido + default.
import { test } from "node:test";
import assert from "node:assert/strict";
import { MODEL_TIERS, DEFAULT_TIER, pickModel } from "../../src/classify/tiers.js";

test("MODEL_TIERS contiene exactamente free/oss/paid", () => {
  assert.deepEqual(Object.keys(MODEL_TIERS).sort(), ["free", "oss", "paid"]);
});

test("pickModel resuelve cada tier al modelo mapeado", () => {
  assert.equal(pickModel({ tier: "free" }), "nvidia/nemotron-nano-9b-v2");
  assert.equal(pickModel({ tier: "oss" }), "deepseek/deepseek-non-thinking-v3.2-exp");
  assert.equal(pickModel({ tier: "paid" }), "deepseek/deepseek-thinking-v3.2-exp");
});

test("pickModel sin args usa DEFAULT_TIER (oss)", () => {
  assert.equal(DEFAULT_TIER, "oss");
  assert.equal(pickModel(), MODEL_TIERS.oss);
  assert.equal(pickModel({}), MODEL_TIERS.oss);
});

test("opts.model explícito gana sobre tier (back-compat)", () => {
  assert.equal(pickModel({ model: "custom/model" }), "custom/model");
  assert.equal(pickModel({ model: "custom/model", tier: "free" }), "custom/model");
});

test("tier desconocido lanza con mensaje claro", () => {
  assert.throws(
    () => pickModel({ tier: "premium" }),
    /Unknown model tier "premium"/,
  );
});

test("MODEL_TIERS es Object.freeze (no se puede mutar)", () => {
  assert.throws(() => {
    MODEL_TIERS.free = "evil";
  }, TypeError);
});
