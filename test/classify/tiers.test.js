import { test } from "node:test";
import assert from "node:assert/strict";
import { pickModel, MODEL_TIERS, DEFAULT_TIER } from "../../src/classify/tiers.js";

// v1.0.0 (item 1.4): DeepSeek V4 family, Nemotron removed.
// flash = default/bulk · pro = spot/council. Smoke-gated by scripts/probe-aiml-models.mjs.

test("pickModel sin opts → tier por defecto (flash → deepseek-v4-flash)", () => {
  assert.equal(pickModel(), MODEL_TIERS[DEFAULT_TIER]);
  assert.equal(pickModel({}), "deepseek/deepseek-v4-flash");
});

test("pickModel: opts.model explícito gana sobre tier (back-compat)", () => {
  assert.equal(pickModel({ model: "custom/model-x", tier: "pro" }), "custom/model-x");
});

test("pickModel: tier flash → deepseek-v4-flash", () => {
  assert.equal(pickModel({ tier: "flash" }), "deepseek/deepseek-v4-flash");
});

test("pickModel: tier pro → deepseek-v4-pro (spot/council)", () => {
  assert.equal(pickModel({ tier: "pro" }), "deepseek/deepseek-v4-pro");
});

test("pickModel: tier desconocido lanza (no falla silente a otro tier)", () => {
  assert.throws(() => pickModel({ tier: "free" }), /Unknown model tier/);
  assert.throws(() => pickModel({ tier: "oss" }), /Unknown model tier/);
});

test("MODEL_TIERS no menciona nemotron y está congelado", () => {
  assert.ok(Object.isFrozen(MODEL_TIERS));
  assert.equal(JSON.stringify(MODEL_TIERS).toLowerCase().includes("nemotron"), false);
  assert.deepEqual(Object.keys(MODEL_TIERS), ["flash", "pro"]);
});
