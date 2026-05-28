// Test del parser argv del CLI (bin/synthex.mjs). El parser es puro → testeable sin correr el pipeline.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseArgs } from "../bin/synthex.mjs";

test("cli parseArgs: --demo boolean + lente posicional", () => {
  assert.deepEqual(parseArgs(["--demo"]), { positional: [], flags: { demo: true } });
  assert.deepEqual(parseArgs(["--demo", "finance"]), { positional: ["finance"], flags: { demo: true } });
});

test("cli parseArgs: target + lente + --dedup=semantic", () => {
  const { positional, flags } = parseArgs(["https://example.com", "security", "--dedup=semantic"]);
  assert.deepEqual(positional, ["https://example.com", "security"]);
  assert.equal(flags.dedup, "semantic");
});

test("cli parseArgs: --key=value parsea el valor; --flag sin = es true", () => {
  const { flags } = parseArgs(["--dedup=exact", "--help"]);
  assert.equal(flags.dedup, "exact");
  assert.equal(flags.help, true);
});

test("cli parseArgs: sin args → vacío", () => {
  assert.deepEqual(parseArgs([]), { positional: [], flags: {} });
});
