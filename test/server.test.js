// Tests de las tools MCP de Synthex (sin arrancar el server stdio).
import { test } from "node:test";
import assert from "node:assert/strict";
import { tools } from "../src/tools.js";
import { buildEvidence } from "../src/prove/evidence-report.js";

test("tools: expone exactamente las 3 tools de Synthex", () => {
  assert.deepEqual(
    tools.map((t) => t.name).sort(),
    ["synthex_monitor", "synthex_scrape_classify_prove", "synthex_verify_evidence"]
  );
});

test("tools: cada una tiene name/description/parameters/execute", () => {
  for (const t of tools) {
    assert.equal(typeof t.name, "string");
    assert.ok(t.description.length > 10);
    assert.ok(t.parameters);
    assert.equal(typeof t.execute, "function");
  }
});

test("synthex_verify_evidence: verifica un evidence real (offline)", async () => {
  const ev = await buildEvidence({ target: "acme", findings: [] }, { hmacKey: "k", requestTsa: false });
  const tool = tools.find((t) => t.name === "synthex_verify_evidence");
  const out = JSON.parse(await tool.execute({ evidence: JSON.stringify(ev), hmacKey: "k" }));
  assert.equal(out.hashOk, true);
  assert.equal(out.hmacOk, true);
});

test("synthex_verify_evidence: detecta evidence manipulado", async () => {
  const ev = await buildEvidence({ a: 1 }, { hmacKey: "k", requestTsa: false });
  ev.payload.a = 999; // tamper
  const tool = tools.find((t) => t.name === "synthex_verify_evidence");
  const out = JSON.parse(await tool.execute({ evidence: JSON.stringify(ev), hmacKey: "k" }));
  assert.equal(out.hashOk, false);
});
