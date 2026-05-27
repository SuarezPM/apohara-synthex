// Tests de MEMORY. MemoryStore (local) testeado con archivos temporales. Cognee = stub honesto.
import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmSync } from "node:fs";
import { MemoryStore, CogneeClient } from "../src/memory/index.js";

function tmpPath() { return join(tmpdir(), `synthex-mem-${Date.now()}-${Math.random().toString(36).slice(2)}.json`); }

test("memory: remember + recall por campos", () => {
  const path = tmpPath();
  try {
    const m = new MemoryStore({ path });
    m.remember({ target: "acme", lens: "gtm", evidenceHash: "h1" });
    m.remember({ target: "acme", lens: "security", evidenceHash: "h2" });
    m.remember({ target: "other", lens: "gtm", evidenceHash: "h3" });
    assert.equal(m.recall({ target: "acme" }).length, 2);
    assert.equal(m.recall({ lens: "gtm" }).length, 2);
    assert.equal(m.recall({ target: "acme", lens: "security" }).length, 1);
  } finally { rmSync(path, { force: true }); }
});

test("memory: persiste entre instancias", () => {
  const path = tmpPath();
  try {
    new MemoryStore({ path }).remember({ target: "x", v: 1 });
    assert.equal(new MemoryStore({ path }).all().length, 1);
  } finally { rmSync(path, { force: true }); }
});

test("cognee: cliente expone connect/cognify/search/close", () => {
  const c = new CogneeClient();
  for (const fn of ["connect", "cognify", "search", "close"]) {
    assert.equal(typeof c[fn], "function");
  }
});

test("cognee: conecta al MCP local y lista tools (requiere COGNEE_LIVE=1)", { skip: !process.env.COGNEE_LIVE }, async () => {
  const c = new CogneeClient();
  await c.connect();
  const tools = await c.listTools();
  assert.ok(Array.isArray(tools) && tools.length > 0, "el cognee MCP debe exponer tools");
  await c.close();
});
