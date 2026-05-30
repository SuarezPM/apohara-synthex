// Tests de los adapters LangChain / CrewAI (item 3.3) — wrappers framework-shaped sobre el
// pipeline. Offline: fetcher + classifier inyectados vía pipelineOpts (sin red).
import { test } from "node:test";
import assert from "node:assert/strict";
import { synthexLangChainTool, SYNTHEX_TOOL_NAME } from "../../adapters/langchain.js";
import { synthexCrewaiTool } from "../../adapters/crewai.js";

const pipelineOpts = {
  requestTsa: false,
  fetcher: async () => [{ url: "https://acme.example", content: "Competitor cut prices 20%." }],
  classifier: async (text, lens) => ({ lens, severity: 7, summary: "s", signals: ["price-cut"] }),
};

test("langchain: tool config tiene name/description/schema/func y sella evidencia", async () => {
  const tool = synthexLangChainTool({ pipelineOpts });
  assert.equal(tool.name, SYNTHEX_TOOL_NAME);
  assert.equal(typeof tool.description, "string");
  assert.equal(tool.schema.required[0], "target");
  assert.equal(typeof tool.func, "function");
  const out = JSON.parse(await tool.func({ target: "acme", lens: "gtm" }));
  assert.equal(typeof out.contentHash, "string");
  assert.ok(out.contentHash.length === 64, "contentHash sha256");
  assert.equal(typeof out.verdict, "string");
  assert.match(out.sealed, /HMAC-SHA256/);
  assert.equal(out.findings, 1);
});

test("crewai: tool def tiene name/args_schema/run y sella evidencia", async () => {
  const tool = synthexCrewaiTool({ pipelineOpts });
  assert.equal(tool.name, SYNTHEX_TOOL_NAME);
  assert.equal(tool.args_schema.required[0], "target");
  const out = await tool.run({ target: "acme", lens: "security" });
  assert.equal(typeof out.contentHash, "string");
  assert.equal(typeof out.verdict, "string");
  assert.match(out.sealed, /HMAC-SHA256/);
});

test("adapters: pipeline inyectable (no toca red)", async () => {
  let called = null;
  const fakePipeline = async (target, opts) => { called = { target, lens: opts.lens }; return { contentHash: "h", payload: { verdict: "LOW RISK", findings: [] }, seal: { method: "HMAC-SHA256" } }; };
  const tool = synthexLangChainTool({ pipeline: fakePipeline });
  await tool.func({ target: "x", lens: "finance" });
  assert.deepEqual(called, { target: "x", lens: "finance" });
});
