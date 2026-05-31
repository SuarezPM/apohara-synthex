// CrewAI adapter — sealed-evidence summary contract (item 3.3).
//
// CrewAI-shaped tool definition over the pipeline. With an INJECTED pipeline (zero network,
// no real crypto/TSA) we assert it returns the sealed-evidence summary object
// (contentHash + verdict + seal method) and is fail-safe on failure / degraded inputs.
// Unlike the LangChain adapter, `run` returns the summary as an object (not stringified).
import { test } from "node:test";
import assert from "node:assert/strict";
import { synthexCrewaiTool } from "../../adapters/crewai.js";
// Tool name/schema are owned by the langchain adapter; crewai re-uses the same contract.
import { SYNTHEX_TOOL_NAME } from "../../adapters/langchain.js";

const sealedEvidence = {
  contentHash: "c".repeat(64),
  payload: { verdict: "LOW RISK", findings: [{ id: 1 }] },
  seal: { method: "HMAC-SHA256" },
};

test("crewai: happy path returns the sealed-evidence summary object (contentHash + verdict + seal method)", async () => {
  let seen = null;
  const pipeline = async (target, opts) => {
    seen = { target, lens: opts.lens };
    return sealedEvidence;
  };
  const tool = synthexCrewaiTool({ pipeline });

  assert.equal(tool.name, SYNTHEX_TOOL_NAME);
  assert.equal(tool.args_schema.required[0], "target");
  assert.equal(typeof tool.run, "function");

  const out = await tool.run({ target: "acme.example", lens: "gtm" });
  assert.deepEqual(seen, { target: "acme.example", lens: "gtm" });
  // Summary is returned as a plain object (CrewAI-JS tool contract), not stringified.
  assert.equal(typeof out, "object");
  assert.equal(out.contentHash, sealedEvidence.contentHash);
  assert.equal(out.contentHash.length, 64);
  assert.equal(out.verdict, "LOW RISK");
  assert.equal(out.sealed, "HMAC-SHA256");
  assert.equal(out.findings, 1);
});

test("crewai: default lens is applied when omitted", async () => {
  let seenLens = null;
  const pipeline = async (_target, opts) => {
    seenLens = opts.lens;
    return sealedEvidence;
  };
  const tool = synthexCrewaiTool({ pipeline });
  await tool.run({ target: "acme.example" });
  assert.equal(seenLens, "security");
});

test("crewai: fail-safe on pipeline failure — propagates, never fabricates a seal", async () => {
  const pipeline = async () => {
    throw new Error("classifier unavailable");
  };
  const tool = synthexCrewaiTool({ pipeline });
  await assert.rejects(() => tool.run({ target: "acme.example" }), /classifier unavailable/);
});

test("crewai: degraded evidence (no payload / no seal) yields fail-safe null defaults, no throw", async () => {
  const pipeline = async () => ({ contentHash: "d".repeat(64) });
  const tool = synthexCrewaiTool({ pipeline });
  const out = await tool.run({ target: "acme.example" });
  assert.equal(out.contentHash.length, 64);
  assert.equal(out.verdict, null);
  assert.equal(out.sealed, null);
  assert.equal(out.findings, 0);
});
