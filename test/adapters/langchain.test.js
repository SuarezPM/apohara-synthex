// LangChain adapter — sealed-evidence summary contract (item 3.3).
//
// The adapter is a thin framework-shaped wrapper over the pipeline. With an INJECTED pipeline
// (zero network, no real crypto/TSA) we assert it returns the sealed-evidence summary
// (contentHash + verdict + seal method) and is fail-safe on failure / degraded inputs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { synthexLangChainTool, SYNTHEX_TOOL_NAME } from "../../adapters/langchain.js";

// A sealed-evidence object shaped like a real pipeline result, fully synthetic (no network).
const sealedEvidence = {
  contentHash: "a".repeat(64),
  payload: { verdict: "HIGH RISK", findings: [{ id: 1 }, { id: 2 }] },
  seal: { method: "Ed25519+RFC3161" },
};

test("langchain: happy path returns the sealed-evidence summary (contentHash + verdict + seal method)", async () => {
  let seen = null;
  const pipeline = async (target, opts) => {
    seen = { target, lens: opts.lens };
    return sealedEvidence;
  };
  const tool = synthexLangChainTool({ pipeline });

  assert.equal(tool.name, SYNTHEX_TOOL_NAME);
  assert.equal(typeof tool.func, "function");

  const out = JSON.parse(await tool.func({ target: "acme.example", lens: "security" }));
  // Pipeline received the un-mangled target + lens (injection seam works, no network).
  assert.deepEqual(seen, { target: "acme.example", lens: "security" });
  // Summary shape: the three load-bearing fields plus findings count.
  assert.equal(out.contentHash, sealedEvidence.contentHash);
  assert.equal(out.contentHash.length, 64);
  assert.equal(out.verdict, "HIGH RISK");
  assert.equal(out.sealed, "Ed25519+RFC3161");
  assert.equal(out.findings, 2);
});

test("langchain: default lens is applied when omitted", async () => {
  let seenLens = null;
  const pipeline = async (_target, opts) => {
    seenLens = opts.lens;
    return sealedEvidence;
  };
  const tool = synthexLangChainTool({ pipeline });
  await tool.func({ target: "acme.example" });
  assert.equal(seenLens, "security");
});

test("langchain: fail-safe on pipeline failure — propagates, never fabricates a seal", async () => {
  const pipeline = async () => {
    throw new Error("scrape failed");
  };
  const tool = synthexLangChainTool({ pipeline });
  // Must NOT resolve to a fake-success summary claiming sealed evidence that does not exist.
  await assert.rejects(() => tool.func({ target: "acme.example" }), /scrape failed/);
});

test("langchain: degraded evidence (no payload / no seal) yields fail-safe null defaults, no throw", async () => {
  const pipeline = async () => ({ contentHash: "b".repeat(64) });
  const tool = synthexLangChainTool({ pipeline });
  const out = JSON.parse(await tool.func({ target: "acme.example" }));
  assert.equal(out.contentHash.length, 64);
  assert.equal(out.verdict, null);
  assert.equal(out.sealed, null);
  assert.equal(out.findings, 0);
});
