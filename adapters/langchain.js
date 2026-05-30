// ADAPTERS/langchain — expose the Synthex pipeline as a LangChain-compatible tool config.
//
// Distribution beyond MCP (item 3.3). This is a thin, framework-SHAPED wrapper: it returns the
// config object LangChain's DynamicStructuredTool expects (name/description/schema/func). You
// bring `@langchain/core` — Synthex does NOT depend on it (zero new deps):
//
//   import { DynamicStructuredTool } from "@langchain/core/tools";
//   import { synthexLangChainTool } from "@apohara/synthex/adapters/langchain.js";
//   const tool = new DynamicStructuredTool(synthexLangChainTool());
//
// The tool runs the real pipeline and returns the SEALED evidence summary (contentHash + verdict
// + seal method) so the agent can cite verifiable provenance, not just raw text.
import { runPipeline } from "../src/pipeline.js";

export const SYNTHEX_TOOL_NAME = "synthex_seal_evidence";
export const SYNTHEX_TOOL_DESCRIPTION =
  "Scrape a target, classify it (GTM / Finance / Security / Supply-chain), and SEAL the result " +
  "into a verifiable Evidence Report (Ed25519 + RFC 3161 TSA + content hash). Returns the sealed " +
  "contentHash, the one-line verdict, and the seal method. Input: {target, lens?}.";
// Framework-agnostic JSON schema (LangChain accepts zod or JSON schema).
export const SYNTHEX_TOOL_SCHEMA = Object.freeze({
  type: "object",
  properties: {
    target: { type: "string", description: "URL or search term to scrape + classify" },
    lens: { type: "string", enum: ["gtm", "finance", "security", "supply-chain", "all"], description: "classification lens" },
  },
  required: ["target"],
});

/**
 * Build a LangChain DynamicStructuredTool config for Synthex.
 * @param {{pipeline?:Function, pipelineOpts?:object}} [opts]  inject pipeline/opts for tests.
 * @returns {{name:string, description:string, schema:object, func:Function}}
 */
export function synthexLangChainTool(opts = {}) {
  const pipeline = opts.pipeline ?? runPipeline;
  return {
    name: SYNTHEX_TOOL_NAME,
    description: SYNTHEX_TOOL_DESCRIPTION,
    schema: SYNTHEX_TOOL_SCHEMA,
    func: async ({ target, lens = "security" }) => {
      const ev = await pipeline(target, { lens, ...(opts.pipelineOpts ?? {}) });
      return JSON.stringify({
        contentHash: ev.contentHash,
        verdict: ev.payload?.verdict ?? null,
        sealed: ev.seal?.method ?? null,
        findings: Array.isArray(ev.payload?.findings) ? ev.payload.findings.length : 0,
      });
    },
  };
}
