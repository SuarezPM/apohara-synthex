// ADAPTERS/crewai — expose the Synthex pipeline as a CrewAI-shaped tool definition.
//
// Distribution beyond MCP (item 3.3). CrewAI's first-class runtime is Python; this JS adapter
// returns a tool definition (name / description / args_schema / run) for CrewAI-JS ports and for
// embedding Synthex as a callable tool in a JS agent crew. Framework-SHAPED, zero new deps — you
// bring the crew runtime. Shares the tool contract with the LangChain adapter.
import { runPipeline } from "../src/pipeline.js";
import { SYNTHEX_TOOL_NAME, SYNTHEX_TOOL_DESCRIPTION, SYNTHEX_TOOL_SCHEMA } from "./langchain.js";

/**
 * Build a CrewAI-shaped tool definition for Synthex.
 * @param {{pipeline?:Function, pipelineOpts?:object}} [opts]  inject pipeline/opts for tests.
 * @returns {{name:string, description:string, args_schema:object, run:Function}}
 */
export function synthexCrewaiTool(opts = {}) {
  const pipeline = opts.pipeline ?? runPipeline;
  return {
    name: SYNTHEX_TOOL_NAME,
    description: SYNTHEX_TOOL_DESCRIPTION,
    args_schema: SYNTHEX_TOOL_SCHEMA,
    run: async ({ target, lens = "security" }) => {
      const ev = await pipeline(target, { lens, ...(opts.pipelineOpts ?? {}) });
      return {
        contentHash: ev.contentHash,
        verdict: ev.payload?.verdict ?? null,
        sealed: ev.seal?.method ?? null,
        findings: Array.isArray(ev.payload?.findings) ? ev.payload.findings.length : 0,
      };
    },
  };
}
