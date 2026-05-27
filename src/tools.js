// Tools MCP que Synthex expone (el "complemento" que envuelve a Bright Data).
// Separadas del arranque del server (server.js) para poder testearlas sin stdio.
import { z } from "zod";
import { verifyEvidence } from "./prove/evidence-report.js";
import { runPipeline } from "./pipeline.js";
import { TriggerWareClient } from "./trigger/index.js";

export const tools = [
  {
    name: "synthex_verify_evidence",
    description:
      "Verifica un Evidence Report de Synthex: comprueba el hash, el sello HMAC-SHA256 y, si lo lleva, el timestamp RFC 3161. Funciona offline.",
    parameters: z.object({
      evidence: z.string().describe("Evidence Report (JSON) a verificar"),
      hmacKey: z.string().optional().describe("Clave HMAC (default: SYNTHEX_HMAC_KEY)"),
    }),
    execute: async ({ evidence, hmacKey }) => {
      const ev = typeof evidence === "string" ? JSON.parse(evidence) : evidence;
      const result = verifyEvidence(ev, { hmacKey: hmacKey ?? process.env.SYNTHEX_HMAC_KEY ?? "synthex-dev" });
      return JSON.stringify(result, null, 2);
    },
  },
  {
    name: "synthex_scrape_classify_prove",
    description:
      "Pipeline completo: scrapea el target vía Bright Data, deduplica y pre-filtra, clasifica bajo la lente pedida (GTM/Finance/Security/Supply-chain, o 'all' para las cuatro en paralelo) y devuelve un Evidence Report sellado.",
    parameters: z.object({
      target: z.string().describe("URL o término objetivo"),
      lens: z.enum(["gtm", "finance", "security", "supply-chain", "all"]).default("security").describe("Lente de clasificación; 'all' corre las cuatro en paralelo"),
    }),
    execute: async ({ target, lens }) => {
      const ev = await runPipeline(target, { lens });
      return JSON.stringify(ev, null, 2);
    },
  },
  {
    name: "synthex_monitor",
    description:
      "Monitoreo continuo vía Triggerware: crea un trigger que vigila el objetivo y acumula deltas (added/deleted) en un schedule, para disparar el pipeline cuando aparece algo nuevo.",
    parameters: z.object({
      description: z.string().describe("Qué monitorear, en lenguaje natural"),
      schedule: z.number().int().positive().optional().describe("Segundos entre corridas (ej. 300 = 5 min)"),
    }),
    execute: async ({ description, schedule }) => {
      const tw = new TriggerWareClient();
      const trigger = await tw.createTrigger({ description, ...(schedule ? { schedule } : {}) });
      return JSON.stringify(trigger, null, 2);
    },
  },
];
