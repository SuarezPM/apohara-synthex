// DELTA/chain — sella el snapshot actual y lo encadena al evidence previo.
// Reusa buildEvidence(payload, opts) de src/prove/evidence-report.js (cero
// reescritura del core criptográfico). Añade payload.delta_chain (additive,
// schema v2 compatible — verifiers de v0.5.0 ignoran el campo).
//
// Shape NORMATIVO de delta_chain (Architect R1 Q1 + Critic R3 ratificó):
//   {
//     previous_tsa_serial: string | null,   // null marker para cold start (no undefined)
//     current_tsa_serial: string,            // siempre presente (esta runrun)
//     diff_summary: { added: number, removed: number, changed: number },
//     kg_status: "ingested" | "skipped" | "unreachable",
//     kg_skip_reason: string | null,
//   }

import { buildEvidence } from "../prove/evidence-report.js";
import { hashSnapshot } from "./hash.js";
import { diffSnapshots } from "./diff.js";
import { normalizeContent } from "./normalize.js";

/**
 * Sella un nuevo snapshot y lo encadena al evidence previo.
 * @param {object} args
 * @param {object | null} args.prev_evidence  evidence anterior (con seal.rfc3161Tsa.serial). null = cold start.
 * @param {object} args.curr_snapshot         {target, lens, content, fetchedAt, sources?, findings?, blocked?, dedup?, ...}
 * @param {string} [args.hmacKey]             HMAC-SHA256 key (passthrough a buildEvidence)
 * @param {boolean} [args.requestTsa=true]    pedir RFC 3161 TSA real (default sí)
 * @param {"ingested"|"skipped"|"unreachable"} [args.kg_status="skipped"]
 * @param {string|null} [args.kg_skip_reason=null]
 * @returns {Promise<object>} evidence con payload.delta_chain
 */
export async function sealDeltaChain(args = {}) {
  const {
    prev_evidence = null,
    curr_snapshot,
    hmacKey,
    requestTsa = true,
    kg_status = "skipped",
    kg_skip_reason = null,
  } = args;

  if (!curr_snapshot || typeof curr_snapshot !== "object") {
    throw new TypeError("sealDeltaChain requires curr_snapshot object");
  }
  if (typeof curr_snapshot.content !== "string") {
    throw new TypeError("sealDeltaChain curr_snapshot.content must be string");
  }

  // 1. Normaliza + hashea contenido para el diff (hot path puro).
  const currNormalized = normalizeContent(curr_snapshot.content);
  const currHash = hashSnapshot(currNormalized);

  // 2. Calcula diff vs prev (cold path mínimo, sin red).
  const prevContent = prev_evidence?.payload?.delta_chain?.normalized_content_preview ?? null;
  const diff = diffSnapshots(prevContent, currNormalized);

  // 3. Compone payload con delta_chain ADDITIVE sobre schema v2.
  //    Nota: kg_status, kg_latency_ms, surface_status quedarán EXCLUIDOS del HMAC
  //    cuando T1.6 implemente HMAC_EXCLUDED_KEYS. Acá los emitimos al payload pero
  //    el sealer los filtrará antes del hash en la siguiente iteración.
  const previousTsaSerial = prev_evidence?.seal?.rfc3161Tsa?.serial ?? null;
  const payload = {
    ...curr_snapshot,
    schema_version: 3,
    snapshot_hash: currHash,
    delta_chain: {
      previous_tsa_serial: previousTsaSerial,
      // current_tsa_serial se rellena post-sello (sale del TSA token).
      current_tsa_serial: null,
      diff_summary: {
        added: diff.added.length,
        removed: diff.removed.length,
        changed: diff.changed.length,
      },
      kg_status,
      kg_skip_reason,
      // Preserva el contenido normalizado para que el próximo run pueda hacer diff.
      // Limitado en tamaño para que payload no infle más allá de lo necesario.
      normalized_content_preview: currNormalized.slice(0, 16384),
    },
  };

  // 4. Llama buildEvidence (HMAC + TSA + JCS canonicalize ya cubiertos por el core).
  const evidence = await buildEvidence(payload, { hmacKey, requestTsa });

  // 5. Cierra el chain: copia el serial del TSA emitido al delta_chain.
  if (evidence.seal?.rfc3161Tsa?.serial) {
    evidence.payload.delta_chain.current_tsa_serial = evidence.seal.rfc3161Tsa.serial;
  }

  return evidence;
}
