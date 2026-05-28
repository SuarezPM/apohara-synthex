// FORGE/dedup-semantic — near-duplicate clustering OPT-IN (lossy). Vía OPCIONAL, jamás default.
//
// HONESTIDAD: la deduplicación por defecto del pipeline es dedupe() exacto (SHA-256, LOSSLESS,
// cero falsos positivos — ver dedup.js). Esto es lo contrario: agrupa páginas SEMÁNTICAMENTE
// parecidas (paráfrasis, mismo hecho redactado distinto) por encima de un umbral de coseno.
// Es LOSSY (puede colapsar dos docs que no son idénticos) → opt-in, CLI-only, NUNCA serverless.
//
// SEGURIDAD DE DEPLOY: @xenova/transformers se importa con `await import()` DINÁMICO dentro de la
// función — nunca como import estático de nivel de módulo. pipeline.js solo carga este archivo con
// import() dinámico cuando dedupMode==="semantic". Así el grafo de dependencias de api/** NUNCA
// alcanza transformers/onnxruntime y el bundle serverless no se infla (ver pre-mortem del plan).
//
// DEP NO DECLARADA A PROPÓSITO: @xenova/transformers NO está en package.json. Su subárbol
// (onnxruntime-node → protobufjs) arrastra un advisory crítico; para un producto de seguridad no
// queremos ensuciar el footprint instalado por defecto con eso. Es instalación opt-in del usuario:
// `npm i @xenova/transformers@2.17.2`. Si falta, getExtractor() lanza un error claro (abajo).
import { fingerprint } from "./dedup.js";

// El extractor (modelo + tokenizer) se inicializa UNA vez y se cachea. El modelo all-MiniLM-L6-v2
// se descarga en el primer uso (~25 MB a ~/.cache); offline tras la primera vez.
let _extractorPromise = null;

async function getExtractor() {
  if (_extractorPromise) return _extractorPromise;
  let transformers;
  try {
    transformers = await import("@xenova/transformers");
  } catch {
    throw new Error(
      "dedup semántico: falta la dependencia opcional @xenova/transformers. " +
        "Instalala con `npm i @xenova/transformers@2.17.2` (es opt-in, CLI-only).",
    );
  }
  _extractorPromise = transformers.pipeline("feature-extraction", "Xenova/all-MiniLM-L6-v2");
  return _extractorPromise;
}

/** Coseno de dos vectores ya L2-normalizados (= producto punto). */
function cosine(a, b) {
  let dot = 0;
  for (let i = 0; i < a.length; i++) dot += a[i] * b[i];
  return dot;
}

const contentLen = (c) => (typeof c === "string" ? c : JSON.stringify(c)).length;

/**
 * Deduplica un array de {url, content} por SIMILITUD SEMÁNTICA (lossy, opt-in). Devuelve el MISMO
 * shape que dedupe() ({unique, duplicates, stats}) para que el pipeline lo consuma igual; stats
 * lleva mode:"semantic" y el threshold usado.
 * @param {Array<{url?:string, content:any}>} items
 * @param {{threshold?:number}} opts  threshold de coseno (0–1) para considerar near-dup. Default 0.92.
 */
export async function dedupeSemantic(items, { threshold = 0.92 } = {}) {
  const extractor = await getExtractor();
  const unique = [];
  const duplicates = [];
  const kept = []; // [{ emb:number[], url:string }]
  let bytesSaved = 0;

  for (const item of items) {
    const out = await extractor(String(item.content ?? ""), { pooling: "mean", normalize: true });
    const emb = Array.from(out.data);
    const contentHash = fingerprint(item.content);
    let duplicateOf = null;
    for (const k of kept) {
      if (cosine(emb, k.emb) >= threshold) { duplicateOf = k.url; break; }
    }
    if (duplicateOf) {
      duplicates.push({ ...item, contentHash, duplicateOf, mode: "semantic" });
      bytesSaved += contentLen(item.content);
    } else {
      unique.push({ ...item, contentHash });
      kept.push({ emb, url: item.url ?? contentHash });
    }
  }

  const total = items.length;
  return {
    unique,
    duplicates,
    stats: {
      uniqueBlocks: unique.length,
      duplicateBlocks: duplicates.length,
      bytesSaved,
      dedupRatio: total > 0 ? duplicates.length / total : 0,
      mode: "semantic",
      threshold,
    },
  };
}
