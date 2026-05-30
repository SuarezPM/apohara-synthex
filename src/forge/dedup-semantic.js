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

/** L2-normaliza un vector in-place-safe → unit norm, para que cosine() == producto punto. */
function l2normalize(vec) {
  let norm = 0;
  for (let i = 0; i < vec.length; i++) norm += vec[i] * vec[i];
  norm = Math.sqrt(norm);
  if (norm === 0) return vec.slice();
  return vec.map((x) => x / norm);
}

// ─────────────────────────────────────────────────────────────────────────────
// EMBED PROVIDER — default Xenova local (offline, opt-in dep); optional AI/ML remote.
// PROVEEDOR DE EMBEDDING — default Xenova local (offline); AI/ML remoto opcional.
//
// AI/ML path is OFF unless explicitly configured (opts.embedProvider==="aiml" or env
// AIML_EMBED_MODEL set), because gate-before-trust did NOT confirm a reachable AI/ML
// embedding id (scripts/probe-aiml-models.mjs → all candidates 404 on this key). When a
// working id IS provided, this calls /embeddings and L2-normalizes (OpenAI-shaped vectors
// are not guaranteed unit-norm, unlike the Xenova path's normalize:true) to preserve the
// cosine()==dot invariant. Si la red/endpoint falla → cae al Xenova local (fail-safe).
//
// El path AI/ML está APAGADO salvo configuración explícita, porque la probe NO confirmó un
// embedding id de AI/ML alcanzable. Si se provee un id válido, normaliza L2 y, ante fallo,
// cae al Xenova local.
const AIML_EMBED_BASE = process.env.AIML_BASE_URL || "https://api.aimlapi.com/v1";

async function aimlEmbed(text, { model, apiKey, baseUrl, timeoutMs }) {
  const key = apiKey ?? process.env.AIML_API_KEY;
  if (!key) throw new Error("dedup semántico AI/ML: falta AIML_API_KEY.");
  const res = await fetch(`${baseUrl ?? AIML_EMBED_BASE}/embeddings`, {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({ model, input: String(text ?? "") }),
    signal: AbortSignal.timeout(timeoutMs ?? 30000),
  });
  if (!res.ok) {
    throw new Error(`AI/ML embeddings HTTP ${res.status}: ${(await res.text()).slice(0, 160)}`);
  }
  const data = await res.json();
  const vec = data?.data?.[0]?.embedding;
  if (!Array.isArray(vec) || vec.length === 0) {
    throw new Error("AI/ML embeddings: respuesta sin vector embedding.");
  }
  return l2normalize(vec);
}

/**
 * Devuelve una función `embed(text) -> Promise<number[]>` que produce vectores L2-normalizados.
 * Default: Xenova local. AI/ML remoto si opts.embedProvider==="aiml" (o AIML_EMBED_MODEL en env);
 * ante fallo del path AI/ML cae al Xenova local (fail-safe).
 */
async function getEmbedder(opts = {}) {
  const aimlModel = opts.embedModel ?? process.env.AIML_EMBED_MODEL;
  const wantAiml = opts.embedProvider === "aiml" || (opts.embedProvider !== "local" && !!aimlModel);

  if (wantAiml && aimlModel) {
    let warned = false;
    let localFallback = null;
    return async (text) => {
      try {
        return await aimlEmbed(text, {
          model: aimlModel,
          apiKey: opts.apiKey,
          baseUrl: opts.baseUrl,
          timeoutMs: opts.timeoutMs,
        });
      } catch (err) {
        if (!warned) {
          console.warn(`[dedup-semantic] AI/ML embeddings failed (${err.message}); falling back to local Xenova.`);
          warned = true;
        }
        if (!localFallback) {
          const extractor = await getExtractor();
          localFallback = async (t) => {
            const out = await extractor(String(t ?? ""), { pooling: "mean", normalize: true });
            return Array.from(out.data);
          };
        }
        return localFallback(text);
      }
    };
  }

  // Default: Xenova local (already L2-normalized via normalize:true). Lazy: el modelo
  // (~25 MB) se carga en el PRIMER embed, no por adelantado — input vacío no necesita la dep.
  let localExtractor = null;
  return async (text) => {
    if (!localExtractor) localExtractor = await getExtractor();
    const out = await localExtractor(String(text ?? ""), { pooling: "mean", normalize: true });
    return Array.from(out.data);
  };
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
 * @param {object} [opts]
 *   - threshold?: number       coseno (0–1) para considerar near-dup. Default 0.92.
 *   - embedProvider?: "local"|"aiml"   default local (Xenova). "aiml" usa /embeddings remoto.
 *   - embedModel?: string      model id de AI/ML (o env AIML_EMBED_MODEL). Requerido para "aiml".
 *   - apiKey?, baseUrl?, timeoutMs?    pasados al path AI/ML.
 */
export async function dedupeSemantic(items, opts = {}) {
  const { threshold = 0.92 } = opts;
  const embed = await getEmbedder(opts);
  const embedMode = (opts.embedProvider === "aiml" || (opts.embedProvider !== "local" && !!(opts.embedModel ?? process.env.AIML_EMBED_MODEL)))
    ? "aiml"
    : "local";
  const unique = [];
  const duplicates = [];
  const kept = []; // [{ emb:number[], url:string }]
  let bytesSaved = 0;

  for (const item of items) {
    const emb = await embed(item.content);
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
      embedMode,
      threshold,
    },
  };
}
