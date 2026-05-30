#!/usr/bin/env node
// PROBE — gate-before-trust smoke test for AI/ML API model ids (item 1.4).
// Smoke-test de los model ids de AI/ML API ANTES de construir encima (gate-before-trust).
//
// Carga la key fuera del repo (NUNCA hardcodear):
//   set -a; source ~/.config/apohara/secrets.env; set +a
//   node scripts/probe-aiml-models.mjs
//
// Imprime una línea por modelo:
//   OK <id> [<extra>]        cuando el endpoint responde 200
//   FAIL <id> <http|reason>  cuando NO responde 200 (crítico para v4-flash/v4-pro)
//
// Salida exit 0 si los dos chat ids críticos (v4-flash, v4-pro) dan OK; exit 1 si alguno falla.
// Los embeddings son best-effort: se prueban candidatos y se reporta el primero que responda 200.

const BASE = process.env.AIML_BASE_URL || "https://api.aimlapi.com/v1";
const API_KEY = process.env.AIML_API_KEY;

if (!API_KEY) {
  console.error("FAIL probe AIML_API_KEY-missing (source ~/.config/apohara/secrets.env)");
  process.exit(1);
}

const headers = {
  Authorization: `Bearer ${API_KEY}`,
  "Content-Type": "application/json",
};
const TIMEOUT_MS = 30000;

// Chat ids CRÍTICOS — si alguno falla, el ítem 1.4 no se construye encima (se reporta).
const CHAT_MODELS = ["deepseek/deepseek-v4-flash", "deepseek/deepseek-v4-pro"];

// Candidatos de embedding — AI/ML reexpone varios catálogos (OpenAI, etc.). Probamos en orden
// y nos quedamos con el primero que responda 200. Si NINGUNO responde, se reporta FAIL (no se inventa).
const EMBED_CANDIDATES = [
  "text-embedding-3-small",
  "text-embedding-3-large",
  "text-embedding-ada-002",
  "togethercomputer/m2-bert-80M-8k-retrieval",
  "BAAI/bge-base-en-v1.5",
  "voyage-3-lite",
];

/** POST helper con timeout. Devuelve {status, json|null, text}. */
async function post(path, body) {
  try {
    const res = await fetch(`${BASE}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    let json = null;
    const text = await res.text();
    try { json = JSON.parse(text); } catch { /* non-JSON body */ }
    return { status: res.status, json, text };
  } catch (err) {
    return { status: 0, json: null, text: String(err?.message || err) };
  }
}

/** Smoke de un chat model — input mínimo (budget AI/ML $20). */
async function probeChat(model) {
  const r = await post("/chat/completions", {
    model,
    messages: [{ role: "user", content: "ping" }],
    max_tokens: 5,
    temperature: 0,
  });
  if (r.status === 200) {
    const content = r.json?.choices?.[0]?.message?.content;
    const tokens = r.json?.usage?.total_tokens ?? "?";
    console.log(`OK ${model} (tokens=${tokens}${content != null ? `, reply=${JSON.stringify(String(content).slice(0, 24))}` : ""})`);
    return true;
  }
  console.log(`FAIL ${model} ${r.status || r.text.slice(0, 80)}`);
  return false;
}

/** Smoke de un embedding model — devuelve {ok, dims}. */
async function probeEmbed(model) {
  const r = await post("/embeddings", { model, input: "synthex probe" });
  if (r.status === 200) {
    const vec = r.json?.data?.[0]?.embedding;
    const dims = Array.isArray(vec) ? vec.length : "?";
    return { ok: true, dims, model };
  }
  return { ok: false, status: r.status || r.text.slice(0, 60), model };
}

(async () => {
  const chatResults = [];
  for (const m of CHAT_MODELS) chatResults.push(await probeChat(m));

  let embedOk = false;
  let firstFail = null;
  for (const m of EMBED_CANDIDATES) {
    const r = await probeEmbed(m);
    if (r.ok) {
      console.log(`OK ${r.model} (embedding, dims=${r.dims})`);
      embedOk = true;
      break;
    }
    if (!firstFail) firstFail = r;
  }
  if (!embedOk) {
    const f = firstFail || { model: EMBED_CANDIDATES[0], status: "no-candidate" };
    console.log(`FAIL embedding (tried ${EMBED_CANDIDATES.length} candidates; first=${f.model} ${f.status})`);
  }

  // Exit code: solo los chat ids son críticos para 1.4. Embeddings son best-effort.
  const criticalOk = chatResults.every(Boolean);
  process.exit(criticalOk ? 0 : 1);
})();
