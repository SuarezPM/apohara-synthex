# Model status — AI/ML API tiers (v1.0.0)

> Estado de los model ids usados por el clasificador. Cada id se valida con un smoke-test
> real (gate-before-trust) ANTES de construir encima: `scripts/probe-aiml-models.mjs`.
> Model ids used by the classifier. Each id is smoke-tested for real before we build on it.

## Chat / classify tiers (`src/classify/tiers.js`)

| Tier  | Model id                       | Uso / Use                                  | Probe (2026-05-29) |
|-------|--------------------------------|--------------------------------------------|--------------------|
| flash | `deepseek/deepseek-v4-flash`   | default / bulk (4-lens always-on)          | **OK** (HTTP 200)  |
| pro   | `deepseek/deepseek-v4-pro`     | spot quality · council high-stakes · L3    | **OK** (HTTP 200)  |

- `DEFAULT_TIER = "flash"` → `pickModel({})` resuelve a `deepseek/deepseek-v4-flash`.
- `pro` es spot-only: nunca entra al map de bulk; se invoca explícito (council / L3 / spot sample).
- **Nemotron eliminado** (`nvidia/nemotron-nano-9b-v2`): se quitó del mapa de tiers en v1.0.0
  (ítem 1.4 / decisión §1.5). Ya no hay tier `free` ni el flag `lowConfidenceTier`.

## Classify modes

- **Per-lens** (`classify()`): default del pipeline. Una llamada por lente → aislamiento
  (una lente mala no corrompe las otras). One call per lens → isolation.
- **Batched 4-lens** (`classifyBatched()`): opt-in / bulk. Una llamada estructurada con las 4
  lentes → paga el input 1× en vez de 4×. Ambos shapes se validan con el mismo schema estricto.

## Embeddings (`src/forge/dedup-semantic.js`)

| Provider | Model                                   | Estado / Status                          |
|----------|-----------------------------------------|------------------------------------------|
| local    | Xenova `all-MiniLM-L6-v2` (opt-in dep)  | **Default operativo** (offline)          |
| aiml     | `AIML_EMBED_MODEL` (configurable)        | **Dormido** — sin id confirmado por probe |

- **Gate-before-trust (2026-05-29):** ningún embedding id de AI/ML respondió 200 con esta key.
  Candidatos probados (`text-embedding-3-small`, `text-embedding-3-large`, `text-embedding-ada-002`,
  `BAAI/bge-base-en-v1.5`, `intfloat/multilingual-e5-large-instruct`, `nomic-ai/nomic-embed-text-v1.5`,
  `voyage-*`, `Qwen/Qwen3-Embedding-8B`, etc.) → todos **HTTP 404 `model_not_found`**.
  `/v1/models` → **HTTP 401** (la key no tiene scope de catálogo).
- El path AI/ML existe (`embedProvider:"aiml"` + `AIML_EMBED_MODEL`) y cae al Xenova local ante
  fallo (fail-safe). Queda DORMIDO hasta confirmar un id válido vía la probe — **no se inventa un id**.
