# v0.6.0 Model Status Audit (T0.2)

**Date:** 2026-05-28
**Auditor:** ralph execution of PRD `synthex-v0.6.0-watch-prove.md`
**PRD section:** §3 D0 T0.2

## Finding

`gemini-2.0-flash` model deprecation (2026-06-01) does NOT affect Synthex runtime.

## Empirical evidence

### 1. No `gemini-2` references in source

```
$ grep -rn "gemini-2" src/
(0 hits)
```

### 2. Actual default model = `deepseek/deepseek-non-thinking-v3.2-exp`

```js
// src/classify/aiml-client.js:5
const DEFAULT_MODEL = process.env.AIML_MODEL || "deepseek/deepseek-non-thinking-v3.2-exp";
```

### 3. Runtime override path = `opts.model`

```js
// src/classify/aiml-client.js:36
const model = opts.model ?? DEFAULT_MODEL;
```

No code change needed in v0.6.0 to migrate off deprecated Gemini. The audit
finding in the original v0.6.0 PRD draft ("CRÍTICO: gemini-2.0-flash deprecate")
was inherited from an external audit that did not inspect the codebase. The
actual default has been DeepSeek since v0.5.0.

## Implications for v0.6.0 scope

- **T0.2 is no-op runtime**: no code change required.
- **T0.3 (tier selector)** adds NEW capability (`MODEL_TIERS.{free,oss,paid}`),
  it does NOT replace any deprecated default.
- **Documentation must NOT claim "migrated from Gemini"** — that framing would
  be a false attribution. Honest framing: "DeepSeek default since v0.5.0; v0.6.0
  adds explicit tier selection for cost/quality tradeoff visibility."

## Resolves

- PRD Eje B Option B1 (NO-OP default model + tier selector).
- Critic R1 finding F4 (verified, no false claims propagated).
- Architect R3 Section E (no principle violations from this audit).
