# Synthex v3 — Deep-Research applicable items (PENDING APPROVAL)

> Consenso ralplan: Planner + Architect (NET-POSITIVE condicionado) + Critic (ITERATE → este v3 resuelve
> sus 2 Critical + 3 Major + minors). Principio rector: HONESTIDAD VERIFICABLE. Branch `feat/deep-research`,
> commits atómicos, sin merge a main hasta OK de Pablo.

## Fence de honestidad (duro)
NO reclamar como credenciales de Synthex: AMD MI300X · Zenodo DOI · Z3-en-pipeline · 79.85% token savings
(son Context_Forge/INV-15, prior-art citado). NO reclamar bloqueo de **VPI visual** (reglas = text/HTML/ARIA
serializado). Tests reales = 133/124/9-skip/0-fail (los 9 skip son live-gated por env: AIML_LIVE/BD_LIVE/
BROWSER_LIVE/COGNEE_LIVE — confirmar con `node --test | grep skip` antes de ejecutar; son legítimos, no rotos).
**Regla de oro:** el claim sigue al hecho verificado, nunca lo precede.

## NÚCLEO (ejecutar) — orden y dependencias
El conteo de reglas (item 1) es un RESULTADO, no un target; todos los sitios de copy lo consumen → item 1 primero.

### 1. FORGE — auditar 28 + añadir SOLO vectores genuinamente no cubiertos
- Primero auditar las 28 reglas actuales (prefilter.js:15-46). Añadir regla SOLO si el vector NO lo atrapa ninguna existente:
  - **ARIA-1**: injection en accessibility-tree / ARIA labels (`aria-label`, `role=` con instrucción) — NUEVO (no cubierto).
  - **META-1**: instrucción embebida en metadata (alt-text / EXIF-text serializado) — NUEVO si EXF-* no lo cubre.
  - **JSON-LD proto-pollution**: si cae bajo `PROTO-1` (prefilter.js:41) → **mejora de regex de PROTO-1, NO regla nueva** (no infla conteo).
  - **MCP tool-response poisoning**: ya existe `MCP-2` (prefilter.js:43) → **mejora de regex de MCP-2 si hay gap, NO regla nueva**.
- Conteo final = el real tras la auditoría. **28 puede quedar legítimamente en 28** si el audit no halla vectores
  genuinamente no cubiertos — ése es un outcome honesto aceptable (el deck/UI se ajusta a lo real, no al revés).
  DoD incluye sincronizar `28-rule|28 reglas|RULES.length` en los **4 sitios** en el MISMO commit:
  `test/forge.test.js:56-57` (assert + corregir comentario: `12 base`→**14** Y `8 v2`→**6**; 14+6+8=28),
  `SLIDES.md` (slides 1,4), `README.md`, `public/index.html`.
- **Rollback item 1:** si una regla candidata resulta ya cubierta (el test negativo no pasa), se DESCARTA esa regla
  y el conteo no cambia — nunca se fuerza un número.
- CVE/papers como **CONTEXTO DE AMENAZA**: redacción "detecta indicadores text-based asociados a [vector de CVE-2025-68143/144/145]",
  NUNCA "mitiga/bloquea CVE". Mantener header honesto prefilter.js:5-14.
- **Acceptance:** por cada regla nueva: (a) test que bloquea/marca su vector; (b) test NEGATIVO que demuestra que las
  reglas viejas NO lo atrapaban (justifica no-solapamiento); (c) benigno cercano → ALLOW. `RULES.length===<nuevo>`.
  Suite verde (124 pass se mantiene; el assert de conteo se edita en el mismo commit).

### 2. CVE anchor en UI (drama) + insumo del deck
- CVE-2025-68143 (Anthropic MCP Git) como contexto de urgencia del ecosistema. **Acceptance:** verificar CVSS/fecha
  contra NVD (WebFetch) ANTES de poner el número en UI/deck; si no se verifica, citar sin CVSS numérico. Honesto:
  "amenaza del ecosistema", no "lo que bloqueamos". Consume el conteo final de item 1.

### 3. Deck 15 slides (SLIDES.md → narrativa REEF, alineado UI+fence) — ÚLTIMO (consume conteo de item 1 + CVE de item 2 + business de item 9).

### 4. Sample Evidence Report PDF en /samples/ + link
- Generado por el pipeline real (runDemo → buildEvidence → buildPDFReport). **Acceptance:** PDF válido (%PDF; conteo de
  páginas vía pdfinfo SI está instalado, si no fallback en node) Y `verifyEvidence(evidence)` → hashOk+hmacOk
  (ata el sample a la garantía, no solo conteo de páginas).
  Link insertado en README (bajo el hero, sin romper estructura) + botón/nota en UI.

### 5. Dedup semántico — OPT-IN CLI-only (jamás default, jamás serverless)
- `src/forge/dedup.js`: cambiar firma a `dedupe(items, { mode = "exact" })`. mode "exact" = SHA-256 actual INTACTO
  (preservar garantía cero-falsos-positivos, dedup.js:2-6). mode "semantic" = `@xenova/transformers` all-MiniLM-L6-v2,
  **lazy-load** (descarga en primer uso; documentar; fallback claro si offline).
- Enhebrar `dedupMode` por `runPipeline(opts)` (pipeline.js:42-50, 85). Default exact. `api/**` NUNCA importa transformers.
- **Acceptance:** (a) test: `dedupe(items)` sin opts → salida byte-idéntica a hoy (no-regresión lossless); (b) test
  integración GATED (skip si no hay modelo) que corre semantic sobre 2 docs near-dup reales y verifica clustering
  (no vanity-mock); (c) test/grep: ningún archivo en `api/` importa @xenova. Documentar como "near-duplicate clustering
  (lossy, opt-in)" vs default "exact, lossless".

### 8. CLI entrypoint (resuelve Critical #1) — `--demo` y `--dedup` son features nuevas, no "wiring"
- Crear `bin/synthex.mjs`: parser argv mínimo (sin dep) → `node bin/synthex.mjs <target> [lens] [--demo] [--dedup=semantic|exact]`.
  `package.json` bin: **PRESERVAR el existente** `"apohara-synthex": "./server.js"` y **AGREGAR** `"synthex": "bin/synthex.mjs"`
  (NO renombrar; el bin actual es `apohara-synthex`→`./server.js`, no se toca, para no romper consumidores MCP).
  npm script `"cli": "node bin/synthex.mjs"`. DoD: grep del repo/docs por `apohara-synthex` como bin antes de tocar nada.
- **Acceptance (comandos literales):** `node bin/synthex.mjs --demo` → Evidence Report verificable SIN secrets (usa runDemo);
  `node bin/synthex.mjs https://… all --dedup=semantic` → corre con dedup semántico. Test del parser (flags → opts).

### 9. Sección business/market en README
- TAM $55B **citado a fuente** (Dimension Market Research); pricing OSS/Pro/Enterprise etiquetado **"proposed"**; tabla
  competitiva. Disciplina de fuentes; nada como ingreso real. **Acceptance:** cada cifra con fuente o label "proposed".

## DIFERIDOS (post-hackathon · gated en acción de Pablo · claim-sigue-al-hecho)
### 6. SLSA provenance — slsa-github-generator (GitHub Action + OIDC `id-token:write`), release vía tags. Requiere acción de
Pablo (aprobar workflow). El claim "SLSA-signed build" SOLO entra a docs TRAS attestation verificado. Rollback: si falla, no hay claim.
### 7. npm publish + distribución — `@apohara/synthex` requiere org npm de Pablo + rename de package.json (rollback: revertir
rename si publish falla) + `--access public` + `--provenance` desde CI. LangChain wrapper + Smithery listing. El claim
"available on npm/LangChain/Smithery" SOLO tras funcionar end-to-end verificado.

## Pre-mortem (4 escenarios)
1. "UI/deck dice 'bloqueamos CVE-X' y un juez ve que es regex" → redacción "detecta indicadores de", revisión claim-por-claim pre-commit.
2. "@xenova rompe/infla el deploy serverless" → CLI-only, api/ jamás importa transformers, smoke del deploy + grep test.
3. "Se reclama npm/SLSA antes de funcionar y un juez lo verifica fallando" → diferidos, claim-sigue-al-hecho.
4. "@xenova descarga el modelo en runtime / falla offline / infla el repo / el mock no prueba nada" → lazy-load documentado,
   modelo NO commiteado (`.gitignore`: `node_modules/@xenova/`, cache `~/.cache/huggingface|.transformers`), pin de versión
   de `@xenova/transformers`, fallback claro si offline, y test de integración REAL gated (no solo mock del branching).

## Verificación global
- `npm test` verde tras cada item (conteo de reglas editado junto con su regla). 
- check-bd-apis (6/6) sin romper. Deploy smoke en synthex.apohara.dev. visual-verdict de UI tras cambios de copy.
- `grep -rn "28-rule\|28 reglas\|RULES.length"` = 0 desincronizaciones tras item 1.

## ADR
- **Decisión:** aplicar el núcleo verificable del Deep Research (FORGE-audit+reglas reales, CVE anchor, deck, sample PDF,
  dedup semántico opt-in CLI, CLI entrypoint, business README); diferir SLSA + distribución (gated en cuentas de Pablo).
- **Drivers:** edge verificable para jueces · honestidad como foso · convertir hackathon en canal (diferido).
- **Alternativas:** (A) ejecutar TODO tal cual → rechazada (infla conteo, claim-antes-de-hecho, @xenova en serverless inviable);
  (B) este núcleo + diferidos gated → elegida; (C) solo quick-wins → insuficiente (deja FORGE en 28, sin CVE/deck).
- **Consecuencias:** menos casillas marcadas a corto plazo; foso de honestidad intacto; @xenova fuera del serverless.
- **Follow-ups:** SLSA + npm cuando Pablo habilite cuentas; des-skip de tests live si se decide.

**STATUS: PENDING APPROVAL**
