# Apohara Synthex v2.0 — Plan de Estado del Arte (PENDING APPROVAL)

> Consenso ralplan (--interactive). Planner + Architect + Critic (revisión inline, los
> subagentes OMC no enrutan modelo en este entorno). Alcance elegido: **todo el roadmap v2.0**.
> Dominio: **synthex.apohara.dev**. Principio rector: **honestidad verificable**.

## Guardrail de honestidad (hard requirement)
NO importar a Synthex claims que son de Context_Forge / paper INV-15:
- ❌ "pytest 310/310", "Z3 formal proof", "AMD MI300X", "ed25519" (salvo que se implemente).
- ✅ INV-15 = prior-art **citado**. KVCOMM / MemArt / SkillFortify = **citados como fundamento**, NO "implementados".
- ✅ "N BD tools reales" → solo se reclama lo verificado LIVE por un `scripts/check-*.mjs`.
- Synthex tiene **76 tests JS** (no 310). Cada número en deck/README debe ser real.

## ADR
- **Decisión:** Evolucionar Synthex a v2.0 integrando las BD APIs reales (SERP✓/Browser/Crawl/Web-Scraper/MCP-native), elevando FORGE a 28 reglas, añadiendo 4ª lente supply-chain, PDF de 6 páginas 4-buyer + risk score, Cognee default (local), observabilidad SSE cinematic, y una **UI nueva con el brand board Apohara** desplegada en synthex.apohara.dev.
- **Drivers:** diferenciación verificable vs competidores (nadie usa los 6 BD reales); impacto visceral en jueces; tiempo flexible (calidad > velocidad).
- **Alternativas consideradas:** (B) núcleo-diff + UI; (C) solo FETCH + UI. Elegida: full roadmap (usuario, "tenemos tiempo").
- **Consecuencias:** mayor superficie → mitigada con verificación live por feature + feature-flags en serverless. Costo de créditos → APIs pesadas/Cognee fuera del endpoint público por default.
- **Follow-ups:** medir TTFT tri-lens (cita KVCOMM); deck con tabla competitiva honesta.

## Brand board Apohara (fuente verificada: apohara-consilium)
- Colores: lime `#25B13F` (acento), dark `#2A2D3A`, bone `#EDEFF0` (texto), ink `#0E1010`, red `#B8262A`, bg-void `#0D0F18`, bg-mid `#1E2130`, bg-raised `#222640`.
- Fonts: **Press Start 2P** (display pixel-art), **JetBrains Mono** (mono), **Inter** (body).
- Lenguaje: dark-mode, radius sharp `0.25rem`, gradiente ambiental lime, scrollbar/selección lime, pixel-render. Referencias live: apohara.dev y apohara.dev/consilium.

## Fases (cada una: código + tests + verificación live + commit atómico)

### P0 — Setup (branch + secrets)
- Branch `feat/synthex-v2` desde main. Secrets ya en `~/.config/apohara/secrets.env` (SERP/Browser/Datasets zonas) — nunca en código.
- **Aceptación:** branch creada; `npm test` baseline 76/0.

### P1 — FETCH multi-API real (diferenciador #1) [CRÍTICA]
- `src/fetch/serp-client.js`: SERP API REST (`zone=serp_api1`, `brd_json=1` → JSON estructurado). **VERIFICADO LIVE ✓.**
- `src/fetch/browser-client.js`: Browser API vía Playwright `connectOverCDP(BRIGHT_DATA_BROWSER_WSS)` para sitios JS-heavy. **Flag/local** (sesión CDP no apta para serverless).
- `src/fetch/crawl-client.js`: Crawl API (site→markdown).
- `src/fetch/dataset-client.js`: Web Scraper/Datasets API (`datasets/v3/scrape`, async trigger→poll, `dataset_id`). Cuidar facturación: límites + flag.
- Router inteligente en `defaultFetch()`: URL JS-heavy→browser, query estructurada→serp, sitio→crawl, dataset conocido→scraper.
- **Aceptación:** `scripts/check-bd-apis.mjs` corre cada API LIVE y reporta OK/FAIL; deck solo lista las OK.
- **Verificación:** SERP ✓ (hecho); Browser/Crawl/Datasets probados live antes de reclamar.

### P2 — FORGE 20→28 reglas + SkillFortify-cited [ALTA]
- +8 reglas: SSRF patterns, JSON hijacking (`__proto__`/prototype-pollution), MCP tool poisoning (ClawHavoc), indirect injection en datos estructurados.
- Citar SkillFortify como benchmark (honesto: "aligned", no "formally verified").
- **Aceptación:** test por regla nueva; 76+ tests verdes; README badge "28 rules".

### P3 — CLASSIFY 4ª lente supply-chain [MEDIA]
- `lens="supply-chain"` (+ incluir en `"all"` → 4 lentes). Detecta disrupciones/риesgo de proveedores.
- **Aceptación:** test shape + live; tri/quad-lens verde.

### P4 — PROVE: PDF 6 páginas 4-buyer + Risk Score [ALTA]
- `pdf-report.js` → 6 páginas: Exec Summary · CISO · CFO · General Counsel (EU AI Act Art.12) · Broker (Risk Score 0-100, disclaimer "estimación interna, no Munich Re") · Verify-yourself.
- **Aceptación:** PDF válido renderizado; secciones presentes; comando `openssl ts` real.

### P5 — MEMORY: Cognee default (local) + cita MemArt [MEDIA]
- Cognee default cuando `COGNEE_LIVE` configurado **en local/CLI**; en endpoint público queda off (costo). Nota MemArt en README (citada).
- **Aceptación:** check-cognee live verde; endpoint público no dispara Cognee.

### P6 — OBSERVE + UI nueva con brand Apohara (vía /hallmark) [ALTA, visceral]
- `/api/stream` SSE: emite eventos por stage (FETCH/FORGE/CLASSIFY/PROVE) con duración.
- **UI nueva** (hallmark + tokens Apohara): hero, input+selector de lente (4), progress bars cinematic en vivo (SSE), evidence card, descarga PDF. Fonts y paleta Apohara.
- **Aceptación:** visual-verdict vs apohara.dev (on-brand); deploy smoke en synthex.apohara.dev; SSE muestra stages live.

### P7 — Deck + Dominio + Docs honestos
- Tabla competitiva (solo features verificadas). Claims territoriales honestos.
- Dominio synthex.apohara.dev (requiere acción de Pablo: agregar dominio en Vercel + CNAME DNS).
- README/SLIDES actualizados; citas KVCOMM/MemArt/SkillFortify como fundamento.

## Plan de tests / verificación
- `npm test` verde (76 + nuevos) tras cada fase.
- `scripts/check-bd-apis.mjs` (SERP/Browser/Crawl/Datasets), `check-pipeline-live.mjs all`, `check-cognee-live.mjs`.
- Deploy smoke + visual-verdict de la UI.

## Riesgos / mitigaciones
- Browser/Datasets/Cognee pesados o facturables → fuera del endpoint público por default (flags); rate-limit + guard SSRF ya presentes.
- DNS synthex.apohara.dev → dependencia de Pablo (pasos provistos).
- No romper 76 tests → test-first, commits atómicos por fase, branch aislada.

## Ejecución
Dado que los subagentes OMC no enrutan modelo aquí, la ejecución la haré **directa** (como la sesión anterior): fases secuenciales, verificación live real, commits atómicos en `feat/synthex-v2`, sin merge a main hasta tu OK.

**STATUS: PENDING APPROVAL**
