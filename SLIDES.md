# Synthex — Deck (15 slides)

> Guion del pitch para Web Data UNLOCKED. Una historia lineal. Cada claim técnico tiene un
> comando que el juez puede correr. Tono: honesto, sin overclaim (es el arma, no la debilidad).

---

**1 · Hero.** "Your AI agents are scraping the live web right now. Do you know what they found, what they classified, and what you can **prove**?"
*Stats strip: 133 tests · 124 pass / 9 skip / 0 fail · RFC 3161 timestamp verifiable · 28-rule injection prefilter · 4 lenses in parallel · live UI on Vercel.*

**2 · The drama (May 2026).** Agents are in production scraping the open web — with **no audit trail of what they classified**. EU AI Act (Art. 12 logging) + DORA make that a liability. SIEMs see the agent's infra, not the web content it touched.

**3 · Category.** Synthex = **the evidence layer that lives inside Bright Data**. Not a SIEM, not a scraper, not a governance dashboard: the first pipeline that scrapes → classifies → **signs** web intelligence.

**4 · Architecture (1 slide, 1 diagram).** `Triggerware → FETCH (Bright Data, 5 APIs) → FORGE (28-rule prefilter) → CLASSIFY (AI/ML, 4 lenses ‖) → PROVE (HMAC+RFC 3161 TSA + 6-page PDF) → OBSERVE (OTel) → MEMORY (Cognee) → act`. 100% JS, an MCP companion to `brightdata-mcp` — **and** a serverless web app (Vercel) running the same pipeline over Bright Data's REST API, streaming per-stage progress to the UI over SSE. Every stage emits OpenTelemetry GenAI spans (duration, tokens, blocked count).

**5 · Bright Data is the substrate, not a feature.** Synthex routes each target to the right Bright Data surface: **Web Unlocker** (MCP + REST), **SERP API**, **Browser API** (Playwright CDP), **Web Scraper / Datasets**, **Crawl API**, **native MCP**. **Without Bright Data, zero data.** Honesty: **all 6 verified live** — Crawl is a multi-page crawl over Web Unlocker (native Crawl API opt-in). Live demo: connect + scrape.

**6 · The pipeline, live (and in your browser).** `node scripts/check-pipeline-live.mjs https://en.wikipedia.org/wiki/Bright_Data all` → real GTM + Finance + Security + Supply-chain signals extracted by a frontier LLM, sealed. Or just open **apohara-synthex.vercel.app**, paste a URL, watch the stages stream in over SSE with their latencies, download the signed 6-page PDF.

**7 · The moat: provable evidence.** Every report sealed with HMAC-SHA256 + **RFC 3161 timestamp from DigiCert**, exportable as a **6-page downloadable PDF Evidence Report** — 4-buyer framing (CISO · CFO · General Counsel · Broker) + a Synthex Risk Score 0–100 — with an `openssl ts` verify command on it. `npm run demo` prints a real token; verification → `hash OK · HMAC OK · TSA OK`. No competitor ships signed web-intel evidence. (The Risk Score is an internal deterministic estimate, **not** a Munich Re rating.)

**8 · One pipeline, four lenses — in parallel.** `lens="all"` runs GTM (competitor/pricing/hiring) · Finance (vendor risk, regulatory) · Security (threats, leaked creds) · Supply-chain (supplier/logistics disruption) concurrently on the same scrape. All four verified live against the AI/ML API. The parallel design is grounded in **KVCOMM** (NeurIPS 2025).

**9 · Always-on, no human in the loop.** Triggerware trigger accumulates web deltas → `react()` polls → fires the pipeline → alert + memory. The watch loop tracks deltas vs. history ("signals before they appear in any feed").

**10 · Partner stack (each verified against the real service).** AI/ML API = the brain (frontier model, extraction). Cognee = the memory (OSS knowledge graph, `remember`/`recall`). Triggerware = react-and-act. Bright Data = the substrate.

**11 · Verify it yourself (60s).** `npm test` (133 tests · 124 pass / 9 skip / 0 fail) · `npm run demo` (signed report) · `check-pipeline-live.mjs … all` (live e2e, 4 lenses) · or the live UI **apohara-synthex.vercel.app** · live at **synthex.apohara.dev**. Public repo: github.com/SuarezPM/apohara-synthex. MIT.

**12 · What we do NOT claim (honesty).** We don't bypass any ToS — we use Bright Data's compliant infra. **All 6** Bright Data surfaces verified live; Crawl is a multi-page crawl over Web Unlocker (not the native Crawl product). The TSA proves *when* evidence existed, not the truth of content. The 28-rule prefilter is **heuristic regex** (aligned with SkillFortify, arXiv 2603.00195) over **text/HTML** injection — **not** a formal proof, and **not** *visual* VPI in screenshots. The PDF Risk Score is an internal estimate, not a Munich Re rating. OTel OTLP export and Cognee memory are opt-in (Cognee off on the public endpoint). The public rate-limit is best-effort (in-memory per warm instance). Network tests are opt-in so the suite never fakes a pass.

**13 · Multi-track fit.** One submission spans GTM + Finance + Security. The signed audit trail is the enterprise wedge (compliance/security teams *depend* on it).

**14 · Built honestly, fast.** Every module test-verified; a real bug (dedup collision) caught by an adversarial test and fixed; even an over-claim (INV-15 "in the pipeline") caught in review and corrected. Prior art: Context_Forge INV-15 (Zenodo DOI).

**15 · Close.** "**Synthex — scrape it, classify it, prove it.** The web your agents touch, now classified and provable." → live demo + the verification commands.
