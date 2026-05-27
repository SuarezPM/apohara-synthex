# Synthex — Deck (15 slides)

> Guion del pitch para Web Data UNLOCKED. Una historia lineal. Cada claim técnico tiene un
> comando que el juez puede correr. Tono: honesto, sin overclaim (es el arma, no la debilidad).

---

**1 · Hero.** "Your AI agents are scraping the live web right now. Do you know what they found, what they classified, and what you can **prove**?"
*Stats strip: 75 tests pass · RFC 3161 timestamp verifiable · 20-rule injection prefilter · 3 lenses in parallel · live UI on Vercel.*

**2 · The drama (May 2026).** Agents are in production scraping the open web — with **no audit trail of what they classified**. EU AI Act (Art. 12 logging) + DORA make that a liability. SIEMs see the agent's infra, not the web content it touched.

**3 · Category.** Synthex = **the evidence layer that lives inside Bright Data**. Not a SIEM, not a scraper, not a governance dashboard: the first pipeline that scrapes → classifies → **signs** web intelligence.

**4 · Architecture (1 slide, 1 diagram).** `Triggerware → FETCH (Bright Data) → FORGE → CLASSIFY (AI/ML) → MEMORY (Cognee) → PROVE (HMAC+TSA) → act`. 100% JS, an MCP companion to `brightdata-mcp` — **and** a serverless web app (Vercel) running the same pipeline over Bright Data's REST API. Every stage emits OpenTelemetry GenAI spans (duration, tokens, blocked count).

**5 · Bright Data is the substrate, not a feature.** Synthex consumes the real `brightdata-mcp` tools (web unlocker, SERP, scraping browser, scrape_batch). **Without Bright Data, zero data.** Live demo: connect + scrape.

**6 · The pipeline, live (and in your browser).** `node scripts/check-pipeline-live.mjs https://en.wikipedia.org/wiki/Bright_Data all` → real GTM + Finance + Security signals extracted by a frontier LLM, sealed. Or just open **apohara-synthex.vercel.app**, paste a URL, watch the 4 stages and their latencies, download the signed PDF.

**7 · The moat: provable evidence.** Every report sealed with HMAC-SHA256 + **RFC 3161 timestamp from DigiCert**, exportable as a **downloadable PDF Evidence Report** with a `openssl ts` verify command on it. `npm run demo` prints a real token; verification → `hash OK · HMAC OK · TSA OK`. No competitor ships signed web-intel evidence.

**8 · One pipeline, three lenses — in parallel.** `lens="all"` runs GTM (competitor/pricing/hiring) · Finance (vendor risk, regulatory) · Security (threats, leaked creds) concurrently on the same scrape. All three verified live against the AI/ML API.

**9 · Always-on, no human in the loop.** Triggerware trigger accumulates web deltas → `react()` polls → fires the pipeline → alert + memory. The watch loop tracks deltas vs. history ("signals before they appear in any feed").

**10 · Partner stack (each verified against the real service).** AI/ML API = the brain (frontier model, extraction). Cognee = the memory (OSS knowledge graph, `remember`/`recall`). Triggerware = react-and-act. Bright Data = the substrate.

**11 · Verify it yourself (60s).** `npm test` (75 pass / 5 skip / 0 fail) · `npm run demo` (signed report) · `check-pipeline-live.mjs … all` (live e2e, 3 lenses) · or the live UI **apohara-synthex.vercel.app**. Public repo: github.com/SuarezPM/apohara-synthex. MIT.

**12 · What we do NOT claim (honesty).** We don't bypass any ToS — we use Bright Data's compliant infra. The TSA proves *when* evidence existed, not the truth of content. The 20-rule prefilter stops **text/HTML** injection (BrowseSafe/VPI-Bench vectors), **not** *visual* VPI in screenshots. OTel OTLP export and Cognee ingest are opt-in. Network tests are opt-in so the suite never fakes a pass.

**13 · Multi-track fit.** One submission spans GTM + Finance + Security. The signed audit trail is the enterprise wedge (compliance/security teams *depend* on it).

**14 · Built honestly, fast.** Every module test-verified; a real bug (dedup collision) caught by an adversarial test and fixed; even an over-claim (INV-15 "in the pipeline") caught in review and corrected. Prior art: Context_Forge INV-15 (Zenodo DOI).

**15 · Close.** "**Synthex — scrape it, classify it, prove it.** The web your agents touch, now classified and provable." → live demo + the verification commands.
