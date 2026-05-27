# Synthex — Deck (15 slides)

> Guion del pitch para Web Data UNLOCKED. Una historia lineal. Cada claim técnico tiene un
> comando que el juez puede correr. Tono: honesto, sin overclaim (es el arma, no la debilidad).

---

**1 · Hero.** "Your AI agents are scraping the live web right now. Do you know what they found, what they classified, and what you can **prove**?"
*Stats strip: 49 tests green · RFC 3161 timestamp verifiable · 4 Bright Data tools · 3 lenses, 1 pipeline.*

**2 · The drama (May 2026).** Agents are in production scraping the open web — with **no audit trail of what they classified**. EU AI Act (Art. 12 logging) + DORA make that a liability. SIEMs see the agent's infra, not the web content it touched.

**3 · Category.** Synthex = **the evidence layer that lives inside Bright Data**. Not a SIEM, not a scraper, not a governance dashboard: the first pipeline that scrapes → classifies → **signs** web intelligence.

**4 · Architecture (1 slide, 1 diagram).** `Triggerware → FETCH (Bright Data) → FORGE → CLASSIFY (AI/ML) → MEMORY (Cognee) → PROVE (HMAC+TSA) → act`. 100% JS, an MCP companion to `brightdata-mcp`.

**5 · Bright Data is the substrate, not a feature.** Synthex consumes the real `brightdata-mcp` tools (web unlocker, SERP, scraping browser, scrape_batch). **Without Bright Data, zero data.** Live demo: connect + scrape.

**6 · The pipeline, live.** `node scripts/check-pipeline-live.mjs https://en.wikipedia.org/wiki/Bright_Data gtm` → real GTM signals extracted by a frontier LLM ("Acquisition of Market Beyond", "AWS ISV Accelerate", …), sealed.

**7 · The moat: provable evidence.** Every report sealed with HMAC-SHA256 + **RFC 3161 timestamp from DigiCert**. `npm run demo` prints a real token; verification → `hash OK · HMAC OK · TSA OK`. No competitor ships signed web-intel evidence.

**8 · One pipeline, three lenses.** GTM (competitor/pricing/hiring signals) · Finance (vendor risk, regulatory) · Security (threats, leaked creds). Same tube, different classifier prompt. *(Today: Security/GTM run live; Finance is a config of the same classifier.)*

**9 · Always-on, no human in the loop.** Triggerware trigger accumulates web deltas → `react()` polls → fires the pipeline → alert + memory. The watch loop tracks deltas vs. history ("signals before they appear in any feed").

**10 · Partner stack (each verified against the real service).** AI/ML API = the brain (frontier model, extraction). Cognee = the memory (OSS knowledge graph, `remember`/`recall`). Triggerware = react-and-act. Bright Data = the substrate.

**11 · Verify it yourself (60s).** `npm test` (45/4/0) · `npm run demo` (signed report) · `check-pipeline-live.mjs` (live e2e). Public repo: github.com/SuarezPM/apohara-synthex. MIT.

**12 · What we do NOT claim (honesty).** We don't bypass any ToS — we use Bright Data's compliant infra. The TSA proves *when* evidence existed, not the truth of content. Cognee ingest (LLM) is opt-in by cost. Network tests are opt-in so the suite never fakes a pass.

**13 · Multi-track fit.** One submission spans GTM + Finance + Security. The signed audit trail is the enterprise wedge (compliance/security teams *depend* on it).

**14 · Built honestly, fast.** 18 commits, every module test-verified; a real bug (dedup collision) caught by an adversarial test and fixed. Prior art: Context_Forge INV-15 (Zenodo DOI).

**15 · Close.** "**Synthex — scrape it, classify it, prove it.** The web your agents touch, now classified and provable." → live demo + the verification commands.
