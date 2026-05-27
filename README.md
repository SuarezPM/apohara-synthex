# Synthex — the evidence layer that lives inside Bright Data

> **Your AI agents are scraping the live web right now. Do you know what they found, what they classified, and what you can prove?**
> Synthex turns the web your agents scrape **via Bright Data** into classified intelligence sealed with **verifiable, court-grade evidence** (HMAC-SHA256 + RFC 3161 timestamp).

Built for the **Web Data UNLOCKED Hackathon** (Bright Data · lablab.ai). MIT licensed. 100% JavaScript — a native MCP companion to [`brightdata-mcp`](https://github.com/brightdata/brightdata-mcp).

---

## What it is (one line)

A MCP server that **wraps `brightdata-mcp`** and adds a pipeline: scrape → dedup/screen → classify (GTM / Finance / Security) → remember → **seal as verifiable evidence** → react.

**Who it's for:** AI Operations & Security teams running agents with web access that must account for *what they found and decided* — under EU AI Act / DORA.

**What's new here (vs. internal tools):** SIEMs and agent-observability see the agent's *infrastructure*; Synthex sees and **signs the web content** the agent touched. The signed evidence report is the moat.

---

## Architecture

```
 Triggerware (react)                                            act ──► alert + webhook
        │                                                              │
        ▼                                                              ▲
   FETCH ──────► FORGE ──────────► CLASSIFY ───────► MEMORY ──────► PROVE
   Bright Data   dedup +           AI/ML API         Cognee          HMAC-SHA256
   (MCP tools)   INV-15 gate +     (frontier LLM)    (graph) +       + RFC 3161 TSA
                 OWASP prefilter   GTM/Fin/Sec        local store     (DigiCert)
```

- **FETCH** — consumes the real `brightdata-mcp` tools over stdio (`search_engine`, `scrape_as_markdown`, `scrape_batch`, …). No Bright Data, no data.
- **FORGE** — SHA-256 dedup, the **INV-15 safety gate** (heuristic ported from the [Context_Forge paper](https://doi.org/10.5281/zenodo.20277875)), and an OWASP prefilter that blocks prompt-injection before spending an LLM call.
- **CLASSIFY** — a frontier model via **AI/ML API** (`deepseek/deepseek-non-thinking-v3.2-exp` by default) extracts structured signals under one of three lenses.
- **MEMORY** — a local store for deltas + **Cognee** (OSS, self-hosted) for the knowledge graph.
- **PROVE** — every report sealed with HMAC-SHA256 (always) and an **RFC 3161 timestamp from DigiCert** (verifiable by any third party).
- **WATCH / REACT** — always-on loop: detect change → run the pipeline → alert, with no human in the loop.

---

## Quick start

```bash
npm install
# credentials live OUTSIDE the repo (never committed):
export BRIGHT_DATA_TOKEN=...   # Bright Data API token (promo: unlocked)
export AIML_API_KEY=...        # AI/ML API
export TRIGGERWARE_API_KEY=... # Triggerware

npm test            # unit suite (network tests are opt-in, see below)
npm run demo        # end-to-end Evidence Report on a cached snapshot + LIVE DigiCert seal
```

Run as an MCP server (companion to brightdata-mcp): `node server.js` — exposes the tools
`synthex_scrape_classify_prove`, `synthex_verify_evidence`, `synthex_monitor`.

---

## Verify it yourself (≈60 seconds)

```bash
npm test                                   # 45 pass / 4 skip (opt-in network) / 0 fail
npm run demo                               # prints an Evidence Report; verify → hash/HMAC/TSA OK

# Real, live, end-to-end (needs BRIGHT_DATA_TOKEN + AIML_API_KEY):
node scripts/check-pipeline-live.mjs "https://en.wikipedia.org/wiki/Bright_Data" gtm
```

Opt-in live checks (require credentials, so they don't fail CI on cost/funds):
`AIML_LIVE=1`, `TRIGGERWARE_LIVE=1`, `COGNEE_LIVE=1`.

---

## Partner integrations (each verified against the real service)

| Partner | Role in Synthex | Verified |
|---|---|---|
| **Bright Data** | FETCH substrate (MCP tools, web unlocker) | ✅ live connect + scrape |
| **AI/ML API** | CLASSIFY brain (frontier model, extraction/summarization) | ✅ live classification |
| **Cognee** | MEMORY knowledge graph (OSS, self-hosted via its MCP) | ✅ MCP started, tools `remember`/`recall` confirmed |
| **Triggerware** | REACT (triggers accumulate deltas → poll → pipeline) | ✅ live API (`GET /triggers` 200) |

---

## Honesty (what's proven vs. what's opt-in)

- **Proven live:** Bright Data scrape, AI/ML classification, DigiCert RFC 3161 timestamp, Triggerware API, Cognee MCP tool names.
- **Opt-in (cost/credentials):** the Cognee `remember` ingest uses an LLM (MiniMax) → behind `COGNEE_LIVE`. Live network tests are behind env flags so the suite never fabricates a pass.
- **Not claimed:** Synthex does not bypass any site's ToS; it uses Bright Data's compliant infrastructure. The TSA proves *when* evidence existed, not the truth of its content.

## License

MIT © 2026 Pablo M. Suárez (Apohara). Prior art: Context_Forge INV-15 ([Zenodo DOI 10.5281/zenodo.20277875](https://doi.org/10.5281/zenodo.20277875)).
