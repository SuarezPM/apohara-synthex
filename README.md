<div align="center">

# ◆ Synthex

### The evidence layer that lives inside Bright Data

**Scrape it · Classify it · Prove it.**
Turn the web your AI agents touch into classified intelligence, sealed with court-grade, verifiable evidence.

![License](https://img.shields.io/badge/license-MIT-blue)
![Tests](https://img.shields.io/badge/tests-47%20passing-brightgreen)
![Node](https://img.shields.io/badge/node-%E2%89%A520-339933?logo=node.js&logoColor=white)
![Runtime](https://img.shields.io/badge/100%25-JavaScript-f7df1e?logo=javascript&logoColor=000)
![MCP](https://img.shields.io/badge/MCP-companion-7c3aed)
![Substrate](https://img.shields.io/badge/substrate-Bright%20Data-ff6b35)

[Quickstart](#-quickstart) · [Verify in 60s](#-verify-it-yourself-60-seconds) · [Architecture](#-architecture) · [Honesty](#-honesty)

<sub>Web Data UNLOCKED Hackathon · Bright Data × lablab.ai · MIT</sub>

</div>

---

> **Your AI agents are scraping the live web right now.**
> Do you know what they found, what they classified, and what you can *prove*?

Synthex is a **100% JavaScript MCP server** that wraps [`brightdata-mcp`](https://github.com/brightdata/brightdata-mcp) and turns raw web scraping into a defensible intelligence pipeline:
**scrape → dedup & screen → classify (GTM · Finance · Security) → remember → seal as verifiable evidence → react.**

**For** AI Operations & Security teams running agents with web access that must account for *what those agents found and decided* — under EU AI Act / DORA.

**The moat:** SIEMs and agent-observability tools watch the agent's *infrastructure*. Synthex sees — and **cryptographically signs** — the web *content* the agent touched. The signed Evidence Report is something no competitor ships.

---

## ◆ Architecture

```
 Triggerware ─(react)─┐                                   ┌─(act)─► alert + webhook
                      ▼                                   │
   FETCH ─────► FORGE ──────────► CLASSIFY ─────► MEMORY ─────► PROVE
   Bright Data  SHA-256 dedup +   AI/ML API       Cognee        HMAC-SHA256
   (MCP tools)  OWASP prefilter   (frontier LLM)  (graph) +     + RFC 3161 TSA
                                  GTM/Fin/Sec      local store   (DigiCert)
```

| Stage | What it does |
|------|--------------|
| **FETCH** | Consumes the real `brightdata-mcp` tools over stdio (`search_engine`, `scrape_as_markdown`, `scrape_batch`…). *No Bright Data, no data.* |
| **FORGE** | SHA-256 dedup + an OWASP prefilter that blocks prompt-injection **before** spending an LLM call. |
| **CLASSIFY** | A frontier model via **AI/ML API** extracts structured signals under one of three lenses. |
| **MEMORY** | Local store for deltas + **Cognee** (OSS, self-hosted) for the knowledge graph. |
| **PROVE** | Every report sealed with HMAC-SHA256 **and** an RFC 3161 timestamp from **DigiCert** — verifiable by anyone. |
| **WATCH / REACT** | Always-on loop: detect change → run the pipeline → alert. No human in the loop. |

---

## ◆ Quickstart

```bash
npm install

# credentials live OUTSIDE the repo (never committed):
export BRIGHT_DATA_TOKEN=...    # Bright Data (promo: unlocked)
export AIML_API_KEY=...         # AI/ML API
export TRIGGERWARE_API_KEY=...  # Triggerware

npm test        # unit suite (network tests are opt-in)
npm run demo    # end-to-end Evidence Report + LIVE DigiCert seal
node server.js  # run as an MCP server (companion to brightdata-mcp)
```

---

## ◆ Verify it yourself (60 seconds)

Don't trust the claims — run them.

```bash
npm test                                   # → 47 pass · 4 skip (opt-in network) · 0 fail
npm run demo                               # → Evidence Report; verify → hash OK · HMAC OK · TSA OK

# Real, live, end-to-end (needs BRIGHT_DATA_TOKEN + AIML_API_KEY):
node scripts/check-pipeline-live.mjs "https://en.wikipedia.org/wiki/Bright_Data" gtm
```

Opt-in live checks (gated by env flags so the suite never fakes a pass): `AIML_LIVE=1` · `TRIGGERWARE_LIVE=1` · `COGNEE_LIVE=1`.

---

## ◆ Partners — each verified against the real service

| Partner | Role in Synthex | Verified |
|---|---|:--:|
| **Bright Data** | FETCH substrate (MCP tools, web unlocker) | ✅ live connect + scrape |
| **AI/ML API** | CLASSIFY brain (frontier model, extraction) | ✅ live classification |
| **Cognee** | MEMORY knowledge graph (OSS, via its MCP) | ✅ tools `remember`/`recall` confirmed |
| **Triggerware** | REACT (poll deltas → fire pipeline) | ✅ live API (`GET /triggers` 200) |

---

## ◆ Honesty

The pitch *is* honesty — so it applies to us too.

- **Proven live:** Bright Data scrape · AI/ML classification · DigiCert RFC 3161 timestamp · Triggerware API · Cognee MCP tools.
- **Opt-in (cost/credentials):** Cognee's `remember` ingest uses an LLM → behind `COGNEE_LIVE`. Network tests are env-gated so the suite never fabricates a pass.
- **Prior art, not pipeline:** the **INV-15** invariant ([Context_Forge paper](https://doi.org/10.5281/zenodo.20277875)) ships as a module and is cited as prior art — it is *not* part of this scraping pipeline.
- **Not claimed:** Synthex doesn't bypass any site's ToS — it uses Bright Data's compliant infrastructure. The timestamp proves *when* evidence existed, not the truth of its content.

---

<div align="center">

**We didn't just use Bright Data — we improved it.**
Upstream contribution: [`brightdata-mcp` PR #140](https://github.com/brightdata/brightdata-mcp/pull/140) (dedup + field filtering). See [`docs/CONTRIBUTION.md`](docs/CONTRIBUTION.md).

MIT © 2026 Pablo M. Suárez · [Apohara]

</div>
