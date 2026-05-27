<div align="center">

# ◆ Synthex

### The evidence layer that lives inside Bright Data

**Scrape it · Classify it · Prove it.**
Turn the web your AI agents touch into classified intelligence, sealed with court-grade, verifiable evidence.

![License](https://img.shields.io/badge/license-MIT-blue)
![Tests](https://img.shields.io/badge/tests-75%20passing-brightgreen)
![Node](https://img.shields.io/badge/node-%E2%89%A520-339933?logo=node.js&logoColor=white)
![Runtime](https://img.shields.io/badge/100%25-JavaScript-f7df1e?logo=javascript&logoColor=000)
![MCP](https://img.shields.io/badge/MCP-companion-7c3aed)
![Substrate](https://img.shields.io/badge/substrate-Bright%20Data-ff6b35)

### ▶ [Live demo: apohara-synthex.vercel.app](https://apohara-synthex.vercel.app)

[Live demo](https://apohara-synthex.vercel.app) · [Quickstart](#-quickstart) · [Verify in 60s](#-verify-it-yourself-60-seconds) · [Architecture](#-architecture) · [Honesty](#-honesty)

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
| **FETCH** | Consumes the real `brightdata-mcp` tools over stdio (`search_engine`, `scrape_as_markdown`, `scrape_batch`…), **or** the Bright Data Web Unlocker REST API for serverless (Vercel). *No Bright Data, no data.* |
| **FORGE** | SHA-256 dedup + a **20-rule** OWASP prefilter (incl. BrowseSafe / VPI-Bench 2026 injection vectors) that blocks malicious content **before** spending an LLM call. |
| **CLASSIFY** | A frontier model via **AI/ML API** extracts structured signals under one lens — or all **three lenses in parallel** (`lens="all"` → GTM + Finance + Security). |
| **MEMORY** | Local store for deltas + **Cognee** (OSS, self-hosted) for the knowledge graph. |
| **PROVE** | Every report sealed with HMAC-SHA256 **and** an RFC 3161 timestamp from **DigiCert** — exportable as a **downloadable PDF Evidence Report**, verifiable by anyone. |
| **OBSERVE** | Every stage emits OpenTelemetry GenAI spans (`gen_ai.client.operation.duration`, token usage, blocked count). OTLP export is opt-in; latencies show in the demo/UI. |
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
SYNTHEX_TRACE=console npm run demo   # same, with per-stage OTel latencies printed
node server.js  # run as an MCP server (companion to brightdata-mcp)
```

**Web UI / Vercel:** `public/` + `api/` deploy as a static site + serverless functions
(`vercel deploy`). The deployed `/api/analyze` runs the **full live pipeline** via the Bright
Data REST API; set `BRIGHT_DATA_TOKEN`, `WEB_UNLOCKER_ZONE`, `AIML_API_KEY`, `SYNTHEX_HMAC_KEY`
in the project env (without them it falls back to a labeled cached demo). The public endpoint is
guarded (SSRF block + per-IP rate-limit). → **[apohara-synthex.vercel.app](https://apohara-synthex.vercel.app)**

---

## ◆ Verify it yourself (60 seconds)

Don't trust the claims — run them.

```bash
npm test                                   # → 75 pass · 5 skip (opt-in network) · 0 fail
npm run demo                               # → Evidence Report; verify → hash OK · HMAC OK · TSA OK

# Real, live, end-to-end (needs BRIGHT_DATA_TOKEN + AIML_API_KEY):
node scripts/check-pipeline-live.mjs "https://en.wikipedia.org/wiki/Bright_Data" all   # 3 lenses in parallel
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

- **Proven live:** Bright Data scrape (MCP **and** REST) · AI/ML classification (single + tri-lens) · DigiCert RFC 3161 timestamp · downloadable PDF · Vercel deploy (`/api/analyze` live, end-to-end) · Triggerware API · Cognee MCP tools.
- **Opt-in (cost/credentials):** Cognee's `remember` ingest uses an LLM → behind `COGNEE_LIVE`. OTel OTLP export only runs if `OTEL_EXPORTER_OTLP_ENDPOINT` is set (otherwise spans are no-op / console-only). Network tests are env-gated so the suite never fabricates a pass.
- **Prefilter scope:** the 20-rule FORGE filter covers **text/HTML** injection (incl. BrowseSafe / VPI-Bench vectors). It does **not** stop *visual* prompt injection (VPI in rendered screenshots/images) — that's a different threat model. CSS-hiding rules flag the delivery technique (REVIEW); the payload text is what triggers BLOCK.
- **Endpoint guard is best-effort:** the public rate-limit is in-memory per warm instance (a hard multi-instance limit would need Vercel KV). The SSRF block filters the hostname (literal + obfuscated/IPv6 private ranges) but does **not** resolve DNS, so a public domain pointing at a private IP (DNS rebinding) would pass — low risk here because the scrape runs on Bright Data's *remote* proxy, not the function's network.
- **Prior art, not pipeline:** the **INV-15** invariant ([Context_Forge paper](https://doi.org/10.5281/zenodo.20277875)) ships as a module and is cited as prior art — it is *not* part of this scraping pipeline.
- **Not claimed:** Synthex doesn't bypass any site's ToS — it uses Bright Data's compliant infrastructure. The timestamp proves *when* evidence existed, not the truth of its content.

---

<div align="center">

**We didn't just use Bright Data — we improved it.**
Upstream contribution: [`brightdata-mcp` PR #140](https://github.com/brightdata/brightdata-mcp/pull/140) (dedup + field filtering). See [`docs/CONTRIBUTION.md`](docs/CONTRIBUTION.md).

MIT © 2026 Pablo M. Suárez · [Apohara]

</div>
