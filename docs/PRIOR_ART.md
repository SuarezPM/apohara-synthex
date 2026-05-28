# Prior Art — Synthex Delta Evidence Chain

**Date of directed search:** 2026-05-28
**Purpose:** document why Synthex says "we found no open-source combination
of [scrape + diff + HMAC + RFC 3161 + KG]" and what we DID find separately,
so a reviewer can reproduce the queries and challenge the claim.

> We do **NOT** claim "first in world", "novel", or "world's first". Those
> are unverifiable. The defensible claim is: **at the date of this directed
> search, no public open-source repository combined the five primitives in
> the way Synthex does.** If you find a counterexample, please open an issue —
> we update this file within 24 h and the README within the next release.

---

## What Synthex combines

| # | Primitive | Synthex implementation |
|---|---|---|
| 1 | **Headless scrape** of the live web | Bright Data Web Unlocker / SERP / Browser / Crawl / native MCP — `src/fetch/router.js` |
| 2 | **Content-level diff** across re-scrapes | `src/delta/diff.js` chunk-level (`<p>`, `<li>`, `<h*>`) |
| 3 | **HMAC-SHA256** sealing of canonical payload | `src/prove/hmac.js` + `src/prove/canonicalize.js` (RFC 8785 JCS) |
| 4 | **RFC 3161** trusted timestamp from a CA-issued TSA | `src/prove/tsa.js` (DigiCert default) |
| 5 | **Knowledge-graph memory** of the same entities cross-time | `src/memory/cognee-client.js` (Cognee MCP, OSS) |

Synthex chains all five so a re-scrape of the same URL produces an evidence
report whose `payload.delta_chain.previous_tsa_serial → current_tsa_serial`
proves both readings existed at the times shown.

---

## Tools that do PART of this (verified individually)

### Scrape + diff (without crypto)

| Tool | Repo | What it does | What it does NOT |
|---|---|---|---|
| **changedetection.io** | github.com/dgtlmoon/changedetection.io | Polls URLs, diffs HTML/text/JSON, notifies via webhook/email/Telegram | No HMAC, no RFC 3161, no KG, no LLM classification |
| **urlwatch** | github.com/thp/urlwatch | CLI watcher with diff + filters + reporters | No HMAC, no RFC 3161, no KG |
| **webhook-monitor** (various) | many small projects | Same pattern (poll + diff + notify) | Same gap |

### HMAC + RFC 3161 (without scrape or KG)

| Tool | Repo | What it does | What it does NOT |
|---|---|---|---|
| **sigstore / cosign** | github.com/sigstore/cosign | Sign artifacts (containers, binaries) with sigstore transparency log | No scraping, no diff, no KG |
| **opentimestamps** | opentimestamps.org | Bitcoin-anchored timestamping | No HMAC layer, no scrape, no KG |
| **RFC 3161 TSAs** (DigiCert, Sectigo, GlobalSign, Apple) | various | Issue trusted timestamps | They are the **service**, not a pipeline — Synthex uses DigiCert |

### KG memory (without scrape signing)

| Tool | Repo | What it does | What it does NOT |
|---|---|---|---|
| **Cognee** | github.com/topoteretes/cognee | Knowledge graph + Graph RAG for agent memory (Synthex consumes this) | No scrape, no signing |
| **Letta** (ex-MemGPT) | github.com/letta-ai/letta | Long-term agent memory with hierarchical summaries | No signing, no scrape |
| **mem0** | github.com/mem0ai/mem0 | Personalised memory layer for LLMs | No signing, no scrape |

### Web-scraping platforms (without crypto layer)

| Tool | What it does | Gap |
|---|---|---|
| **Bright Data** (the substrate) | Production-grade scrape across Unlocker/SERP/Browser/Crawl/Datasets | No crypto seal, no KG, no LLM classification — **Synthex adds those layers on top, that's literally the product** |
| **Apify** | Hosted scraper marketplace | Same gap |
| **ScrapingBee, ScraperAPI** | REST scraping services | Same gap |

### Triggerware (the partner, the comparable)

**Triggerware** (triggerware.ai) is the closest match: scheduled queries that
emit deltas or send email/webhook. **Documented gap**: no cryptographic seal,
no signature spec public, no KG memory layer described.

Synthex's positioning is explicit: **"Triggerware detects deltas at the data
layer. Synthex seals each delta with a chain that survives off-platform."**
(See `SLIDES.md` slide 10.)

---

## Search queries used (reproducible)

All searches done 2026-05-28 from CachyOS-PC.

### GitHub code search

| Query | Hits relevant to combined scope | Note |
|---|---|---|
| `"changedetection" "RFC 3161"` | 0 | |
| `"scraper" "RFC 3161" cognee` | 0 | |
| `"web scrape" hmac "timestamp authority"` | 0 | |
| `"sealed evidence" scrape diff` | 0 | |
| `"delta evidence" scrape` | 0 | (Synthex hits as match — self-reference excluded) |

### Google web search

- `"scrape + diff + HMAC + timestamp" open source` → no combined hits, only Synthex / Apohara if any
- `"web evidence pipeline" cryptographic chain` → SLSA tooling (provenance for build artifacts, not web data), sigstore (artifact signing)
- `"chain-of-custody" web scraping open source` → forensic-tooling guides, no end-to-end OSS pipeline

### arXiv (papers, not code — but referenced for context)

| arXiv ID | Title (abridged) | Match to Synthex |
|---|---|---|
| **2506.13246** | Immutable Memory Systems: Merkle-anchored claims + provenance | Concept overlap (verifiable memory) but no scrape/diff layer |
| **2511.17118** | Extension of Crosby-Wallach tamper-evident logging | Concept overlap (tamper-evident log) |
| **2505.24478** | Optimizing the Interface Between KGs and LLMs (Cognee team) | Synthex consumes this layer |
| **2509.03821** | Rethinking Tamper-Evident Logging (Zhao et al., ACM CCS 2025) | Cited in `.kiro/specs/delta-engine.md` |
| **2503.22573** | Cryptographic Verifiability of End-to-End AI Pipelines | Closest conceptual match — calls out DECORAIT/C2PA pattern |

### Papers with Code

- "tamper-evident scraping" → 0 results
- "cryptographic web evidence" → 0 results

---

## What we DO claim (precise)

1. **Synthex is the first MCP server that ships all five primitives wired
   into one pipeline that an agent can call as a single tool.** Verified by
   inspection of MCP marketplace 2026-05-28 (no other entry combines them).
2. **Synthex provides a `delta_chain` payload with `previous_tsa_serial →
   current_tsa_serial` that no other inspected tool produces.** The chain
   itself is the contribution.

## What we do NOT claim

- ❌ "First in world to use RFC 3161 with scraped content."
- ❌ "First open-source tool with crypto-signed web evidence."
- ❌ "Novel cryptographic primitive."

We use existing well-known primitives (HMAC-SHA256, RFC 3161, sha256, JCS).
The contribution is the **specific composition** and the **production-quality
end-to-end pipeline** that ships them together.

---

## How to challenge this document

1. Run our queries above and report any hit we missed.
2. Open an issue at github.com/SuarezPM/apohara-synthex.
3. We update this file within 24 h, and either:
   - **Add the prior art** with a "Synthex extends [X] by..." framing in the
     README, OR
   - **Document why the hit does NOT actually combine all five primitives**
     (e.g., "tool X signs containers but not scraped HTML").

Honesty over pride. See PRD principle #1.
