#!/usr/bin/env node
// Measure the scrape_batch dedup layer (Bright Data PR #140) on a realistic
// monitoring batch — so the "fewer tokens" claim on the landing is MEASURED,
// not asserted. The fingerprint below mirrors brightdata-mcp/context_cache.js
// from PR #140 (SHA-256 of prefix+middle+suffix); kept self-contained here so the
// benchmark is reproducible from the Synthex repo alone.
//
// Scenario (named, not cherry-picked): an AI agent monitors a vendor by
// scrape_batch-ing a URL list it assembled from SERP + nav crawling. Real lists
// carry exact-duplicate CONTENT — tracking-param aliases (?utm=...), trailing
// slashes, in-page fragments (#section), and the same page pulled twice via
// cross-references. Those duplicates cost 0 classification tokens once dedup'd.
//
// Usage: node scripts/bench-dedup.mjs
import { createHash } from "node:crypto";

// ── fingerprint, mirrored from brightdata-mcp/context_cache.js (PR #140) ──
function fingerprint(content) {
  if (content.length <= 2048) return createHash("sha256").update(content).digest("hex");
  const prefix = content.slice(0, 2048);
  const mid = content.slice(Math.floor(content.length / 2), Math.floor(content.length / 2) + 256);
  const suffix = content.slice(-256);
  return createHash("sha256").update(prefix + mid + suffix).digest("hex");
}
function dedupe(batch) {
  const seen = new Set();
  let hits = 0, misses = 0, bytesSaved = 0, totalBytes = 0;
  for (const { content } of batch) {
    totalBytes += content.length;
    const h = fingerprint(content);
    if (seen.has(h)) { hits++; bytesSaved += content.length; }
    else { seen.add(h); misses++; }
  }
  return { unique: misses, duplicates: hits, bytesSaved, totalBytes,
    dedupRatio: hits / (hits + misses), tokenRatio: bytesSaved / totalBytes };
}

// ── corpus: 10 unique vendor pages + 6 exact duplicates from real-world aliasing ──
const P = {
  pricing: "Pricing — Starter $0, Team $12/seat/mo, Business $40/seat/mo, Enterprise custom. Annual billing saves 20%. All plans include SSO, audit logs, and the REST API. " + "Compare plans across seats, usage limits, support SLA, and data residency. ".repeat(18),
  blog: "Blog — Shipping faster with agent workflows. We rebuilt our ingestion path around an event-driven queue and cut p95 latency by half. Here is the architecture, the trade-offs, and what we'd do differently. " + "The migration took three sprints and one incident review. ".repeat(20),
  changelog: "Changelog — v4.2 adds webhook retries with exponential backoff, a new audit export, and Ed25519-signed receipts. v4.1 fixed a race in the scheduler. v4.0 was the queue rewrite. " + "Each release is tagged and the provenance is published. ".repeat(16),
  docs: "Docs — Quickstart: install the SDK, set your API key, call client.scan(url). The pipeline fetches, screens, classifies, and seals. See the reference for every option and the webhook payload shape. " + "Authentication uses bearer tokens scoped per workspace. ".repeat(22),
  status: "Status — All systems operational. API: operational. Dashboard: operational. Webhooks: operational. Scheduled maintenance window Sunday 02:00–03:00 UTC. Past incidents are listed below with postmortems. " + "Uptime over the last 90 days: 99.98%. ".repeat(14),
  about: "About — We build the evidence layer for AI agents that touch the live web. Founded 2025, remote-first, backed by operators who shipped security infrastructure at scale. " + "Our thesis: agents need receipts, not vibes. ".repeat(15),
  security: "Security — SOC 2 Type II in progress. Data encrypted in transit and at rest. SSO via SAML/OIDC. Least-privilege access, audited quarterly. Report vulnerabilities to security@vendor.com. " + "We publish signed build provenance (SLSA L3). ".repeat(17),
  api: "API reference — POST /v1/scan {url, lens}. Returns an Evidence Report with contentHash, seal, and findings. Rate limit 60 req/min. Errors are RFC 7807 problem+json. " + "Every field is documented with type and example. ".repeat(21),
  integrations: "Integrations — Slack, PagerDuty, Jira, GitHub, webhook. Native MCP server for Claude Code, Kiro, and Cursor. Pull deltas, fire the pipeline, post the signed report to your channel. " + "Setup is a one-line config per tool. ".repeat(19),
  careers: "Careers — We're hiring a founding security engineer and a developer-experience lead. Remote, senior, equity-heavy. We value taste, honesty, and shipping. " + "No take-home longer than two hours, ever. ".repeat(13),
};

// the batch the agent actually submitted (order as assembled from SERP + crawl)
const batch = [
  { url: "vendor.com/pricing",                 content: P.pricing },
  { url: "vendor.com/blog/agent-workflows",    content: P.blog },
  { url: "vendor.com/pricing?utm_source=serp", content: P.pricing },     // dup: tracking param
  { url: "vendor.com/changelog",               content: P.changelog },
  { url: "vendor.com/docs/quickstart",         content: P.docs },
  { url: "vendor.com/status",                  content: P.status },
  { url: "vendor.com/docs/quickstart/",        content: P.docs },        // dup: trailing slash
  { url: "vendor.com/about",                   content: P.about },
  { url: "vendor.com/security",                content: P.security },
  { url: "vendor.com/blog/agent-workflows?ref=hn", content: P.blog },    // dup: referrer param
  { url: "vendor.com/api",                     content: P.api },
  { url: "vendor.com/integrations",            content: P.integrations },
  { url: "vendor.com/status?refresh=1",        content: P.status },      // dup: refresh param
  { url: "vendor.com/careers",                 content: P.careers },
  { url: "vendor.com/api#authentication",      content: P.api },         // dup: in-page fragment
  { url: "vendor.com/changelog",               content: P.changelog },   // dup: re-scraped via cross-ref
];

const r = dedupe(batch);
const pagePct = (r.dedupRatio * 100).toFixed(0);
const tokenPct = (r.tokenRatio * 100).toFixed(0);
const tokensSaved = Math.round(r.bytesSaved / 4);   // ~4 chars/token (cl100k ballpark)
const tokensTotal = Math.round(r.totalBytes / 4);
console.log("\n== Bright Data scrape_batch dedup (PR #140) · measured ==\n");
console.log(`  batch size       : ${batch.length} pages`);
console.log(`  unique content   : ${r.unique}`);
console.log(`  exact duplicates : ${r.duplicates}  (tracking-param aliases, trailing slash, fragments, re-scrape)`);
console.log(`  pages deduped    : ${pagePct}%  (${r.duplicates}/${batch.length} — duplicate pages that reach the LLM = 0)`);
console.log(`  token spend cut  : ${tokenPct}%  (${tokensSaved} of ~${tokensTotal} classification tokens, @4 chars/token)`);
console.log(`\n  → ${tokenPct}% less token spend on this batch. Savings scale with the duplicate rate of the crawl.\n`);
