// Tests del SERP signal lens (src/fetch/serp-signal.js).
// Unit: a stub `fetcher` is injected — NUNCA toca el SERP API real en la suite. We assert each signal
// kind builds the right query, the SEAL-READY envelope shape, and a fail-safe failure path.
// Live: opt-in con SERP_LIVE=1 + Bright Data secrets (skipped por defecto).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  scanSignal,
  buildQuery,
  normalizeResults,
  deriveSignals,
  SIGNAL_KINDS,
  SURFACE,
} from "../../src/fetch/serp-signal.js";

// A stub SERP payload in the confirmed brd_json shape (organic[] with title/snippet, +link defensively).
const STUB_SERP = {
  organic: [
    { title: "Acme breach disclosure", url: "https://news.example.com/acme", snippet: "passwords exposed" },
    { title: "Acme careers", link: "https://linkedin.com/jobs/acme", snippet: "hiring 5 engineers" },
  ],
};

// Records every query the lens asked for, returns the stub. Lets us assert the query per kind.
function recordingFetcher(payload = STUB_SERP) {
  const queries = [];
  const fetcher = async (query) => {
    queries.push(query);
    return payload;
  };
  return { fetcher, queries };
}

test("serp-signal: SIGNAL_KINDS is the frozen 4-kind contract", () => {
  assert.deepEqual([...SIGNAL_KINDS].sort(), ["brand-abuse", "credential-leak", "hiring", "regulatory"]);
  assert.ok(Object.isFrozen(SIGNAL_KINDS));
});

test("serp-signal: each kind builds a distinct, kind-appropriate query", () => {
  const cred = buildQuery("Acme", "credential-leak");
  assert.match(cred, /"Acme"/);
  assert.match(cred, /password/);
  assert.match(cred, /site:pastebin\.com/);

  const reg = buildQuery("Acme", "regulatory");
  assert.match(reg, /"Acme"/);
  assert.match(reg, /site:sec\.gov/);

  const abuse = buildQuery("Acme", "brand-abuse");
  assert.match(abuse, /"Acme"/);
  assert.match(abuse, /phishing/);

  const hiring = buildQuery("Acme", "hiring");
  assert.match(hiring, /"Acme"/);
  assert.match(hiring, /site:linkedin\.com/);

  // The four queries are all different (each kind targets a different surface).
  const all = new Set([cred, reg, abuse, hiring]);
  assert.equal(all.size, 4);
});

test("serp-signal: scanSignal sends the kind's query to the injected fetcher (each kind)", async () => {
  for (const kind of SIGNAL_KINDS) {
    const { fetcher, queries } = recordingFetcher();
    const env = await scanSignal("Acme", kind, { fetcher });
    assert.equal(env.ok, true, `${kind} should succeed`);
    assert.equal(queries.length, 1);
    assert.equal(queries[0], buildQuery("Acme", kind), `${kind} query mismatch`);
  }
});

test("serp-signal: success → SEAL-READY envelope shape", async () => {
  const { fetcher } = recordingFetcher();
  const env = await scanSignal("Acme", "credential-leak", { fetcher });

  assert.equal(env.ok, true);
  assert.equal(env.surface, SURFACE);
  assert.equal(env.surface, "serp");
  assert.equal(env.kind, "credential-leak");
  assert.equal(typeof env.query, "string");
  assert.equal(typeof env.fetchedAt, "string");
  assert.ok(!Number.isNaN(Date.parse(env.fetchedAt)), "fetchedAt is an ISO timestamp");

  // results[] normalized to {title,url,snippet}; url read defensively across link/url.
  assert.equal(env.results.length, 2);
  assert.deepEqual(env.results[0], {
    title: "Acme breach disclosure",
    url: "https://news.example.com/acme",
    snippet: "passwords exposed",
  });
  assert.equal(env.results[1].url, "https://linkedin.com/jobs/acme"); // `link` fallback picked up
  for (const r of env.results) {
    assert.deepEqual(Object.keys(r).sort(), ["snippet", "title", "url"]);
  }

  // signals[] is string[] (the classify/redteam convention) and grounded in what the SERP returned.
  assert.ok(Array.isArray(env.signals));
  assert.ok(env.signals.every((s) => typeof s === "string"));
  assert.match(env.signals[0], /2 SERP hit\(s\)/);
});

test("serp-signal: does not mutate the source SERP payload", async () => {
  const payload = { organic: [{ title: "t", url: "https://x.com", snippet: "s" }] };
  const snapshot = JSON.stringify(payload);
  const fetcher = async () => payload;
  await scanSignal("Acme", "hiring", { fetcher });
  assert.equal(JSON.stringify(payload), snapshot, "source payload must be untouched");
});

test("serp-signal: limit caps the normalized results", async () => {
  const big = { organic: Array.from({ length: 25 }, (_, i) => ({ title: `t${i}`, url: `https://x.com/${i}`, snippet: "s" })) };
  const fetcher = async () => big;
  const env = await scanSignal("Acme", "regulatory", { fetcher, limit: 3 });
  assert.equal(env.ok, true);
  assert.equal(env.results.length, 3);
});

test("serp-signal: unknown kind → structured error (no throw), still SEAL-shaped", async () => {
  const { fetcher, queries } = recordingFetcher();
  const env = await scanSignal("Acme", "not-a-kind", { fetcher });
  assert.equal(env.ok, false);
  assert.equal(env.surface, "serp");
  assert.match(env.error, /unknown signal kind/);
  assert.deepEqual(env.results, []);
  assert.deepEqual(env.signals, []);
  assert.equal(queries.length, 0, "must not fetch for an invalid kind");
});

test("serp-signal: missing brand → structured error (no throw)", async () => {
  const env = await scanSignal("   ", "hiring", { fetcher: async () => STUB_SERP });
  assert.equal(env.ok, false);
  assert.match(env.error, /brand\/entity is required/);
});

test("serp-signal: fetcher rejection → fail-safe envelope (never throws)", async () => {
  const fetcher = async () => {
    throw new Error("Bright Data SERP HTTP 401: unauthorized");
  };
  const env = await scanSignal("Acme", "brand-abuse", { fetcher });
  assert.equal(env.ok, false);
  assert.equal(env.surface, "serp");
  assert.equal(env.kind, "brand-abuse");
  assert.match(env.error, /401/);
  assert.deepEqual(env.results, []);
  assert.deepEqual(env.signals, []);
});

test("serp-signal: non-object SERP payload → structured error", async () => {
  const env = await scanSignal("Acme", "hiring", { fetcher: async () => "not json" });
  assert.equal(env.ok, false);
  assert.match(env.error, /non-object payload/);
});

test("serp-signal: empty organic → ok envelope with 'no hits' signal", async () => {
  const env = await scanSignal("Acme", "regulatory", { fetcher: async () => ({ organic: [] }) });
  assert.equal(env.ok, true);
  assert.deepEqual(env.results, []);
  assert.deepEqual(env.signals, ["no SERP hits for regulatory"]);
});

test("serp-signal: normalizeResults tolerates missing fields + a missing link", () => {
  const out = normalizeResults({ organic: [{ title: "only title" }, { snippet: "only snippet" }] });
  assert.deepEqual(out, [
    { title: "only title", url: "", snippet: "" },
    { title: "", url: "", snippet: "only snippet" },
  ]);
});

test("serp-signal: deriveSignals reports count + distinct domains", () => {
  const signals = deriveSignals("hiring", [
    { title: "a", url: "https://linkedin.com/x", snippet: "" },
    { title: "b", url: "https://linkedin.com/y", snippet: "" },
    { title: "c", url: "https://lever.co/z", snippet: "" },
  ]);
  assert.match(signals[0], /3 SERP hit\(s\) for hiring/);
  assert.match(signals[1], /domains: linkedin\.com, lever\.co/); // deduped, order-stable
});

// ─── LIVE smoke test (opt-in) ────────────────────────────────────────────────
// Requires SERP_LIVE=1 + Bright Data secrets (BRIGHT_DATA_TOKEN / BRIGHT_DATA_SERP_ZONE) in the env.
// Skipped by default — never hits the real SERP API in CI. Uses the DEFAULT fetcher (no injection).
test("serp-signal LIVE: real SERP signal scan — opt-in", { skip: process.env.SERP_LIVE !== "1" }, async () => {
  const env = await scanSignal("Bright Data", "regulatory");
  assert.equal(env.surface, "serp");
  assert.equal(typeof env.query, "string");
  if (env.ok) {
    assert.ok(Array.isArray(env.results));
    assert.ok(env.results.every((r) => typeof r.title === "string" && typeof r.snippet === "string"));
  } else {
    // A live failure must still be the structured fail-safe shape, not a throw.
    assert.equal(typeof env.error, "string");
  }
});
