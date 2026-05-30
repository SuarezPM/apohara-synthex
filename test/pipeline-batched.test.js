// P1.3 — lens="all" uses classifyBatched (one call pays the untrusted input once) by default, with
// the per-lens classifier kept as the isolation fallback. Zero network: fetcher + classifiers are
// injected and requestTsa:false skips the TSA round-trip.
import { test } from "node:test";
import assert from "node:assert/strict";
import { runPipeline } from "../src/pipeline.js";

const fetcher = async () => [{ url: "https://example.com/", content: "ordinary benign business update, nothing untrusted" }];

test("P1.3 — lens=all issues exactly ONE batched call for the 4 lenses (the cost win)", async () => {
  let calls = 0;
  let sawLenses = null;
  const batchedClassifier = async (_text, lenses) => {
    calls++;
    sawLenses = lenses;
    return Object.fromEntries(lenses.map((l) => [l, { lens: l, severity: 1, summary: "ok", signals: [] }]));
  };
  const ev = await runPipeline("https://example.com/", { lens: "all", fetcher, batchedClassifier, hmacKey: "k", requestTsa: false });
  assert.equal(calls, 1, "one doc → one batched call (not 4 per-lens)");
  assert.deepEqual([...sawLenses].sort(), ["finance", "gtm", "security", "supply-chain"]);
  const f = ev.payload.findings[0];
  assert.ok(f.trilens, "trilens output shape preserved");
  assert.deepEqual(Object.keys(f.trilens).sort(), ["finance", "gtm", "security", "supply-chain"]);
});

test("P1.3 — an injected per-lens classifier keeps the isolation fallback (4 calls, no batching)", async () => {
  let calls = 0;
  const classifier = async (_text, lens) => { calls++; return { lens, severity: 1, summary: "ok", signals: [] }; };
  const ev = await runPipeline("https://example.com/", { lens: "all", fetcher, classifier, hmacKey: "k", requestTsa: false });
  assert.equal(calls, 4, "per-lens classifier injected → 4 calls (isolation preserved, no batching)");
  assert.ok(ev.payload.findings[0].trilens);
});

test("P1.3 — single-lens path is unchanged (per-lens classify, not batched)", async () => {
  let batched = 0, perLens = 0;
  const batchedClassifier = async (_t, lenses) => { batched++; return Object.fromEntries(lenses.map((l) => [l, { lens: l, severity: 0, summary: "", signals: [] }])); };
  const classifier = async (_t, lens) => { perLens++; return { lens, severity: 0, summary: "", signals: [] }; };
  await runPipeline("https://example.com/", { lens: "security", fetcher, classifier, batchedClassifier, hmacKey: "k", requestTsa: false });
  assert.equal(batched, 0, "single lens never batches");
  assert.equal(perLens, 1, "one per-lens call for the single lens");
});
