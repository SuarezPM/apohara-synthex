// Unit tests para src/delta/chain.js (T1.2 AC4 del PRD v0.6.0).
// requestTsa: false en todos los tests → 0 red, instantáneo, suite CI compatible.
import { test } from "node:test";
import assert from "node:assert/strict";
import { sealDeltaChain } from "../../src/delta/chain.js";

test("sealDeltaChain: cold start produces evidence con delta_chain.previous_tsa_serial=null", async () => {
  const ev = await sealDeltaChain({
    prev_evidence: null,
    curr_snapshot: {
      target: "https://example.com/pricing",
      lens: "gtm",
      content: "<p>plan price is one hundred dollars</p>",
      fetchedAt: "2026-05-28T15:00:00Z",
    },
    hmacKey: "test-key",
    requestTsa: false,
  });
  assert.equal(ev.payload.schema_version, 2);
  assert.ok(ev.payload.delta_chain);
  assert.equal(ev.payload.delta_chain.previous_tsa_serial, null);
  assert.equal(ev.payload.delta_chain.current_tsa_serial, null); // requestTsa=false
  assert.ok(typeof ev.payload.snapshot_hash === "string");
  assert.equal(ev.payload.snapshot_hash.length, 64);
});

test("sealDeltaChain: cold start diff_summary tiene added > 0, removed = 0", async () => {
  const ev = await sealDeltaChain({
    prev_evidence: null,
    curr_snapshot: {
      target: "https://example.com/x",
      lens: "gtm",
      content: "<p>first chunk here</p><p>second chunk here</p>",
      fetchedAt: "2026-05-28T15:00:00Z",
    },
    hmacKey: "k",
    requestTsa: false,
  });
  assert.ok(ev.payload.delta_chain.diff_summary.added >= 1);
  assert.equal(ev.payload.delta_chain.diff_summary.removed, 0);
});

test("sealDeltaChain: encadena con prev (sin TSA real) preserva previous_tsa_serial=null cuando prev no tenía TSA", async () => {
  const prev = await sealDeltaChain({
    prev_evidence: null,
    curr_snapshot: { target: "x", lens: "gtm", content: "<p>initial chunk here</p>", fetchedAt: "t0" },
    hmacKey: "k",
    requestTsa: false,
  });
  const curr = await sealDeltaChain({
    prev_evidence: prev,
    curr_snapshot: { target: "x", lens: "gtm", content: "<p>initial chunk here</p><p>new chunk here</p>", fetchedAt: "t1" },
    hmacKey: "k",
    requestTsa: false,
  });
  // prev no tenía TSA → previous_tsa_serial sigue siendo null (no se inventa serial).
  assert.equal(curr.payload.delta_chain.previous_tsa_serial, null);
  assert.equal(curr.payload.delta_chain.diff_summary.added, 1);
  assert.equal(curr.payload.delta_chain.diff_summary.removed, 0);
});

test("sealDeltaChain: kg_status default 'skipped' (cold path off por default)", async () => {
  const ev = await sealDeltaChain({
    prev_evidence: null,
    curr_snapshot: { target: "x", lens: "gtm", content: "<p>any chunk here</p>", fetchedAt: "t" },
    requestTsa: false,
  });
  assert.equal(ev.payload.delta_chain.kg_status, "skipped");
  assert.equal(ev.payload.delta_chain.kg_skip_reason, null);
});

test("sealDeltaChain: rechaza curr_snapshot.content no-string", async () => {
  await assert.rejects(
    () => sealDeltaChain({ prev_evidence: null, curr_snapshot: { content: 123 }, requestTsa: false }),
    TypeError,
  );
});

test("sealDeltaChain: rechaza si curr_snapshot ausente", async () => {
  await assert.rejects(
    () => sealDeltaChain({ prev_evidence: null, requestTsa: false }),
    TypeError,
  );
});

test("sealDeltaChain: evidence sigue schema v2 (contentHash + seal + sealedAt)", async () => {
  const ev = await sealDeltaChain({
    prev_evidence: null,
    curr_snapshot: { target: "x", lens: "gtm", content: "<p>some chunk here</p>", fetchedAt: "t" },
    hmacKey: "k",
    requestTsa: false,
  });
  assert.ok(typeof ev.contentHash === "string");
  assert.equal(ev.contentHash.length, 64);
  assert.ok(ev.seal);
  assert.ok(typeof ev.seal.hmacSha256 === "string");
  assert.ok(typeof ev.sealedAt === "string");
});

test("sealDeltaChain: payload.snapshot_hash es estable sobre re-runs idénticos", async () => {
  const opts = {
    prev_evidence: null,
    curr_snapshot: { target: "x", lens: "gtm", content: "<p>identical chunk here</p>", fetchedAt: "t" },
    requestTsa: false,
  };
  const a = await sealDeltaChain(opts);
  const b = await sealDeltaChain(opts);
  assert.equal(a.payload.snapshot_hash, b.payload.snapshot_hash);
});
