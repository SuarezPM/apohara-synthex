// P2.1 — the react/monitor + MCP paths must seal the REAL Ed25519 by default (not HMAC-only).
// watch.js / tools.js now resolve the persistent signing key and forward it to the pipeline. This
// test proves the WIRING portably (env-based, so it does not depend on a machine's XDG key file):
// when a signing key is resolvable, watchTarget forwards it to its runner; with no key it stays null.
import { test } from "node:test";
import assert from "node:assert/strict";
import { watchTarget } from "../../src/watch.js";

const STUB_EVIDENCE = {
  contentHash: "a".repeat(64),
  sealedAt: "2026-05-30T00:00:00Z",
  payload: { findings: [] },
  seal: {},
};

test("P2.1 — watchTarget forwards an env-resolved signing key to the pipeline (react path seals Ed25519)", async () => {
  const prev = process.env.SYNTHEX_SIGNING_KEY;
  process.env.SYNTHEX_SIGNING_KEY = "dGVzdC1rZXktbWF0ZXJpYWw="; // base64 marker; resolveSigningKey wraps it as PEM
  try {
    let captured = null;
    const runner = async (_target, opts) => { captured = opts; return STUB_EVIDENCE; };
    const store = { recall: () => [], remember: () => {} };
    await watchTarget("https://example.com", { runner, store, sinks: [] });
    assert.ok(captured, "runner was called");
    assert.ok(captured.signingKey, "watch forwarded a signingKey (not symmetric-only)");
    assert.match(captured.signingKey, /BEGIN PRIVATE KEY/, "the key resolved to a normalized PEM");
  } finally {
    if (prev === undefined) delete process.env.SYNTHEX_SIGNING_KEY;
    else process.env.SYNTHEX_SIGNING_KEY = prev;
  }
});

test("P2.1 — an explicit opts.signingKey takes precedence over the resolver", async () => {
  let captured = null;
  const runner = async (_target, opts) => { captured = opts; return STUB_EVIDENCE; };
  const store = { recall: () => [], remember: () => {} };
  await watchTarget("https://example.com", { runner, store, sinks: [], signingKey: "EXPLICIT-PEM" });
  assert.equal(captured.signingKey, "EXPLICIT-PEM");
});
