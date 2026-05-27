// Tests de los sinks (delivery de inteligencia). Clientes mockeados — sin red.
import { test } from "node:test";
import assert from "node:assert/strict";
import { cogneeSink, webhookSink } from "../src/sinks.js";

test("cogneeSink: ingiere la inteligencia al grafo vía cogneeClient.remember", async () => {
  let remembered = null;
  const fakeCognee = { remember: async (text) => { remembered = text; } };
  const sink = cogneeSink(fakeCognee);
  await sink({
    target: "acme", lens: "gtm",
    evidence: { contentHash: "h1", payload: { findings: [{ summary: "price cut signal" }] } },
    signals: ["price-cut"], maxSeverity: 7,
  });
  assert.match(remembered, /acme/);
  assert.match(remembered, /price cut signal/);
  assert.match(remembered, /price-cut/);
});

test("webhookSink: postea la alerta; sin alerta no hace nada", async () => {
  const calls = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => { calls.push({ url, body: JSON.parse(opts.body) }); return { ok: true }; };
  try {
    const sink = webhookSink("https://hook.example/x");
    await sink({ alert: null });           // sin alerta → no dispara
    assert.equal(calls.length, 0);
    await sink({ alert: { target: "acme", maxSeverity: 9 } });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://hook.example/x");
    assert.equal(calls[0].body.target, "acme");
  } finally {
    globalThis.fetch = origFetch;
  }
});
