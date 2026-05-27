// Tests de los sinks (delivery de inteligencia). Clientes mockeados — sin red ni LLM.
import { test } from "node:test";
import assert from "node:assert/strict";
import { cogneeSink, webhookSink, defaultSinks } from "../src/sinks.js";

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

test("defaultSinks: con COGNEE_LIVE seteado => incluye el cogneeSink (Cognee default en LOCAL/CLI)", async () => {
  let connected = false, remembered = null;
  const fakeCognee = {
    connect: async () => { connected = true; return fakeCognee; },
    remember: async (text) => { remembered = text; },
  };
  const sinks = await defaultSinks({
    env: { COGNEE_LIVE: "1" },
    cogneeClientFactory: () => fakeCognee,
  });
  assert.equal(sinks.length, 1, "debe haber exactamente un sink (Cognee)");
  assert.equal(connected, true, "debe conectar el CogneeClient antes de usarlo");
  await sinks[0]({
    target: "acme", lens: "gtm",
    evidence: { contentHash: "h1", payload: { findings: [{ summary: "signal" }] } },
    signals: ["price-cut"], maxSeverity: 7,
  });
  assert.match(remembered, /acme/);
});

test("defaultSinks: sin COGNEE_LIVE => NO incluye Cognee (no se dispara LLM por default)", async () => {
  let factoryCalled = false;
  const sinks = await defaultSinks({
    env: {}, // como en el endpoint público (Vercel): COGNEE_LIVE ausente
    cogneeClientFactory: () => { factoryCalled = true; return {}; },
  });
  assert.equal(sinks.length, 0, "sin COGNEE_LIVE no debe haber sinks");
  assert.equal(factoryCalled, false, "no debe ni instanciar el CogneeClient");
});

test("defaultSinks: COGNEE_LIVE + SYNTHEX_WEBHOOK_URL => Cognee + webhook", async () => {
  const fakeCognee = { connect: async () => fakeCognee, remember: async () => {} };
  const sinks = await defaultSinks({
    env: { COGNEE_LIVE: "1", SYNTHEX_WEBHOOK_URL: "https://hook.example/x" },
    cogneeClientFactory: () => fakeCognee,
  });
  assert.equal(sinks.length, 2);
});
