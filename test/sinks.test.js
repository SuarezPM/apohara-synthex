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

// ─── v0.8 CaMeL flow-gate tests (HONESTY §8.B) ──────────────────────────

// Helper para armar un evidence con un decision row REVIEW de injection-guard.
function _evidenceWithReview(sourceUrl) {
  return {
    contentHash: "h-test",
    payload: {
      sources: [sourceUrl, "clean.example/x"],
      findings: [{ url: sourceUrl, summary: "borderline finding" }],
      decisions: [
        { url: sourceUrl, outcome: "REVIEW", layer: "injection-guard", stage: "INJECTION_GUARD", guard_mode: "prompt-guard", guard_score: 0.7 },
      ],
    },
  };
}

test("cogneeSink: REVIEW'd source SUPRIME ingest (no opt-in)", async () => {
  let remembered = null;
  const fake = { remember: async (t) => { remembered = t; } };
  const sink = cogneeSink(fake, { env: {} }); // sin SYNTHEX_COGNEE_TRUST_REVIEWED
  await sink({
    target: "acme", lens: "gtm",
    evidence: _evidenceWithReview("borderline.example/x"),
    signals: ["s"], maxSeverity: 5,
  });
  assert.equal(remembered, null, "ingest debe estar suprimido por el CaMeL gate");
});

test("cogneeSink: REVIEW'd source + SYNTHEX_COGNEE_TRUST_REVIEWED=1 → ingiere", async () => {
  let remembered = null;
  const fake = { remember: async (t) => { remembered = t; } };
  const sink = cogneeSink(fake, { env: { SYNTHEX_COGNEE_TRUST_REVIEWED: "1" } });
  await sink({
    target: "acme", lens: "gtm",
    evidence: _evidenceWithReview("borderline.example/x"),
    signals: ["s"], maxSeverity: 5,
  });
  assert.ok(remembered, "con opt-in, el ingest debe ocurrir");
});

test("cogneeSink: sin REVIEW'd sources → ingiere normalmente", async () => {
  let remembered = null;
  const fake = { remember: async (t) => { remembered = t; } };
  const sink = cogneeSink(fake, { env: {} });
  await sink({
    target: "acme", lens: "gtm",
    evidence: { contentHash: "h", payload: { sources: ["clean/x"], findings: [{ summary: "ok" }], decisions: [] } },
    signals: ["s"], maxSeverity: 5,
  });
  assert.ok(remembered, "sin REVIEW, el ingest siempre ocurre");
});

test("webhookSink: REVIEW'd source SUPRIME webhook (no opt-in)", async () => {
  const calls = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url) => { calls.push(url); return { ok: true }; };
  try {
    const sink = webhookSink("https://hook/x", { env: {} });
    await sink({
      alert: { target: "acme", maxSeverity: 9 },
      evidence: _evidenceWithReview("borderline.example/x"),
    });
    assert.equal(calls.length, 0, "webhook debe estar suprimido por el CaMeL gate");
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("webhookSink: REVIEW'd source + SYNTHEX_REACT_TRUST_REVIEWED=1 → dispara", async () => {
  const calls = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url) => { calls.push(url); return { ok: true }; };
  try {
    const sink = webhookSink("https://hook/x", { env: { SYNTHEX_REACT_TRUST_REVIEWED: "1" } });
    await sink({
      alert: { target: "acme", maxSeverity: 9 },
      evidence: _evidenceWithReview("borderline.example/x"),
    });
    assert.equal(calls.length, 1, "con opt-in, el webhook debe dispararse");
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("webhookSink: sin REVIEW'd sources → dispara normalmente", async () => {
  const calls = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url) => { calls.push(url); return { ok: true }; };
  try {
    const sink = webhookSink("https://hook/x", { env: {} });
    await sink({
      alert: { target: "acme", maxSeverity: 9 },
      evidence: { contentHash: "h", payload: { sources: ["clean/x"], decisions: [] } },
    });
    assert.equal(calls.length, 1, "sin REVIEW, el webhook siempre dispara");
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("webhookSink: REVIEW row de DJL (L1 regex) SUPRIME — gate ampliado v1.0.0 (A1)", async () => {
  // v1.0.0 (A1): tras el FP fix D5, DJL/prefilter emiten REVIEW en ingesta. El gate CaMeL se
  // amplió para honrar esas filas — un doc REVIEW'd por L1 regex NO debe disparar el webhook.
  const calls = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url) => { calls.push(url); return { ok: true }; };
  try {
    const sink = webhookSink("https://hook/x", { env: {} });
    await sink({
      alert: { target: "acme", maxSeverity: 9 },
      evidence: {
        contentHash: "h",
        payload: {
          sources: ["x"],
          decisions: [{ url: "x", outcome: "REVIEW", layer: "djl", stage: "DJL", severity: 9 }],
        },
      },
    });
    assert.equal(calls.length, 0, "REVIEW de DJL debe gate-ar el webhook (gate ampliado A1)");
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("webhookSink: REVIEW row de capa NO gateadora NO suprime", async () => {
  // El gate aplica a {injection-guard, djl, prefilter} + stage ALIGNMENT_CHECK. Una capa
  // arbitraria (p.ej. una etapa de classify futura) NO debe gate-ar por accidente.
  const calls = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url) => { calls.push(url); return { ok: true }; };
  try {
    const sink = webhookSink("https://hook/x", { env: {} });
    await sink({
      alert: { target: "acme", maxSeverity: 9 },
      evidence: {
        contentHash: "h",
        payload: {
          sources: ["x"],
          decisions: [{ url: "x", outcome: "REVIEW", layer: "classify-debug" }], // ← capa no gateadora
        },
      },
    });
    assert.equal(calls.length, 1, "REVIEW en una capa fuera del set de gating no debe gate-ar");
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("cogneeSink + webhookSink: Evidence Report cuyo ÚNICO REVIEW row es layer 'djl' → ambos suprimidos (A1)", async () => {
  // Caso integral de la Parte B: un report donde la única señal es un REVIEW de DJL debe
  // suprimir TANTO la ingesta a Cognee COMO el disparo del webhook (sin opt-in).
  const evidence = {
    contentHash: "h-djl",
    payload: {
      sources: ["djl-reviewed.example/x"],
      findings: [{ url: "djl-reviewed.example/x", summary: "kept + reviewed" }],
      decisions: [
        { url: "djl-reviewed.example/x", outcome: "REVIEW", layer: "djl", stage: "DJL", severity: 9 },
      ],
    },
  };

  // Cognee NO ingiere
  let remembered = null;
  const cognee = cogneeSink({ remember: async (t) => { remembered = t; } }, { env: {} });
  await cognee({ target: "acme", lens: "gtm", evidence, signals: ["s"], maxSeverity: 5 });
  assert.equal(remembered, null, "cognee debe suprimir el ingest por el REVIEW de DJL");

  // Webhook NO dispara
  const calls = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url) => { calls.push(url); return { ok: true }; };
  try {
    const webhook = webhookSink("https://hook/x", { env: {} });
    await webhook({ alert: { target: "acme", maxSeverity: 9 }, evidence });
    assert.equal(calls.length, 0, "webhook debe suprimir el disparo por el REVIEW de DJL");
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("defaultSinks: COGNEE_LIVE + SYNTHEX_WEBHOOK_URL => Cognee + webhook", async () => {
  const fakeCognee = { connect: async () => fakeCognee, remember: async () => {} };
  const sinks = await defaultSinks({
    env: { COGNEE_LIVE: "1", SYNTHEX_WEBHOOK_URL: "https://hook.example/x" },
    cogneeClientFactory: () => fakeCognee,
  });
  assert.equal(sinks.length, 2);
});
