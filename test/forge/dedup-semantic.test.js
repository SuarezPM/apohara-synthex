import { test } from "node:test";
import assert from "node:assert/strict";
import { dedupeSemantic } from "../../src/forge/dedup-semantic.js";

// Item 1.4 — optional AI/ML embeddings path for dedup-semantic, Xenova local fallback.
// Estos tests ejercitan SOLO el path AI/ML (fetch stub), porque @xenova/transformers es
// dep opt-in NO instalada por defecto. El default local se valida a mano en CLI con la dep.

/** Stub de fetch que mapea texto → vector determinista (para clusterizar near-dups). */
function withFetchVectors(vectorFor, fn) {
  return async () => {
    const real = globalThis.fetch;
    globalThis.fetch = async (_url, init) => {
      const input = JSON.parse(init.body).input;
      return {
        ok: true,
        status: 200,
        json: async () => ({ data: [{ embedding: vectorFor(input) }] }),
        text: async () => "ok",
      };
    };
    try { return await fn(); }
    finally { globalThis.fetch = real; }
  };
}

test(
  "dedupeSemantic con embedProvider=aiml: agrupa near-dups y sella embedMode=aiml",
  withFetchVectors(
    (t) => (t.includes("alpha") ? [1, 0, 0] : [0, 1, 0]),
    async () => {
      const items = [
        { url: "a", content: "alpha one" },
        { url: "b", content: "alpha two" }, // mismo vector → near-dup de a
        { url: "c", content: "beta three" },
      ];
      const res = await dedupeSemantic(items, {
        embedProvider: "aiml",
        embedModel: "fake/embed-model",
        apiKey: "test-key",
        threshold: 0.92,
      });
      assert.equal(res.stats.embedMode, "aiml");
      assert.equal(res.unique.length, 2, "alpha colapsa a 1, beta queda → 2 únicos");
      assert.equal(res.duplicates.length, 1);
      assert.equal(res.duplicates[0].duplicateOf, "a");
    },
  ),
);

test(
  "dedupeSemantic AI/ML normaliza vectores no-unitarios (cosine==dot tras L2)",
  withFetchVectors(
    () => [3, 4, 0], // norma 5, no unitario → debe normalizarse a [0.6,0.8,0]
    async () => {
      const res = await dedupeSemantic(
        [{ url: "a", content: "x" }, { url: "b", content: "y" }],
        { embedProvider: "aiml", embedModel: "fake/embed", apiKey: "k", threshold: 0.99 },
      );
      // mismo vector normalizado en ambos → cosine 1.0 ≥ 0.99 → b es dup de a
      assert.equal(res.duplicates.length, 1);
      assert.equal(res.unique.length, 1);
    },
  ),
);

test("dedupeSemantic default (sin config AI/ML) reporta embedMode=local", async () => {
  // No llamamos a la red: con 0 items el loop no toca el extractor, pero el modo se decide igual.
  const res = await dedupeSemantic([], {});
  assert.equal(res.stats.embedMode, "local");
  assert.equal(res.unique.length, 0);
});
