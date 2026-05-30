// Tests de Spotlighting (1.6): el envelope usa nonce POR REQUEST (no estático), y el
// CI lint detecta cualquier call-site untrusted→LLM SIN el envelope (test negativo).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spotlight, spotlightInstruction } from "../../src/classify/spotlight.js";
import { auditSource } from "../../scripts/lint-spotlight.mjs";

test("spotlight: envuelve el untrusted con sentinels nonce-tagged", () => {
  const { nonce, wrapped } = spotlight("hello world");
  assert.ok(wrapped.includes(`<<<UNTRUSTED:${nonce}>>>`));
  assert.ok(wrapped.includes(`<<<END:${nonce}>>>`));
  assert.ok(wrapped.includes("hello world"));
});

test("spotlight: nonce DISTINTO por request (no estático/adivinable)", () => {
  const a = spotlight("x").nonce;
  const b = spotlight("x").nonce;
  assert.notEqual(a, b, "dos requests deben generar nonces distintos");
});

test("spotlight: nonce override para determinismo en tests", () => {
  const { wrapped } = spotlight("doc", "fixed-nonce");
  assert.ok(wrapped.includes("<<<UNTRUSTED:fixed-nonce>>>"));
  assert.ok(wrapped.includes("<<<END:fixed-nonce>>>"));
});

test("spotlightInstruction: referencia los sentinels exactos del nonce + DATA", () => {
  const ins = spotlightInstruction("abc123");
  assert.ok(ins.includes("<<<UNTRUSTED:abc123>>>"));
  assert.ok(ins.includes("<<<END:abc123>>>"));
  assert.match(ins, /DATA/);
});

test("lint-spotlight: call-site CON envelope nonce → OK", () => {
  const good = `const r = await fetch(base + "/chat/completions", { body: JSON.stringify({ messages: [{ role: "user", content: spotlight(doc).wrapped }] }) });`;
  const a = auditSource(good);
  assert.equal(a.llm, true);
  assert.equal(a.ok, true);
});

test("lint-spotlight: call-site SIN envelope → detectado (el lint falla, exit 1)", () => {
  const bad = `const r = await fetch(base + "/chat/completions", { body: JSON.stringify({ messages: [{ role: "user", content: rawScrapedDoc }] }) });`;
  const a = auditSource(bad);
  assert.equal(a.llm, true, "es un call-site que postea a un LLM");
  assert.equal(a.ok, false, "untrusted sin envelope → el lint DEBE marcarlo");
});

test("lint-spotlight: archivo que sólo MENCIONA completions en un comentario → no es egress (sin falso positivo)", () => {
  const comment = `// AI/ML API exposes these models at /chat/completions in OpenAI shape.\nexport const X = 1;`;
  assert.equal(auditSource(comment).llm, false);
});
