// Unit tests para src/delta/diff.js (T1.2 AC3 del PRD v0.6.0).
import { test } from "node:test";
import assert from "node:assert/strict";
import { diffSnapshots } from "../../src/delta/diff.js";

test("diff: cold start (prev=null) → all chunks added", () => {
  const curr = "<p>first chunk here</p><p>second chunk here</p>";
  const d = diffSnapshots(null, curr);
  assert.equal(d.removed.length, 0);
  assert.equal(d.changed.length, 0);
  assert.ok(d.added.length >= 1);
});

test("diff: identical content → no changes", () => {
  const html = "<p>same content twice</p><p>another paragraph here</p>";
  const d = diffSnapshots(html, html);
  assert.equal(d.added.length, 0);
  assert.equal(d.removed.length, 0);
});

test("diff: added chunk reported as added", () => {
  const prev = "<p>kept content here</p>";
  const curr = "<p>kept content here</p><p>brand new chunk here</p>";
  const d = diffSnapshots(prev, curr);
  assert.equal(d.added.length, 1);
  assert.match(d.added[0].chunk, /brand new chunk/);
  assert.equal(d.removed.length, 0);
});

test("diff: removed chunk reported as removed", () => {
  const prev = "<p>chunk A here</p><p>chunk B here</p>";
  const curr = "<p>chunk A here</p>";
  const d = diffSnapshots(prev, curr);
  assert.equal(d.removed.length, 1);
  assert.match(d.removed[0].chunk, /chunk B/);
  assert.equal(d.added.length, 0);
});

test("diff: changed chunk reported as removed+added (v0.6 behavior)", () => {
  const prev = "<p>price is one hundred dollars</p>";
  const curr = "<p>price is two hundred dollars</p>";
  const d = diffSnapshots(prev, curr);
  assert.equal(d.added.length, 1);
  assert.equal(d.removed.length, 1);
  assert.equal(d.changed.length, 0); // v0.6 deja changed vacío; v0.7+ pairs by similarity
});

test("diff: each entry has chunk + hash", () => {
  const d = diffSnapshots(null, "<p>chunk with words here</p>");
  for (const e of d.added) {
    assert.equal(typeof e.chunk, "string");
    assert.equal(typeof e.hash, "string");
    assert.equal(e.hash.length, 16);
  }
});

test("diff: rejects non-string curr", () => {
  assert.throws(() => diffSnapshots(null, 123), TypeError);
});

test("diff: rejects non-string prev when set", () => {
  assert.throws(() => diffSnapshots(42, "<p>x</p>"), TypeError);
});

test("diff: prev=undefined behaves like null (cold start)", () => {
  const d = diffSnapshots(undefined, "<p>cold start chunk here</p>");
  assert.ok(d.added.length >= 1);
});

test("diff: ignores very short chunks (<8 chars)", () => {
  const d = diffSnapshots(null, "<p>x</p><p>y</p><p>longer kept chunk here</p>");
  assert.equal(d.added.length, 1);
  assert.match(d.added[0].chunk, /longer kept chunk/);
});
