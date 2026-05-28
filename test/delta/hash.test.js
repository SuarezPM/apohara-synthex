// Unit tests para src/delta/hash.js (T1.2 AC1 del PRD v0.6.0).
import { test } from "node:test";
import assert from "node:assert/strict";
import { hashSnapshot } from "../../src/delta/hash.js";

test("hash: returns 64-char lowercase hex", () => {
  const h = hashSnapshot("hello world");
  assert.equal(h.length, 64);
  assert.match(h, /^[0-9a-f]{64}$/);
});

test("hash: deterministic (same input → same output)", () => {
  const a = hashSnapshot("the quick brown fox");
  const b = hashSnapshot("the quick brown fox");
  assert.equal(a, b);
});

test("hash: distinct inputs → distinct outputs", () => {
  const a = hashSnapshot("alpha");
  const b = hashSnapshot("beta");
  assert.notEqual(a, b);
});

test("hash: known sha256 of 'abc'", () => {
  // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  assert.equal(
    hashSnapshot("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("hash: empty string has a defined sha256", () => {
  // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  assert.equal(
    hashSnapshot(""),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
});

test("hash: rejects non-string", () => {
  assert.throws(() => hashSnapshot(null), TypeError);
  assert.throws(() => hashSnapshot(42), TypeError);
});
