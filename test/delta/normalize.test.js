// Unit tests para src/delta/normalize.js (T1.2 AC2 del PRD v0.6.0).
import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeContent } from "../../src/delta/normalize.js";

test("normalize: strip <script> blocks", () => {
  const html = "<p>keep</p><script>analytics.track('view')</script><p>also keep</p>";
  const out = normalizeContent(html);
  assert.ok(!out.includes("analytics.track"));
  assert.ok(out.includes("keep"));
  assert.ok(out.includes("also keep"));
});

test("normalize: strip <style> blocks", () => {
  const html = "<style>.x{color:red}</style><p>content</p>";
  const out = normalizeContent(html);
  assert.ok(!out.includes("color:red"));
  assert.ok(out.includes("content"));
});

test("normalize: strip HTML comments", () => {
  const html = "<p>visible</p><!-- secret build id 0x1234 --><p>also</p>";
  const out = normalizeContent(html);
  assert.ok(!out.includes("secret build id"));
});

test("normalize: strip csrf/nonce attributes", () => {
  const a = '<form data-csrf="abc123"><input nonce="x42"/></form>';
  const b = '<form data-csrf="xyz999"><input nonce="z88"/></form>';
  assert.equal(normalizeContent(a), normalizeContent(b));
});

test("normalize: strip framework-generated IDs", () => {
  const a = '<div id="ember1234">hello</div>';
  const b = '<div id="ember9999">hello</div>';
  assert.equal(normalizeContent(a), normalizeContent(b));
});

test("normalize: strip inline ISO timestamps", () => {
  const a = "<p>Posted at 2026-05-28T15:00:00Z</p>";
  const b = "<p>Posted at 2026-05-28T17:30:00Z</p>";
  assert.equal(normalizeContent(a), normalizeContent(b));
});

test("normalize: strip view counters", () => {
  const a = "<span>12,345 views</span>";
  const b = "<span>98,765 views</span>";
  assert.equal(normalizeContent(a), normalizeContent(b));
});

test("normalize: strip 'Updated N minutes ago'", () => {
  const a = "<span>Updated 5 minutes ago</span>";
  const b = "<span>Updated 47 minutes ago</span>";
  assert.equal(normalizeContent(a), normalizeContent(b));
});

test("normalize: collapse whitespace runs", () => {
  const a = "<p>   one\t\t  two  </p>";
  const b = "<p> one two </p>";
  assert.equal(normalizeContent(a), normalizeContent(b));
});

test("normalize: idempotent (same input → same output)", () => {
  const html = "<p>Stable content</p><script>x()</script>";
  assert.equal(normalizeContent(html), normalizeContent(html));
});

test("normalize: rejects non-string input", () => {
  assert.throws(() => normalizeContent(null), TypeError);
  assert.throws(() => normalizeContent(123), TypeError);
  assert.throws(() => normalizeContent(undefined), TypeError);
});
