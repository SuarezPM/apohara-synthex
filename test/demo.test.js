// Test del demo determinista (sin TSA para rapidez; el demo real sí sella con TSA).
import { test } from "node:test";
import assert from "node:assert/strict";
import { runDemo } from "../demo/demo.js";
import { verifyEvidence } from "../src/prove/evidence-report.js";

test("demo: produce un Evidence Report verificable sobre datos cacheados", async () => {
  const ev = await runDemo({ requestTsa: false });
  assert.equal(ev.payload.target, "Competitor X");
  assert.equal(ev.payload.lens, "gtm");
  // el pricing aparece 2 veces (otro ref) → 1 duplicado detectado por FORGE
  assert.equal(ev.payload.dedup.duplicateBlocks, 1);
  // findings: pricing + careers (los únicos, clasificados)
  assert.equal(ev.payload.findings.length, 2);
  assert.ok(ev.payload.findings.every((f) => f.severity >= 6));
  const v = verifyEvidence(ev, { hmacKey: "synthex-demo" });
  assert.equal(v.hashOk, true);
  assert.equal(v.hmacOk, true);
});
