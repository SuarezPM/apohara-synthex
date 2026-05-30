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
  // v1.0.0 (1.7): el doc de injection EJECUTABLE es L3-BLOCKED (dropeado de classify); quedan
  // pricing + careers + el doc OWASP (describing → ALLOW) clasificados = 3 findings.
  assert.equal(ev.payload.findings.length, 3);
  assert.ok(ev.payload.findings.every((f) => f.severity >= 6));
  const v = await verifyEvidence(ev, { hmacKey: "synthex-demo" });
  assert.equal(v.hashOk, true);
  assert.equal(v.hmacOk, true);
});

test("demo: 3 capas selladas (INJECTION_GUARD + ALIGNMENT_CHECK + GROUNDING) + contraste L3 (C1)", async () => {
  const ev = await runDemo({ requestTsa: false });
  const decisions = ev.payload.decisions ?? [];
  const stages = new Set(decisions.map((d) => d.stage));
  assert.ok(stages.has("INJECTION_GUARD"), "L2 injection-guard sella REVIEW");
  assert.ok(stages.has("ALIGNMENT_CHECK"), "L3 AlignmentCheck sella su verdict");
  assert.ok(stages.has("GROUNDING"), "grounding sella la verificación de cifras");
  // Contraste describing-vs-executing: el doc ejecutable → L3 BLOCK; el OWASP → L3 ALLOW.
  const l3 = decisions.filter((d) => d.stage === "ALIGNMENT_CHECK");
  assert.ok(l3.some((d) => d.outcome === "BLOCK"), "doc ejecutable → L3 BLOCK");
  assert.ok(l3.some((d) => d.outcome === "ALLOW"), "doc OWASP (describe) → L3 ALLOW");
  // El veneno NUNCA llega a classify: ninguna fila finding proviene del doc ejecutable.
  assert.ok(
    !ev.payload.findings.some((f) => /exfiltrate|evil\.example/i.test(JSON.stringify(f))),
    "el doc ejecutable fue dropeado (no clasificado)",
  );
  // El demo auto-firma con Ed25519 efímero → seal.signature.keyId es un string.
  assert.ok(ev.seal.signature && typeof ev.seal.signature.keyId === "string", "seal Ed25519 presente");
});
