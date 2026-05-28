// Test T1.5 — verifica back-compat decoder con evidence v0.5.0 (sin delta_chain)
// y muestra correctamente la cadena cuando payload.delta_chain está presente.
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../bin/decode-evidence.js";
import { sealDeltaChain } from "../src/delta/index.js";
import { buildEvidence } from "../src/prove/evidence-report.js";

function captureStdout(fn) {
  const original = process.stdout.write.bind(process.stdout);
  let captured = "";
  process.stdout.write = (chunk) => { captured += String(chunk); return true; };
  return fn().then((res) => { process.stdout.write = original; return { res, out: captured }; });
}

test("decoder: back-compat con v0.5.0 evidence (sin delta_chain) → no rompe", async () => {
  const ev = await buildEvidence({
    schema_version: 2,
    target: "https://example.com",
    findings: [{ severity: 5, summary: "x" }],
  }, { hmacKey: "synthex-demo", requestTsa: false });

  const dir = mkdtempSync(join(tmpdir(), "decode-test-"));
  const path = join(dir, "v05.json");
  writeFileSync(path, JSON.stringify(ev));

  const { res, out } = await captureStdout(() => main([path]));
  assert.equal(res, 0);
  assert.ok(out.includes("Evidence Report"));
  assert.ok(!out.includes("Delta Chain"), "no debe mostrar Delta Chain si no hay delta_chain");
});

test("decoder: muestra Delta Chain cuando payload.delta_chain está presente", async () => {
  const ev = await sealDeltaChain({
    prev_evidence: null,
    curr_snapshot: {
      target: "https://example.com",
      lens: "gtm",
      content: "<p>some pricing chunk here</p>",
      fetchedAt: "2026-05-28T15:00:00Z",
      findings: [{ severity: 5, summary: "x" }],
    },
    hmacKey: "synthex-demo",
    requestTsa: false,
  });

  const dir = mkdtempSync(join(tmpdir(), "decode-test-"));
  const path = join(dir, "v06.json");
  writeFileSync(path, JSON.stringify(ev));

  const { res, out } = await captureStdout(() => main([path]));
  assert.equal(res, 0);
  assert.ok(out.includes("Delta Chain"));
  assert.ok(out.includes("previous_tsa_serial"));
  assert.ok(out.includes("current_tsa_serial"));
  assert.ok(out.includes("diff_summary"));
  assert.ok(out.includes("cold start"), "previous_tsa_serial=null debe mostrarse como cold start");
});
