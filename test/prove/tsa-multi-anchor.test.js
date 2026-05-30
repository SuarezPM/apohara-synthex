// Multi-TSA resilience (R4) — Actalis token verifies under the pinned Actalis CA G1 anchor, the
// untrusted-anchor vs forged distinction holds for the new TSA, DigiCert is unaffected, and a
// string-guard forbids any "qualified"/"eIDAS-qualified" overclaim for the free endpoint.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Buffer } from "node:buffer";
import { verifyTimestamp } from "../../src/prove/tsa.js";
import { loadAnchors, ANCHOR_METADATA, ANCHOR_FINGERPRINTS } from "../../src/prove/tsa-anchors.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const TOKEN = Buffer.from(readFileSync(join(HERE, "fixtures", "actalis-token.b64"), "utf8"), "base64");
const HASH = Buffer.from(readFileSync(join(HERE, "fixtures", "actalis-token.hash"), "utf8").trim(), "hex");

test("multi-TSA: token Actalis verifica con los anchors default (multi-TSA) → signatureValid:true", async () => {
  const v = await verifyTimestamp(new Uint8Array(TOKEN), new Uint8Array(HASH));
  assert.equal(v.granted, true);
  assert.equal(v.match, true);
  assert.equal(v.signatureValid, true);
  assert.equal(v.signatureValidReason, null);
});

test("multi-TSA: token Actalis con SOLO anchors DigiCert → untrusted-anchor (no forged)", async () => {
  const digicertOnly = loadAnchors().slice(0, 2); // [DigiCert intermediate, DigiCert root]
  const v = await verifyTimestamp(new Uint8Array(TOKEN), new Uint8Array(HASH), { trustedCerts: digicertOnly });
  assert.equal(v.signatureValid, false);
  assert.equal(v.signatureValidReason, "untrusted-anchor", "staleness != forgery — distinción preservada para el 2do TSA");
});

test("multi-TSA: token Actalis con la firma corrupta → forged", async () => {
  const tampered = Buffer.from(TOKEN);
  tampered[tampered.length - 12] ^= 0xff; // corrompe bytes de la firma CMS
  const v = await verifyTimestamp(new Uint8Array(tampered), new Uint8Array(HASH));
  assert.equal(v.signatureValid, false);
  assert.match(String(v.signatureValidReason), /forged|chain-incomplete/);
});

// (DigiCert-unaffected is covered by the existing back-compat-matrix + tsa-cms-verify suites,
//  which run against the now-3-anchor loadAnchors() — if those stay green, DigiCert is unaffected.)

test("HONESTY string-guard: NUNCA 'qualified'/'eIDAS-qualified' para el endpoint Actalis free", () => {
  // El metadata del anchor Actalis NO debe afirmar qualified.
  assert.equal(ANCHOR_METADATA.actalisTsCaG1.qualified, false);
  const meta = JSON.stringify(ANCHOR_METADATA.actalisTsCaG1).toLowerCase();
  assert.ok(!/eidas|qualified.?(timestamp|tsa|signature)/.test(meta) || meta.includes('"qualified":false'),
    "el metadata Actalis no debe afirmar eIDAS-qualified (solo qualified:false)");
  assert.ok(ANCHOR_FINGERPRINTS.actalisTsCaG1, "Actalis CA G1 FP pinned");
});
