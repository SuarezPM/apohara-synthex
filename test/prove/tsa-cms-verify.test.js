// M1 / v0.7.0 — RFC 3161 CMS signature verification against pinned DigiCert anchors.
//
// Coverage matrix:
//   AC1   positive   sample real DigiCert token        → signatureValid:true,  reason:null
//   AC2a  negative   trustedCerts:[]  (anchor-stale)   → signatureValid:false, reason:"untrusted-anchor"
//   AC2b  negative   flipped byte in signature (forged)→ signatureValid:false, reason:"forged"
//   AC4   short-cir  evidence sin rfc3161Tsa (HMAC-only) → signatureValid:null
//   AC4b  back-compat 1 v2 HMAC-only fixture de stress-piloto-50 → signatureValid:null
//   AC6   v1+TSA     sample legacy (schema_version undefined) verifica end-to-end
//   anchor-guard    fingerprint mismatch lanza on load (anti-silent-drift)
//   pre-demo smoke  smoke pass que separa staleness ("untrusted-anchor") de forgería
//                   — drives PM-6-agudo detection antes de cualquier live demo.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { Buffer } from "node:buffer";
import { verifyTimestamp } from "../../src/prove/tsa.js";
import { verifyEvidence, buildEvidence } from "../../src/prove/evidence-report.js";
import { loadAnchors, ANCHOR_FINGERPRINTS } from "../../src/prove/tsa-anchors.js";

const SAMPLE_PATH = "samples/synthex-evidence-report.json";
const PILOTO_DIR = "out/stress-piloto-50-2026-05-28";

function loadSample() {
  return JSON.parse(readFileSync(SAMPLE_PATH, "utf8"));
}

function sampleTokenAndHash() {
  const ev = loadSample();
  const tokenDer = new Uint8Array(Buffer.from(ev.seal.rfc3161Tsa.token, "base64"));
  const hashBytes = new Uint8Array(Buffer.from(ev.contentHash, "hex"));
  return { tokenDer, hashBytes };
}

test("M1 AC1 · positive: sample real DigiCert token verifies against pinned anchors", async () => {
  const { tokenDer, hashBytes } = sampleTokenAndHash();
  const r = await verifyTimestamp(tokenDer, hashBytes);
  assert.equal(r.granted, true, "TSA status granted");
  assert.equal(r.match, true, "messageImprint == contentHash");
  assert.equal(r.signatureValid, true, "CMS signature verifies via pinned DigiCert chain");
  assert.equal(r.signatureValidReason, null, "no failure reason on success");
  assert.ok(typeof r.genTime === "string" && r.genTime.length > 0, "genTime present");
  assert.ok(typeof r.serial === "string" && r.serial.length > 0, "serial present");
});

test("M1 AC2a · negative untrusted-anchor: trustedCerts:[] distinguishes staleness from forgery", async () => {
  const { tokenDer, hashBytes } = sampleTokenAndHash();
  const r = await verifyTimestamp(tokenDer, hashBytes, { trustedCerts: [] });
  assert.equal(r.granted, true, "token itself is still valid TSP");
  assert.equal(r.match, true);
  assert.equal(r.signatureValid, false, "chain doesn't reach any anchor");
  assert.equal(
    r.signatureValidReason,
    "untrusted-anchor",
    "must NOT be 'forged' — this is the anti-credibility-catastrophe distinction (R2 ruling #4, PM-6-agudo)",
  );
});

test("M1 AC2b · negative forged: signature-byte flip yields reason:'forged' (not untrusted-anchor)", async () => {
  const { tokenDer, hashBytes } = sampleTokenAndHash();
  const forged = new Uint8Array(tokenDer);
  // Flip a byte deep in the token where the signature lives (last ~512 bytes for RSA-4096).
  forged[forged.length - 50] = forged[forged.length - 50] ^ 0xff;
  const r = await verifyTimestamp(forged, hashBytes);
  assert.equal(r.signatureValid, false);
  assert.equal(
    r.signatureValidReason,
    "forged",
    "signature math fail must be labeled 'forged' (not 'untrusted-anchor')",
  );
});

test("M1 AC4 · HMAC-only short-circuit: evidence sin rfc3161Tsa → signatureValid:null (NOT false)", async () => {
  const ev = await buildEvidence({ a: 1, b: 2 }, { hmacKey: "k", requestTsa: false });
  assert.equal(ev.seal.rfc3161Tsa, null, "fixture sanity: no TSA token");
  const v = await verifyEvidence(ev, { hmacKey: "k" });
  assert.equal(v.hashOk, true);
  assert.equal(v.hmacOk, true);
  assert.equal(v.tsaOk, null);
  assert.equal(
    v.signatureValid,
    null,
    "no TSA token → never call .verify() → signatureValid:null (NOT false, NOT throw)",
  );
  assert.equal(v.signatureValidReason, null);
});

test("M1 AC4b · piloto-50 back-compat: HMAC-only batch verifies with signatureValid:null", async () => {
  // Pick the first available fixture in the batch (all 47 are method:HMAC-SHA256, rfc3161Tsa:null).
  const files = readdirSync(PILOTO_DIR).filter((n) => n.startsWith("evidence-") && n.endsWith(".json"));
  assert.ok(files.length > 0, `piloto-50 dir has fixtures: ${PILOTO_DIR}`);
  const ev = JSON.parse(readFileSync(`${PILOTO_DIR}/${files[0]}`, "utf8"));
  assert.equal(ev.seal.rfc3161Tsa, null, "fixture sanity: piloto-50 is HMAC-only");
  const v = await verifyEvidence(ev, { hmacKey: "synthex-dev" });
  // hash + HMAC still verify; TSA short-circuit returns null (no .verify() call).
  assert.equal(v.hashOk, true, "v2 HMAC re-verifies under post-M1 codec");
  assert.equal(v.hmacOk, true);
  assert.equal(v.signatureValid, null, "null-token short-circuit at scale");
});

test("M1 AC6 · v1+TSA back-compat: schema_version undefined + TSA token verifies end-to-end", async () => {
  // samples/synthex-evidence-report.json is legacy v1 (no schema_version) WITH a real TSA token.
  // Post-M1 verifier must accept TSA tokens on payloads that lack schema_version.
  const ev = loadSample();
  assert.equal(ev.payload.schema_version, undefined, "fixture sanity: legacy v1 payload");
  assert.ok(ev.seal.rfc3161Tsa?.token, "fixture sanity: has TSA token");
  const v = await verifyEvidence(ev, { hmacKey: "synthex-demo" });
  assert.equal(v.hashOk, true, "v1 path serializes with JSON.stringify");
  assert.equal(v.signatureValid, true, "TSA verifies on v1/legacy payload too");
  assert.equal(v.signatureValidReason, null);
});

test("M1 anchor-guard · fingerprints frozen + loadAnchors() returns intermediate+root", () => {
  const anchors = loadAnchors();
  assert.equal(anchors.length, 2, "intermediate + root cross-cert");
  assert.ok(ANCHOR_FINGERPRINTS.intermediate.startsWith("CA:0B:15:54"), "intermediate FP pinned");
  assert.ok(ANCHOR_FINGERPRINTS.rootCross.startsWith("33:84:6B:54"), "root cross-cert FP pinned");
  // Frozen — silent drift refused at the type level.
  assert.throws(
    () => { ANCHOR_FINGERPRINTS.intermediate = "tamper"; },
    TypeError,
    "ANCHOR_FINGERPRINTS must be Object.frozen — guards against silent edits",
  );
});

test("M1 pre-demo smoke (PM-6-agudo) · positive vs untrusted-anchor produce distinguishable verdicts", async () => {
  // Drives the operator smoke test BEFORE any live demo:
  //   - Positive path returns signatureValid:true.
  //   - Empty-anchors path returns signatureValid:false with reason "untrusted-anchor" (NOT "forged").
  // If a DigiCert rotation lands mid-demo, the operator sees "untrusted-anchor" in logs and
  // knows to refresh anchors (Follow-up F4) — they DON'T misread it as a forgery alarm.
  const { tokenDer, hashBytes } = sampleTokenAndHash();
  const ok = await verifyTimestamp(tokenDer, hashBytes);
  const stale = await verifyTimestamp(tokenDer, hashBytes, { trustedCerts: [] });
  assert.equal(ok.signatureValid, true);
  assert.equal(stale.signatureValid, false);
  assert.notEqual(stale.signatureValidReason, "forged", "rotation must NOT look like forgery");
  assert.equal(stale.signatureValidReason, "untrusted-anchor");
});
