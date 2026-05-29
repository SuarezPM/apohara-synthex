// v0.8.0 Commit 1B — TSA cert validity hardening (reviewer F5–F7).
//
// Tests the new chain-walk gates: cert validity (at TSTInfo genTime, NOT
// Date.now()), EKU id-kp-timeStamping on the signer cert, and the
// gentime-outside-validity precedence on the signer cert specifically.
//
// Strategy: the helpers `certValidityReason` + `certMissingTimestampingEku`
// are exported for testing in isolation (synthesizing an expired/EKU-less
// fixture from real DigiCert tokens is impossibly fiddly). We test the
// helpers directly with real cert objects from the sample + with synthetic
// atDate values, plus the e2e over-tightening guard on the shipped sample.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Buffer } from "node:buffer";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { verifyTimestamp, certValidityReason, certMissingTimestampingEku } from "../../src/prove/tsa.js";
import { loadAnchors } from "../../src/prove/tsa-anchors.js";

const SAMPLE_PATH = "samples/synthex-evidence-report.json";

function loadSampleCerts() {
  // Extract signer + intermediate + cross-root certs from the embedded CMS of
  // the shipped sample. Same path verifyCmsSigned walks; isolating here for tests.
  const ev = JSON.parse(readFileSync(SAMPLE_PATH, "utf8"));
  const der = new Uint8Array(Buffer.from(ev.seal.rfc3161Tsa.token, "base64"));
  const asn1 = asn1js.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
  const tspResp = new pkijs.TimeStampResp({ schema: asn1.result });
  const signed = new pkijs.SignedData({ schema: tspResp.timeStampToken.content });
  // CMS carries [signer (Responder), intermediate (G4 TSA 2025 CA1), root cross-cert (G4)].
  const cmsCerts = signed.certificates;
  const signer = cmsCerts.find((c) =>
    c.subject.typesAndValues.find((t) => t.type === "2.5.4.3")?.value?.valueBlock?.value?.includes("Responder")
  );
  const intermediate = cmsCerts.find((c) =>
    c.subject.typesAndValues.find((t) => t.type === "2.5.4.3")?.value?.valueBlock?.value?.includes("2025 CA1")
  );
  const root = cmsCerts.find((c) =>
    c.subject.typesAndValues.find((t) => t.type === "2.5.4.3")?.value?.valueBlock?.value === "DigiCert Trusted Root G4"
  );
  return { signer, intermediate, root };
}

// ─── helpers (unit-level) ────────────────────────────────────────────────

test("certValidityReason · signer cert valid at genTime → null", () => {
  const { signer } = loadSampleCerts();
  // genTime of the shipped sample = 2026-05-28; signer validity 2025-06-04 → 2036-09-03.
  const atGenTime = new Date("2026-05-28T01:59:31Z");
  assert.equal(certValidityReason(signer, atGenTime, "signer"), null);
  assert.equal(certValidityReason(signer, atGenTime, "issuer"), null);
});

test("certValidityReason · signer cert AT atDate ⟂ validity → 'gentime-outside-validity'", () => {
  const { signer } = loadSampleCerts();
  // Pretend the token was stamped before the responder cert existed
  const beforeNB = new Date("2020-01-01T00:00:00Z");
  assert.equal(certValidityReason(signer, beforeNB, "signer"), "gentime-outside-validity");
  // Pretend the token was stamped after the responder cert expired
  const afterNA = new Date("2050-01-01T00:00:00Z");
  assert.equal(certValidityReason(signer, afterNA, "signer"), "gentime-outside-validity");
});

test("certValidityReason · issuer cert with bad window → 'cert-not-yet-valid' / 'cert-expired'", () => {
  const { intermediate } = loadSampleCerts();
  // intermediate validity: 2025-05-07 → 2038-01-14
  assert.equal(
    certValidityReason(intermediate, new Date("2020-01-01T00:00:00Z"), "issuer"),
    "cert-not-yet-valid",
  );
  assert.equal(
    certValidityReason(intermediate, new Date("2050-01-01T00:00:00Z"), "issuer"),
    "cert-expired",
  );
});

test("certMissingTimestampingEku · real DigiCert responder has id-kp-timeStamping → false (present)", () => {
  const { signer } = loadSampleCerts();
  assert.equal(certMissingTimestampingEku(signer), false);
});

test("certMissingTimestampingEku · DigiCert TSA intermediate also carries the EKU (CA-policy choice)", () => {
  const { intermediate } = loadSampleCerts();
  // Empirically: DigiCert's TSA intermediate also carries id-kp-timeStamping (constraining
  // the chain to time-stamping use). The implementation applies the EKU check signer-only
  // because (a) RFC 3161 §2.3 mandates it on the responder, not the chain; (b) root CAs
  // typically lack EKU and would otherwise be rejected. See next test for the root case.
  assert.equal(certMissingTimestampingEku(intermediate), false);
});

test("certMissingTimestampingEku · root cross-cert has NO EKU (root CAs are general-purpose) → true", () => {
  const { root } = loadSampleCerts();
  // DigiCert Trusted Root G4 has no Extended Key Usage extension — it's a general-purpose
  // root that issues for many uses. This is exactly why verifyCmsSigned applies EKU on the
  // signer only: applying it chain-wide would reject every legitimate TSA chain whose root
  // is a general-purpose CA.
  assert.equal(certMissingTimestampingEku(root), true);
});

// ─── e2e regression: real sample MUST still verify (over-tightening guard) ─

test("e2e regression · real shipped sample still verifies signatureValid:true after hardening", async () => {
  const ev = JSON.parse(readFileSync(SAMPLE_PATH, "utf8"));
  const tokenDer = new Uint8Array(Buffer.from(ev.seal.rfc3161Tsa.token, "base64"));
  const hashBytes = new Uint8Array(Buffer.from(ev.contentHash, "hex"));
  const r = await verifyTimestamp(tokenDer, hashBytes);
  assert.equal(r.granted, true);
  assert.equal(r.match, true);
  assert.equal(r.signatureValid, true, "the real sample must continue to verify after cert validity hardening — over-tightening guard");
  assert.equal(r.signatureValidReason, null);
});

test("e2e regression · untrusted-anchor path still distinguishable from cert reasons", async () => {
  const ev = JSON.parse(readFileSync(SAMPLE_PATH, "utf8"));
  const tokenDer = new Uint8Array(Buffer.from(ev.seal.rfc3161Tsa.token, "base64"));
  const hashBytes = new Uint8Array(Buffer.from(ev.contentHash, "hex"));
  const r = await verifyTimestamp(tokenDer, hashBytes, { trustedCerts: [] });
  // EKU + signer validity pass (the cert IS valid at genTime, and DOES have id-kp-timeStamping);
  // only the chain-to-anchor walk fails → "untrusted-anchor", not a cert-* reason.
  assert.equal(r.signatureValid, false);
  assert.equal(r.signatureValidReason, "untrusted-anchor",
    "precedence: cert-missing-eku and gentime-outside-validity are signer-cert-level (and pass); only the chain walk fails");
});
