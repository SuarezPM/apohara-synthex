// Tests para src/prove/ocsp.js — fail-open contract + helper unit tests.
// Las happy-path (status:good/revoked) requieren mockear DER de OCSPResponse,
// que es complejo; las cubrimos via integración con verifyEvidence + mock
// fetchImpl. El foco acá es el contrato fail-open (nunca throws, default
// 'unknown' on any failure).
import { test } from "node:test";
import assert from "node:assert/strict";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { Buffer } from "node:buffer";
import { extractOcspUrl, checkRevocation } from "../../src/prove/ocsp.js";

// ─── extractOcspUrl ────────────────────────────────────────────────────────

test("extractOcspUrl: cert sin extensions → null", () => {
  assert.equal(extractOcspUrl({}), null);
  assert.equal(extractOcspUrl(null), null);
  assert.equal(extractOcspUrl(undefined), null);
});

test("extractOcspUrl: cert sin AIA → null", () => {
  const cert = { extensions: [{ extnID: "2.5.29.17", parsedValue: {} }] }; // subjectAltName
  assert.equal(extractOcspUrl(cert), null);
});

test("extractOcspUrl: AIA con id-ad-ocsp → URL", () => {
  const cert = {
    extensions: [
      {
        extnID: "1.3.6.1.5.5.7.1.1",
        parsedValue: {
          accessDescriptions: [
            { accessMethod: "1.3.6.1.5.5.7.48.2", accessLocation: { value: "http://ca.example/issuer.crt" } },
            { accessMethod: "1.3.6.1.5.5.7.48.1", accessLocation: { value: "http://ocsp.example/" } },
          ],
        },
      },
    ],
  };
  assert.equal(extractOcspUrl(cert), "http://ocsp.example/");
});

test("extractOcspUrl: AIA SIN id-ad-ocsp (solo caIssuers) → null", () => {
  const cert = {
    extensions: [
      {
        extnID: "1.3.6.1.5.5.7.1.1",
        parsedValue: {
          accessDescriptions: [
            { accessMethod: "1.3.6.1.5.5.7.48.2", accessLocation: { value: "http://ca.example/issuer.crt" } },
          ],
        },
      },
    ],
  };
  assert.equal(extractOcspUrl(cert), null);
});

// ─── checkRevocation fail-open contract ────────────────────────────────────

// Helpers: certs vacíos que solo aportan el shape mínimo que checkRevocation toca.
// extractOcspUrl decide qué pasa primero — para forzar el path donde necesitamos
// AIA, agregamos extensions.
function _certWithoutAia() {
  return {
    extensions: [],
    serialNumber: new asn1js.Integer({ value: 1 }),
    subject: { toSchema: () => new asn1js.Sequence() },
    subjectPublicKeyInfo: { subjectPublicKey: { valueBlock: { valueHexView: new Uint8Array([1, 2, 3]) } } },
  };
}

function _certWithAia(url) {
  return {
    ..._certWithoutAia(),
    extensions: [
      {
        extnID: "1.3.6.1.5.5.7.1.1",
        parsedValue: {
          accessDescriptions: [
            { accessMethod: "1.3.6.1.5.5.7.48.1", accessLocation: { value: url } },
          ],
        },
      },
    ],
  };
}

test("checkRevocation: no AIA → unknown(no-aia-ocsp), sin red", async () => {
  let fetched = false;
  const r = await checkRevocation(_certWithoutAia(), _certWithoutAia(), {
    fetchImpl: async () => { fetched = true; return { ok: true }; },
  });
  assert.equal(r.status, "unknown");
  assert.equal(r.reason, "no-aia-ocsp");
  assert.equal(fetched, false);
});

test("checkRevocation: fetch lanza → unknown(network-error), NO throw", async () => {
  const r = await checkRevocation(_certWithAia("http://ocsp.example/"), _certWithoutAia(), {
    fetchImpl: async () => { throw new Error("ECONNREFUSED"); },
  });
  assert.equal(r.status, "unknown");
  assert.equal(r.reason, "network-error");
  assert.equal(r.responder, "http://ocsp.example/");
});

test("checkRevocation: non-200 → unknown(http-XXX)", async () => {
  const r = await checkRevocation(_certWithAia("http://ocsp.example/"), _certWithoutAia(), {
    fetchImpl: async () => ({ ok: false, status: 503, arrayBuffer: async () => new ArrayBuffer(0) }),
  });
  assert.equal(r.status, "unknown");
  assert.equal(r.reason, "http-503");
});

test("checkRevocation: garbage DER → unknown(parse-error)", async () => {
  const r = await checkRevocation(_certWithAia("http://ocsp.example/"), _certWithoutAia(), {
    fetchImpl: async () => ({
      ok: true,
      arrayBuffer: async () => new Uint8Array([0xff, 0xff, 0xff]).buffer,
    }),
  });
  assert.equal(r.status, "unknown");
  // parse-error o decode-error, ambos válidos según falle el outer o el inner parse
  assert.match(r.reason, /(parse|decode)-error/);
});

test("checkRevocation: responseStatus != 0 (malformedRequest) → unknown(responseStatus-N)", async () => {
  // Build a minimal OCSPResponse con responseStatus = 1 (malformedRequest).
  const malformed = new pkijs.OCSPResponse({
    responseStatus: new asn1js.Enumerated({ value: 1 }),
  });
  const der = new Uint8Array(malformed.toSchema().toBER(false));
  const r = await checkRevocation(_certWithAia("http://ocsp.example/"), _certWithoutAia(), {
    fetchImpl: async () => ({ ok: true, arrayBuffer: async () => der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) }),
  });
  assert.equal(r.status, "unknown");
  assert.match(r.reason, /^responseStatus-/);
});

test("checkRevocation: never throws — robust ante input basura en signerCert", async () => {
  // Pasamos un signerCert sin las shape that buildOcspRequestDer needs.
  // Debe ir por el catch interno y retornar unknown sin throw.
  const r = await checkRevocation(
    _certWithAia("http://ocsp.example/"),
    {}, // issuer sin shape → buildOcspRequestDer lanza, capturado
    { fetchImpl: async () => ({ ok: true, arrayBuffer: async () => new ArrayBuffer(0) }) },
  );
  assert.equal(r.status, "unknown");
});

// ─── Integration: verifyEvidence con checkRevocation flag ──────────────────

test("verifyEvidence: checkRevocation=false (default) → revocationChecked:false, sin red", async () => {
  // Sample real con TSA pero sin pedir revocation.
  const { readFileSync } = await import("node:fs");
  const { verifyEvidence } = await import("../../src/prove/evidence-report.js");
  const sample = JSON.parse(readFileSync(new URL("../../samples/synthex-evidence-report.json", import.meta.url), "utf8"));
  let fetched = false;
  const v = await verifyEvidence(sample, {
    hmacKey: "synthex-dev",
    ocspFetchImpl: async () => { fetched = true; return { ok: true, arrayBuffer: async () => new ArrayBuffer(0) }; },
  });
  assert.equal(v.revocationChecked, false);
  assert.equal(v.revocationStatus, null);
  assert.equal(fetched, false, "default OFF debe ser ZERO red");
});

test("verifyEvidence: checkRevocation=true + mock fetchImpl que falla → revocationChecked:true, status:unknown", async () => {
  const { readFileSync } = await import("node:fs");
  const { verifyEvidence } = await import("../../src/prove/evidence-report.js");
  const sample = JSON.parse(readFileSync(new URL("../../samples/synthex-evidence-report.json", import.meta.url), "utf8"));
  const v = await verifyEvidence(sample, {
    hmacKey: "synthex-dev",
    checkRevocation: true,
    ocspFetchImpl: async () => { throw new Error("offline test"); },
  });
  assert.equal(v.revocationChecked, true);
  assert.equal(v.revocationStatus, "unknown");
  // tsaSignatureValid sigue siendo true — revocation es surfacing-only, no auto-fail.
  assert.equal(v.tsaSignatureValid, true, "revoked/unknown no debe auto-fail tsaSignatureValid en v0.8");
});
