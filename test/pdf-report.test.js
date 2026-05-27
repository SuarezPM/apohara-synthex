// Test del Evidence Report en PDF. Valida que se genera un PDF real (magic %PDF) sin red.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildPDFReport } from "../src/prove/pdf-report.js";

const baseEvidence = (overrides = {}) => ({
  payload: {
    target: "https://competitor.example",
    lens: "security",
    fetchedAt: "2026-05-27T00:00:00.000Z",
    sources: ["https://competitor.example"],
    blocked: [{ url: "https://x", reason: "prompt-injection" }],
    findings: [{ url: "https://competitor.example", lens: "security", severity: 9, summary: "Breach expuesto.", signals: ["breach", "cve"] }],
    ...overrides.payload,
  },
  contentHash: "a".repeat(64),
  seal: { hmacSha256: "b".repeat(64), rfc3161Tsa: { standard: "RFC 3161", authority: "digicert", genTime: "2026-05-27T00:00:01Z", serial: "deadbeef" }, method: "HMAC-SHA256 + RFC 3161 TSA" },
  sealedAt: "2026-05-27T00:00:02.000Z",
  ...overrides,
});

function assertIsPdf(buf) {
  assert.ok(Buffer.isBuffer(buf), "debe ser Buffer");
  assert.ok(buf.length > 1000, `PDF demasiado chico: ${buf.length} bytes`);
  assert.equal(buf.subarray(0, 5).toString("latin1"), "%PDF-", "debe empezar con el magic %PDF-");
}

test("pdf: genera un PDF válido para evidence con TSA (shape plano)", async () => {
  const buf = await buildPDFReport(baseEvidence());
  assertIsPdf(buf);
});

test("pdf: genera un PDF válido para evidence HMAC-only (sin TSA)", async () => {
  const ev = baseEvidence();
  ev.seal = { hmacSha256: "b".repeat(64), rfc3161Tsa: null, method: "HMAC-SHA256" };
  const buf = await buildPDFReport(ev);
  assertIsPdf(buf);
});

test("pdf: genera un PDF válido para findings tri-lens (lens='all')", async () => {
  const ev = baseEvidence({
    payload: {
      target: "acme.com", lens: "all", sources: ["acme.com"], blocked: [],
      findings: [{ url: "acme.com", trilens: {
        gtm: { severity: 7, summary: "price cut", signals: ["pricing"] },
        finance: { severity: 4, summary: "vendor risk", signals: ["soc2"] },
        security: { severity: 9, summary: "exposed key", signals: ["secret"] },
      } }],
    },
  });
  const buf = await buildPDFReport(ev);
  assertIsPdf(buf);
});
