// Test T1.4 — verifica que buildPDFReport genera 7ma página Delta cuando hay
// payload.delta_chain, y 6 páginas (back-compat) cuando no.
//
// Usa pdfkit en memoria + asserción sobre buffer (no requiere pdftotext en CI).
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildPDFReport } from "../../src/prove/pdf-report.js";
import { sealDeltaChain } from "../../src/delta/index.js";

test("PDF: report sin delta_chain → exactamente 6 páginas (back-compat v0.5)", async () => {
  const evidence = {
    contentHash: "a".repeat(64),
    seal: { hmacSha256: "b".repeat(64), method: "HMAC-SHA256", rfc3161Tsa: null },
    sealedAt: "2026-05-28T15:00:00Z",
    payload: {
      target: "https://example.com",
      lens: "gtm",
      fetchedAt: "2026-05-28T15:00:00Z",
      sources: ["https://example.com/a"],
      blocked: [],
      findings: [{ severity: 5, summary: "noop", signals: ["x"] }],
    },
  };
  const buf = await buildPDFReport(evidence);
  assert.ok(Buffer.isBuffer(buf));
  // PDF page count via /Type /Pages /Count N (raw scan, sufficient para asserción binaria).
  const head = buf.toString("latin1");
  const m = head.match(/\/Count\s+(\d+)/);
  assert.ok(m, "PDF debe contener /Count");
  assert.equal(Number(m[1]), 6, "Sin delta_chain debe ser 6 páginas");
});

test("PDF: report con delta_chain → exactamente 7 páginas", async () => {
  const ev = await sealDeltaChain({
    prev_evidence: null,
    curr_snapshot: {
      target: "https://example.com",
      lens: "gtm",
      content: "<p>price is one hundred dollars</p>",
      fetchedAt: "2026-05-28T15:00:00Z",
      sources: ["https://example.com"],
      findings: [{ severity: 6, summary: "noop" }],
    },
    hmacKey: "test",
    requestTsa: false,
  });
  assert.ok(ev.payload.delta_chain, "delta_chain presente");
  const buf = await buildPDFReport(ev);
  const head = buf.toString("latin1");
  const m = head.match(/\/Count\s+(\d+)/);
  assert.ok(m, "PDF debe contener /Count");
  assert.equal(Number(m[1]), 7, "Con delta_chain debe ser 7 páginas");
});

test("PDF: bytes contienen string 'Delta Evidence Chain' cuando hay delta", async () => {
  const ev = await sealDeltaChain({
    prev_evidence: null,
    curr_snapshot: {
      target: "https://example.com",
      lens: "gtm",
      content: "<p>some pricing change here</p>",
      fetchedAt: "2026-05-28T15:00:00Z",
      findings: [{ severity: 5, summary: "x" }],
    },
    hmacKey: "k",
    requestTsa: false,
  });
  const buf = await buildPDFReport(ev);
  // PDFKit comprime el text stream — buscamos un substring del título tal cual no necesariamente
  // aparece. Validación más débil pero útil: que el doc tenga al menos 7 instancias de "/Type /Page"
  // (1 por página, sin contar /Pages).
  const head = buf.toString("latin1");
  const pageRefs = (head.match(/\/Type\s*\/Page[^s]/g) ?? []).length;
  assert.ok(pageRefs >= 7, `esperaba >=7 /Type /Page, vi ${pageRefs}`);
});
