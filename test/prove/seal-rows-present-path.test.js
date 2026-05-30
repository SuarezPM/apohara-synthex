// P0.1 — present-path guard for the Evidence Report seal block. The Rekor + C2PA rows are
// present-gated on the sidecars; this proves they SURFACE when the sidecars are passed and are
// (honestly) ABSENT when they are not. We assert on sealRows() in-process, never by grepping the
// rendered PDF: PDFKit subset-CID fonts make string-grep on the bytes return 0 hits even for text
// that is visibly on the page.
import { test } from "node:test";
import assert from "node:assert/strict";
import { sealRows } from "../../src/prove/report/components.js";

const baseSeal = {
  signature: { keyId: "76af8b6912a90684", value: "Zm9vYmFy".repeat(8) },
  rfc3161Tsa: { authority: "DigiCert", genTime: "2026-05-30T12:00:00Z", serial: "0x0A1B2C" },
  hmacSha256: "deadbeefcafef00d".repeat(4),
};
const contentHash = "a".repeat(64);

test("sealRows surfaces Rekor + C2PA rows when the sidecars are present (P0.1 present-path)", () => {
  const rows = sealRows({
    seal: baseSeal,
    contentHash,
    c2paSidecar: { manifest: { claim_generator: "apohara-synthex" } },
    rekorBundle: { tlogEntry: { logIndex: 4756641 } },
  });
  const labels = rows.map((r) => r[0]);
  assert.ok(labels.includes("Ed25519 sig"), "Ed25519 must lead the seal block");
  assert.ok(labels.includes("RFC 3161 TSA"), "TSA row present");
  assert.ok(labels.includes("Sigstore Rekor v2"), "Rekor row must surface with a bundle");
  assert.ok(labels.includes("C2PA Content Cred."), "C2PA row must surface with a sidecar");
  const rekorRow = rows.find((r) => r[0] === "Sigstore Rekor v2");
  assert.match(rekorRow[1], /4756641/, "the real logIndex is rendered");
});

test("sealRows tolerates the alternate Rekor bundle shape (logIndex at top level)", () => {
  const rows = sealRows({ seal: baseSeal, contentHash, c2paSidecar: {}, rekorBundle: { logIndex: 99 } });
  const rekorRow = rows.find((r) => r[0] === "Sigstore Rekor v2");
  assert.ok(rekorRow, "rekorLogIndex reads logIndex at top level too");
  assert.match(rekorRow[1], /99/);
});

test("sealRows omits Rekor + C2PA when the sidecars are absent (the dark-by-default gap P0.1 fixes)", () => {
  const rows = sealRows({ seal: baseSeal, contentHash, c2paSidecar: null, rekorBundle: null });
  const labels = rows.map((r) => r[0]);
  assert.ok(!labels.includes("Sigstore Rekor v2"), "no Rekor row without a bundle (honest absence)");
  assert.ok(!labels.includes("C2PA Content Cred."), "no C2PA row without a sidecar (honest absence)");
  assert.ok(labels.includes("Ed25519 sig"), "Ed25519 + TSA still present — the seal is never empty");
  assert.ok(labels.includes("HMAC-SHA256"), "HMAC labeled, internal-only");
});
