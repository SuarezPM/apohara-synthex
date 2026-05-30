// PROVE/report/page-verify — "Verify It Yourself · For Anyone" (interior, light · page 9).
// The page that proves the two axes competitors miss: every seal layer is REPRODUCIBLE OFFLINE
// with real tooling, and the FULL hashes/signatures ship in a downloadable sidecar (never a
// truncated value with no path to the original — design spec §4). 3-way verify (TSA · C2PA ·
// Rekor) + Ed25519 vs the published public key, plus the one-command `synthex verify <bundle>`.
// Present-gated: a layer's command renders ONLY when its data is in this run; absent layers say so.
// PDFKit pitfall: doc.y does NOT advance after a lineBreak:false draw — single lines step y by a
// fixed amount; only codeBox/body (wrapping blocks) read doc.y. (The cover-overlap bug.)
import { PAPER, FONTS, TYPE, PAGE } from "./theme.js";
import { pageOpen, sectionTitle, body } from "./interior.js";
import { codeBox, truncMid, rekorLogIndex } from "./components.js";

export function pageVerify(doc, ev, ctx = {}) {
  const { contentHash, seal = {} } = ev;
  const sig = seal.signature;
  const tsa = seal.rfc3161Tsa;
  const rekorIndex = rekorLogIndex(ctx.rekorBundle);
  const hasC2pa = !!ctx.c2paSidecar;
  const left = doc.page.margins.left;

  pageOpen(doc, {
    persona: "● Verify It Yourself · for Anyone",
    title: "Reproduce every seal offline",
    reportId: ctx.reportId,
    registry: ctx.registry,
  });

  body(doc,
    "Nothing here asks for trust. Each layer is checked with open tooling an auditor already has — no " +
    "Synthex service, no network. The seal proves WHEN these bytes existed and that they are UNCHANGED, " +
    "not that the claims are true. The downloadable sidecar evidence.json carries the FULL, untruncated " +
    "hashes and signatures, so every head…tail value in this PDF has a path to the bytes you verify.");
  doc.moveDown(0.55);

  // ── One-command path (the easy button) ───────────────────────────────────────
  sectionTitle(doc, "One command — verifies every present layer");
  codeBox(doc, {
    theme: PAPER,
    lines: [
      "$ synthex verify evidence.json",
      "#   exit 0 → every present layer verified · non-zero → one failed",
    ],
  });
  doc.moveDown(0.5);

  // ── (1) RFC 3161 timestamp ───────────────────────────────────────────────────
  if (tsa) {
    sectionTitle(doc, "1 · RFC 3161 timestamp — proves WHEN (offline)");
    codeBox(doc, {
      theme: PAPER,
      lines: [
        "$ jq -r .seal.rfc3161Tsa.token evidence.json | base64 -d > synthex.tsr",
        "$ openssl ts -verify -in synthex.tsr -sha256 \\",
        "    -digest " + (contentHash ?? "—") + " \\",
        "    -CAfile digicert-tsa-chain.pem",
        "#   \"Verification: OK\"  exit 0   authority " + (tsa.authority ?? "digicert") +
          " · serial " + truncMid(tsa.serial, 10, 8),
      ],
    });
    doc.moveDown(0.5);
  }

  // ── (2) C2PA Content Credentials (present-gated) ─────────────────────────────
  sectionTitle(doc, "2 · C2PA Content Credentials — provenance card");
  if (hasC2pa) {
    codeBox(doc, {
      theme: PAPER,
      lines: [
        "$ c2patool evidence.c2pa.json --info",
        "#   expect claimSignature.validated = true · dataHash.match = true   exit 0",
      ],
    });
  } else {
    codeBox(doc, {
      theme: PAPER,
      lines: [
        "# Not present in this run (present-gated). When a manifest is attached:",
        "$ c2patool evidence.c2pa.json --info",
        "#   expect claimSignature.validated = true · dataHash.match = true   exit 0",
      ],
    });
  }
  doc.moveDown(0.5);

  // ── (3) Sigstore Rekor v2 (present-gated) ────────────────────────────────────
  sectionTitle(doc, "3 · Sigstore Rekor v2 — offline inclusion + checkpoint");
  if (rekorIndex != null) {
    codeBox(doc, {
      theme: PAPER,
      lines: [
        "$ rekor-cli verify --rekor_bundle evidence.rekor.json --pubkey rekor-log.pub",
        "#   logIndex " + rekorIndex + " · checkpoint matches the pinned log key   exit 0",
      ],
    });
  } else {
    codeBox(doc, {
      theme: PAPER,
      lines: [
        "# Not present in this run (present-gated). When a bundle is attached, the",
        "# inclusion + checkpoint are checked OFFLINE against the pinned log key:",
        "$ rekor-cli verify --rekor_bundle evidence.rekor.json --pubkey rekor-log.pub",
      ],
    });
  }
  doc.moveDown(0.5);

  // ── Ed25519 signature vs published public key (the headline layer) ───────────
  if (sig) {
    sectionTitle(doc, "Ed25519 signature — verify against the published key");
    codeBox(doc, {
      theme: PAPER,
      lines: [
        "# keyId " + (sig.keyId ?? "—") + "  (publishable public key in the sidecar)",
        "$ jq -r .seal.signature.publicKey evidence.json | base64 -d > synthex.pub.der",
        "$ jq -r .seal.signature.value     evidence.json | base64 -d > synthex.sig",
        "$ openssl pkeyutl -verify -pubin -inkey synthex.pub.der \\",
        "    -rawin -in payload.canonical.json -sigfile synthex.sig",
        "#   \"Signature Verified Successfully\"  exit 0   identity is self-signed",
      ],
    });
    doc.moveDown(0.5);
  }

  // ── The SHA-256 you must match (single-line digest, manual y-step) ───────────
  sectionTitle(doc, "The SHA-256 these checks must reproduce");
  doc.x = left;
  const hashY = doc.y;
  doc.font(FONTS.mono).fontSize(9).fillColor(PAPER.violet)
    .text(contentHash ?? "—", left, hashY, { width: PAGE.textWidth, lineBreak: false });
  doc.y = hashY + TYPE.code.leading + 2;
  doc.x = left;

  // Present-layer summary line, honest about what this run actually carries.
  const present = ["SHA-256", sig ? "Ed25519" : null, tsa ? "RFC 3161 TSA" : null,
    hasC2pa ? "C2PA" : null, rekorIndex != null ? "Rekor v2" : null, "HMAC-SHA256"]
    .filter(Boolean).join(" · ");
  doc.font(FONTS.body).fontSize(8.5).fillColor(PAPER.muted)
    .text(`Layers present in this run: ${present}. HMAC-SHA256 is an internal integrity checksum, not the headline.`,
      left, doc.y, { width: PAGE.textWidth });
  doc.fillColor(PAPER.ink).x = left;
}
