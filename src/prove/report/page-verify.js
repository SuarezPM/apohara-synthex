// PROVE/report/page-verify — "Verify It Yourself" (interior, light). Phase-1 body MOVED here,
// re-themed to PAPER. The one structural change required by the spec: the dark #0f172a command
// block becomes the LIGHT codeBox component (printable; dark code lives only on the cover).
import { PAPER, FONTS, PAGE, VOICE } from "./theme.js";
import { pageOpen, sectionTitle, body } from "./interior.js";
import { codeBox } from "./components.js";

export function pageVerify(doc, ev, ctx = {}) {
  const { contentHash, seal = {} } = ev;
  const tsa = seal.rfc3161Tsa;
  pageOpen(doc, { persona: VOICE.verifyKicker, title: "Reproduce the proof offline", reportId: ctx.reportId, registry: ctx.registry });
  sectionTitle(doc, "Reproduce the proof offline");

  body(doc,
    "RFC 3161 proves WHEN this content was sealed — not that the content is TRUE. The HMAC proves " +
    "integrity against the issuing key. Reproduce the checks yourself with OpenSSL:");
  doc.moveDown(0.5);

  const cmd = tsa
    ? `# 1. Decode the trusted timestamp token shipped in the report JSON (seal.rfc3161Tsa.token):\n` +
      `echo "<base64-token>" | base64 -d > synthex.tsr\n\n` +
      `# 2. Inspect the DigiCert RFC 3161 reply (works offline):\n` +
      `openssl ts -reply -in synthex.tsr -text\n\n` +
      `# 3. Confirm the messageImprint in that output equals this SHA-256:\n` +
      `#    ${contentHash}\n\n` +
      `# 4. Full chain validation (needs the DigiCert CA chain):\n` +
      `openssl ts -verify -in synthex.tsr -CAfile digicert-chain.pem -sha256`
    : `# HMAC-only report (no network at seal time). Recompute the seal over the canonical payload:\n` +
      `#   HMAC-SHA256(JSON.stringify(payload), <key>) == ${seal.hmacSha256 ?? "—"}\n` +
      `#   SHA-256(JSON.stringify(payload))            == ${contentHash}\n\n` +
      `# With the key in $KEY and payload.json on disk:\n` +
      `openssl dgst -sha256 -hmac "$KEY" payload.json\n` +
      `openssl dgst -sha256 payload.json`;

  codeBox(doc, { theme: PAPER, lines: cmd });
  doc.moveDown(0.6);

  sectionTitle(doc, "The SHA-256 you must match");
  doc.x = doc.page.margins.left;
  doc.font(FONTS.mono).fontSize(9).fillColor(PAPER.violet).text(contentHash ?? "—", doc.page.margins.left, doc.y, { width: PAGE.textWidth });
  doc.fillColor(PAPER.ink).x = doc.page.margins.left;
}
