// Evidence Card — C2PA Content Credentials carrier (v0.9.0).
//
// The Evidence Report PDF carries the load-bearing seal (HMAC + Ed25519 + RFC
// 3161 TSA). The Evidence Card is a PNG companion that carries a REAL C2PA
// manifest — verifiable by c2patool / contentcredentials.org — so the evidence
// gets standard Content Credentials.
//
// NON-NEGOTIABLE binding (v0.9.0 design review): the card and the PDF must
// attest the SAME contentHash. The custom `com.apohara.synthex` assertion
// carries the evidence contentHash + the seal keyId; the card is signed with
// the SAME Ed25519 key that sealed the evidence, so the cert keyId, the seal
// keyId, and the assertion keyId all coincide. Without that binding the Content
// Credential would float free of the evidence it claims to certify.
//
// Container choice: c2pa-rs 0.85 cannot WRITE PDF (read-only handler), so the
// C2PA container is a PNG; c2patool embeds the JUMBF and verifies it. The signer
// is self-signed → "untrusted source" in c2patool (real trust needs a CA in the
// C2PA trust list — out of scope). See HONESTY §1.6.

export const SYNTHEX_ASSERTION_LABEL = "com.apohara.synthex";
export const CARD_GENERATOR = "Apohara Synthex";
export const CARD_SPEC = "Apohara Synthex Evidence Card v1";

/**
 * Build a c2patool manifest-definition for the evidence card. PURE — no I/O.
 *
 * The `c2pa.hash.data` assertion over the PNG bytes is added by c2patool at
 * embed time; here we declare the actions + the custom binding assertion that
 * ties the Content Credential to the exact evidence the PDF seals.
 *
 * @param {object} evidence  — buildEvidence() output; MUST be Ed25519-sealed
 *                             (seal.signature.keyId present).
 * @param {{
 *   alg?: string,             // default "ed25519"
 *   privateKeyPath?: string,  // path c2patool reads the signing key from
 *   signCertPath?: string,    // path c2patool reads the cert chain from
 *   generatorVersion?: string,
 *   taUrl?: string,           // RFC 3161 TSA for the C2PA signature (optional)
 * }} [opts]
 * @returns {object} manifest definition JSON for `c2patool -m`
 */
export function buildCardManifestDefinition(evidence, opts = {}) {
  if (!evidence?.contentHash || typeof evidence.contentHash !== "string") {
    throw new TypeError("buildCardManifestDefinition: evidence.contentHash (hex string) is required");
  }
  const sig = evidence?.seal?.signature;
  if (!sig?.keyId) {
    throw new TypeError(
      "buildCardManifestDefinition: evidence must carry an Ed25519 seal (seal.signature.keyId). " +
      "A C2PA card without the seal keyId would float free of the evidence it certifies.",
    );
  }

  const {
    alg = "ed25519",
    privateKeyPath,
    signCertPath,
    generatorVersion = "0.9.0",
    taUrl,
  } = opts;

  const def = {
    alg,
    claim_generator_info: [{ name: CARD_GENERATOR, version: generatorVersion }],
    title: "Apohara Synthex Evidence Card",
    assertions: [
      {
        label: "c2pa.actions",
        data: {
          actions: [{
            action: "c2pa.created",
            softwareAgent: `${CARD_GENERATOR} ${generatorVersion}`,
            ...(evidence.sealedAt ? { when: evidence.sealedAt } : {}),
          }],
        },
      },
      {
        // NON-NEGOTIABLE binding: card ⇄ PDF attest the same evidence.
        label: SYNTHEX_ASSERTION_LABEL,
        data: {
          contentHash: evidence.contentHash,           // SHA-256 of the sealed payload
          keyId: sig.keyId,                            // Ed25519 seal keyId (same key signs the card)
          sealMethod: evidence.seal?.method ?? null,
          sealedAt: evidence.sealedAt ?? null,
          spec: CARD_SPEC,
        },
      },
    ],
  };

  if (privateKeyPath) def.private_key = privateKeyPath;
  if (signCertPath) def.sign_cert = signCertPath;
  if (taUrl) def.ta_url = taUrl;
  return def;
}

// ─── Card rendering ─────────────────────────────────────────────────────────

const BRAND = "#5b21b6";
const bandColor = (band) => (band === "HIGH" ? "#b91c1c" : band === "MEDIUM" ? "#b45309" : "#15803d");

/** Minimal HTML-escape for text interpolated into the card. */
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/**
 * Render the evidence card as a self-contained HTML string. PURE — no I/O.
 * 1200×630 (Open Graph ratio) so it doubles as a shareable preview.
 *
 * @param {object} evidence
 * @param {{ score?:number, band?:string, qrDataUrl?:string }} [view]
 * @returns {string} HTML
 */
export function renderCardHtml(evidence, view = {}) {
  const { payload = {}, contentHash, seal = {}, sealedAt } = evidence ?? {};
  const keyId = seal?.signature?.keyId ?? "—";
  const target = Array.isArray(payload.target) ? payload.target.join(", ") : (payload.target ?? "—");
  const lens = payload.lens ?? "—";
  const { score, band = "LOW", qrDataUrl } = view;
  const scoreTxt = Number.isFinite(score) ? String(score) : "—";

  return `<!doctype html><html><head><meta charset="utf-8"><style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{width:1200px;height:630px;font-family:'Helvetica Neue',Arial,sans-serif;
    background:linear-gradient(135deg,#1e1b2e 0%,#0f0e17 100%);color:#f4f1fb;overflow:hidden}
  .card{padding:56px 64px;height:100%;display:flex;flex-direction:column;justify-content:space-between}
  .top{display:flex;justify-content:space-between;align-items:flex-start}
  .brand{display:flex;align-items:center;gap:14px}
  .diamond{width:22px;height:22px;background:${BRAND};transform:rotate(45deg);border-radius:3px}
  .wordmark{font-size:26px;font-weight:700;letter-spacing:2px}
  .wordmark small{display:block;font-size:11px;letter-spacing:4px;color:#a78bfa;font-weight:400;margin-top:2px}
  .cc{text-align:right;font-size:12px;color:#a78bfa;line-height:1.5}
  .cc b{color:#f4f1fb}
  .mid{display:flex;gap:48px;align-items:center}
  .risk{flex:0 0 200px;text-align:center;padding:24px;border-radius:16px;background:rgba(255,255,255,.04);
    border:1px solid rgba(255,255,255,.08)}
  .risk .num{font-size:72px;font-weight:800;line-height:1;color:${bandColor(band)}}
  .risk .band{margin-top:8px;font-size:14px;letter-spacing:3px;font-weight:700;color:${bandColor(band)}}
  .risk .lbl{margin-top:4px;font-size:10px;letter-spacing:2px;color:#9ca3af}
  .facts{flex:1}
  .fact{margin-bottom:14px}
  .fact .k{font-size:11px;letter-spacing:1.5px;color:#9ca3af;text-transform:uppercase}
  .fact .v{font-size:17px;color:#f4f1fb;margin-top:2px}
  .mono{font-family:'SF Mono',Menlo,monospace;font-size:13px;color:#c4b5fd;word-break:break-all}
  .bottom{display:flex;justify-content:space-between;align-items:flex-end}
  .seal{font-size:11px;color:#9ca3af;line-height:1.7;max-width:760px}
  .seal .h{color:#a78bfa;letter-spacing:1px;text-transform:uppercase;font-size:10px}
  .qr{width:104px;height:104px;border-radius:10px;background:#fff;padding:8px}
  .qr img{width:100%;height:100%}
  </style></head><body><div class="card">
    <div class="top">
      <div class="brand"><div class="diamond"></div>
        <div class="wordmark">APOHARA SYNTHEX<small>EVIDENCE CARD</small></div></div>
      <div class="cc"><b>Content Credentials</b><br>C2PA · Ed25519<br><span style="color:#9ca3af">self-signed · untrusted source</span></div>
    </div>
    <div class="mid">
      <div class="risk"><div class="num">${esc(scoreTxt)}</div><div class="band">${esc(band)}</div><div class="lbl">SYNTHEX RISK SCORE</div></div>
      <div class="facts">
        <div class="fact"><div class="k">Target</div><div class="v">${esc(target)}</div></div>
        <div class="fact"><div class="k">Lens</div><div class="v">${esc(lens)}</div></div>
        <div class="fact"><div class="k">Sealed</div><div class="v">${esc(sealedAt ?? "—")}</div></div>
        <div class="fact"><div class="k">Content hash · SHA-256</div><div class="v mono">${esc(contentHash ?? "—")}</div></div>
        <div class="fact"><div class="k">Seal keyId · Ed25519</div><div class="v mono">${esc(keyId)}</div></div>
      </div>
    </div>
    <div class="bottom">
      <div class="seal"><span class="h">everything signed, nothing trusted</span><br>
        The card and the Evidence Report PDF attest the same content hash. Verify the C2PA credential with
        c2patool or contentcredentials.org; verify the seal with <b>synthex verify</b>.</div>
      ${qrDataUrl ? `<div class="qr"><img src="${esc(qrDataUrl)}" alt="verify"></div>` : ""}
    </div>
  </div></body></html>`;
}

/**
 * Render the evidence card to a PNG Buffer via Playwright (Chromium). Async I/O.
 * Dynamic imports keep playwright/qrcode/pdf-report out of the manifest-builder
 * import path (the gate + unit tests stay browser-free).
 *
 * @param {object} evidence
 * @param {{ width?:number, height?:number }} [opts]
 * @returns {Promise<Buffer>} PNG bytes (1200×630)
 */
export async function renderCardPng(evidence, opts = {}) {
  const { width = 1200, height = 630 } = opts;
  const [{ chromium }, QRCode, { riskScore }] = await Promise.all([
    import("playwright"),
    import("qrcode").then((m) => m.default ?? m),
    import("./pdf-report.js"),
  ]);

  const { score, band } = riskScore(evidence);
  const qrPayload = JSON.stringify({
    hash: evidence?.contentHash, keyId: evidence?.seal?.signature?.keyId, method: evidence?.seal?.method,
  });
  const qrDataUrl = await QRCode.toDataURL(qrPayload, { errorCorrectionLevel: "M", margin: 0, width: 200 });

  const html = renderCardHtml(evidence, { score, band, qrDataUrl });

  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 2 });
    await page.setContent(html, { waitUntil: "networkidle" });
    return await page.screenshot({ type: "png", clip: { x: 0, y: 0, width, height } });
  } finally {
    await browser.close();
  }
}
