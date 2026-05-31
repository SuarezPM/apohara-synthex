// ============================================================================
// STRESS DIMENSION (2) — SEAL INTEGRITY (the killer metric).
//
// Independently re-verify a batch of sealed evidence artifacts using the SHIPPED
// verifier (`verifyEvidence` from src/prove/evidence-report.js). Pure + injectable:
// the verifier is passed in (`verifyImpl`) so the unit test runs with fixtures and
// ZERO network — exactly the harness discipline run.mjs documents.
//
// HONESTY (the moat) — what each layer count MEANS here:
//   - ed25519 : counted ONLY when the injected verifier returns signatureValid===true
//               (a real Ed25519 verify). 'symmetric-only' is NOT a pass — it means the
//               artifact carries no asymmetric signature, so the layer is absent, not
//               verified. false is a tamper alarm.
//   - tsa     : counted ONLY when the verifier returns tsaOk===true (RFC 3161 token
//               granted + digest match via the shipped CMS-chain verifier). null = no
//               TSA layer present (absent, not verified). false = present-but-failed.
//   - rekor   : the single injected `verifyImpl` (verifyEvidence) does NOT verify Rekor
//               bundles — that lives in src/prove/rekor.js (verifyRekorBundle). To avoid
//               fabricating a verdict the injected impl never produced, this dimension
//               counts a Rekor layer as verified ONLY when the item carries a Rekor
//               bundle AND its OWN verify function reports ok. If no rekorVerify is
//               supplied, Rekor presence is recorded but NEVER counted as verified.
//   - c2pa    : same contract as rekor, via an optional `c2paVerify`.
//
// An artifact counts toward `verified` (top-level) only when EVERY layer that is
// PRESENT verifies and the base integrity holds (hashOk, and hmacOk!==false). A
// missing optional layer never fails an artifact; a present-but-broken layer always
// does. We never count an unverifiable artifact as verified, and we report the gap.
//
// Item shape (frozen, not mutated):
//   { evidence, opts?, rekorBundle?, c2paSidecar? }
//   - evidence    : the sealed Evidence Report object verifyEvidence consumes.
//   - opts        : per-item verify opts forwarded to verifyImpl (e.g. { hmacKey }).
//   - rekorBundle : optional Sigstore Rekor v2 bundle sidecar (NOT inside seal).
//   - c2paSidecar : optional C2PA Content Credentials sidecar (NOT inside seal).
// A bare evidence object (no wrapper) is also accepted and normalized.
//
// Returns: { total, verified, failed, byLayer:{ed25519,tsa,rekor,c2pa} }
// (plus `results` — per-item verdicts — so the harness can show every failure).
// ============================================================================

/** Normalize a list item into the frozen { evidence, opts, rekorBundle, c2paSidecar } shape. */
function _normalizeItem(item) {
  // A wrapper carries `evidence`; otherwise the item IS the evidence object.
  const isWrapper = item && typeof item === "object" && "evidence" in item;
  const evidence = isWrapper ? item.evidence : item;
  const opts = isWrapper && item.opts ? item.opts : {};
  const rekorBundle = isWrapper ? (item.rekorBundle ?? null) : null;
  const c2paSidecar = isWrapper ? (item.c2paSidecar ?? null) : null;
  return Object.freeze({ evidence, opts, rekorBundle, c2paSidecar });
}

/**
 * Verify a batch of sealed evidence artifacts independently.
 *
 * @param {Array} evidenceList  list of evidence objects or { evidence, opts, rekorBundle, c2paSidecar } items.
 * @param {{
 *   verifyImpl: function,      REQUIRED — the shipped async verifyEvidence (evidence, opts) => verdict.
 *   verifyOpts?: object,       base opts merged under each item's opts (e.g. shared trustedCerts).
 *   rekorVerify?: function,    optional (bundle) => { ok } — wire src/prove/rekor.js verifyRekorBundle.
 *   c2paVerify?: function,     optional async (sidecar) => { ok } — wire src/prove/c2pa.js verifyC2paManifest.
 * }} cfg
 * @returns {Promise<{
 *   total:number, verified:number, failed:number,
 *   byLayer:{ ed25519:number, tsa:number, rekor:number, c2pa:number },
 *   results: Array<{ index:number, verified:boolean, layers:object, reason:(string|null) }>
 * }>}
 */
export async function verifySealIntegrity(evidenceList, cfg = {}) {
  const { verifyImpl, verifyOpts = {}, rekorVerify, c2paVerify } = cfg;
  if (typeof verifyImpl !== "function") {
    throw new TypeError("verifySealIntegrity requires cfg.verifyImpl (the shipped verifyEvidence)");
  }
  const list = Array.isArray(evidenceList) ? evidenceList : [];

  const byLayer = { ed25519: 0, tsa: 0, rekor: 0, c2pa: 0 };
  const results = [];
  let verified = 0;

  for (let index = 0; index < list.length; index++) {
    const { evidence, opts, rekorBundle, c2paSidecar } = _normalizeItem(list[index]);

    // Fail-safe: a verifier throwing must NOT crash the batch or fake a pass.
    let v;
    try {
      v = await verifyImpl(evidence, { ...verifyOpts, ...opts });
    } catch (e) {
      results.push(Object.freeze({
        index,
        verified: false,
        layers: Object.freeze({ ed25519: null, tsa: null, rekor: null, c2pa: null }),
        reason: `verifier threw: ${e.message}`,
      }));
      continue;
    }

    // Per-layer verdicts. true=present+verified, false=present+failed, null=absent.
    const layerEd25519 = v.signatureValid === true ? true
      : v.signatureValid === false ? false
      : null; // 'symmetric-only' / null → no asymmetric layer present
    const layerTsa = v.tsaOk === true ? true
      : v.tsaOk === false ? false
      : null; // no TSA layer present

    // Rekor / C2PA — only the item's OWN verifier may attest these; verifyEvidence does not.
    let layerRekor = null;
    if (rekorBundle != null) {
      if (typeof rekorVerify === "function") {
        try {
          const r = rekorVerify(rekorBundle);
          layerRekor = r && r.ok === true;
        } catch {
          layerRekor = false;
        }
      } else {
        // Present but no verifier wired → honestly unverified (NOT a pass, NOT a fail).
        layerRekor = "present-unverified";
      }
    }

    let layerC2pa = null;
    if (c2paSidecar != null) {
      if (typeof c2paVerify === "function") {
        try {
          const r = await c2paVerify(c2paSidecar);
          layerC2pa = r && r.ok === true;
        } catch {
          layerC2pa = false;
        }
      } else {
        layerC2pa = "present-unverified";
      }
    }

    // Tally a layer ONLY on a true verdict (never on presence-without-verification).
    if (layerEd25519 === true) byLayer.ed25519++;
    if (layerTsa === true) byLayer.tsa++;
    if (layerRekor === true) byLayer.rekor++;
    if (layerC2pa === true) byLayer.c2pa++;

    // Base integrity: hash must hold, and if an HMAC was checked it must not be false.
    const baseOk = v.hashOk === true && v.hmacOk !== false;

    // Any PRESENT layer that failed (=== false) breaks the artifact. A present-unverified
    // Rekor/C2PA layer does NOT break it (we just did not attest it) — but it cannot count
    // toward byLayer either, which keeps the verified-% honest.
    const presentFailed =
      layerEd25519 === false || layerTsa === false ||
      layerRekor === false || layerC2pa === false;

    const isVerified = baseOk && !presentFailed;
    if (isVerified) verified++;

    results.push(Object.freeze({
      index,
      verified: isVerified,
      layers: Object.freeze({
        ed25519: layerEd25519,
        tsa: layerTsa,
        rekor: layerRekor,
        c2pa: layerC2pa,
      }),
      reason: isVerified ? null : _reasonFor({ baseOk, v, layerEd25519, layerTsa, layerRekor, layerC2pa }),
    }));
  }

  return {
    total: list.length,
    verified,
    failed: list.length - verified,
    byLayer: Object.freeze(byLayer),
    results: Object.freeze(results),
  };
}

/** Human reason for a non-verified artifact — first concrete failure, no fabrication. */
function _reasonFor({ baseOk, v, layerEd25519, layerTsa, layerRekor, layerC2pa }) {
  if (v.hashOk !== true) return "hash-mismatch";
  if (v.hmacOk === false) return "hmac-mismatch";
  if (layerEd25519 === false) return "ed25519-bad-signature";
  if (layerTsa === false) return "tsa-failed";
  if (layerRekor === false) return "rekor-failed";
  if (layerC2pa === false) return "c2pa-failed";
  if (!baseOk) return "base-integrity-failed";
  return "unverified";
}
