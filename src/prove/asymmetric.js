// Asymmetric signature layer (Ed25519, v0.8.0).
//
// Closes the symmetric-HMAC gap the 2026-05-29 audit flagged:
// HMAC-SHA256 is symmetric → no non-repudiation (the verifier can also forge).
// Ed25519 gives third-party-verifiable WHO: anyone with the public key
// verifies, but only the private-key holder can sign.
//
// Honesty: the embedded pubkey alone is integrity, NOT identity — anyone can
// generate a keypair and embed its pubkey. Identity requires out-of-band
// publication (DNS TXT / .well-known JSON / transparency log) + caller-side
// `expectedKeyId` discovery. The signer-identity publication helpers live in
// `bin/synthex.mjs` (keygen + publish-keyid verbs); HONESTY §1.4 documents
// the contract and the rotation/continuity tradeoffs.
//
// We sign over the EXACT same canonical string `_serializeForHmac(payload)`
// produces in evidence-report.js — byte-identity is the equivalence argument
// with C2PA `c2pa.hash.data` + claim signature. Single shared encoder helper
// to eliminate sign/verify drift (R4 in the migration plan).
//
// Zero new dependencies — `node:crypto` webcrypto Ed25519 is native and
// stable in Node ≥24.
import { webcrypto, createHash, generateKeyPairSync, createPublicKey, createPrivateKey } from "node:crypto";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";

const ALG = "Ed25519";

/** Single source of truth for sign/verify pre-image encoding. UTF-8 always. */
function encodeMessage(canonicalString) {
  return Buffer.from(String(canonicalString), "utf8");
}

/**
 * SHA-256 of the SPKI DER, truncated to 32 hex chars (16 bytes). Stable across
 * runs for the same public key; lets a verifier pin/allow-list a key without
 * parsing SPKI. This is the rotation handle (operator publishes the keyId
 * out-of-band; the seal carries it; the verifier matches against the
 * --expected-keyid the operator passes).
 *
 * @param {Uint8Array|Buffer|string} spkiDerOrB64
 *        Public key in SPKI DER form (bytes) or base64-encoded SPKI DER (string).
 * @returns {string} 32-hex-char keyId
 */
export function keyIdOf(spkiDerOrB64) {
  const der = typeof spkiDerOrB64 === "string"
    ? Buffer.from(spkiDerOrB64, "base64")
    : Buffer.from(spkiDerOrB64);
  return createHash("sha256").update(der).digest("hex").slice(0, 32);
}

/**
 * Generate a new Ed25519 keypair. Returns PEM (for persistence in
 * ~/.config/apohara/synthex/) + SPKI base64 + keyId (for inline serialization).
 *
 * @returns {{
 *   privateKeyPem: string,  // pkcs8 PEM — chmod 0600 on disk
 *   publicKeyPem: string,   // spki PEM — distributable
 *   publicKeySpkiB64: string,
 *   keyId: string
 * }}
 */
export function generateKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync(ALG.toLowerCase());
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  return {
    privateKeyPem,
    publicKeyPem,
    publicKeySpkiB64: Buffer.from(spkiDer).toString("base64"),
    keyId: keyIdOf(spkiDer),
  };
}

/**
 * Sign a canonical pre-image string. The private key may be supplied as a
 * pkcs8 PEM string, a base64-encoded pkcs8 DER string, or a Buffer/Uint8Array
 * holding the raw pkcs8 DER.
 *
 * @param {string} canonicalString  — what _serializeForHmac(payload) produces
 * @param {string|Buffer|Uint8Array} signingKey
 * @returns {Promise<{alg:"Ed25519", publicKey:string, keyId:string, value:string, signedAt:string}>}
 *
 * NEVER throws on a malformed canonicalString (returns null instead). DOES
 * throw on a malformed key (caller bug).
 */
export async function sign(canonicalString, signingKey) {
  if (canonicalString == null) return null;
  const privKeyObj = _loadPrivateKey(signingKey);
  const pubKeyObj = createPublicKey(privKeyObj);
  const spkiDer = pubKeyObj.export({ type: "spki", format: "der" });

  // pkcs8 → webcrypto CryptoKey
  const pkcs8Der = privKeyObj.export({ type: "pkcs8", format: "der" });
  const cryptoKey = await webcrypto.subtle.importKey(
    "pkcs8",
    pkcs8Der.buffer.slice(pkcs8Der.byteOffset, pkcs8Der.byteOffset + pkcs8Der.byteLength),
    { name: ALG },
    false,
    ["sign"],
  );
  const msg = encodeMessage(canonicalString);
  const sigAb = await webcrypto.subtle.sign(ALG, cryptoKey,
    msg.buffer.slice(msg.byteOffset, msg.byteOffset + msg.byteLength));

  return {
    alg: ALG,
    publicKey: Buffer.from(spkiDer).toString("base64"),
    keyId: keyIdOf(spkiDer),
    value: Buffer.from(new Uint8Array(sigAb)).toString("base64"),
    signedAt: new Date().toISOString(),
  };
}

/**
 * Verify a signature block against a canonical pre-image string. Fail-closed:
 * any decode/import/verify error returns `{ok:false, reason:"<reason>"}`.
 * Never throws.
 *
 * @param {string} canonicalString
 * @param {object|null} signatureBlock  — what sign() returned, or null/undefined for "no signature"
 * @returns {Promise<{
 *   ok: boolean,
 *   reason: null | "no-signature" | "bad-signature" | "malformed-signature" | "key-mismatch"
 * }>}
 *
 * `reason` semantics:
 *   - no-signature       → signatureBlock absent (caller decides whether to treat as failure)
 *   - bad-signature      → signature math fails (tamper alarm)
 *   - malformed-signature→ key/sig decode fail, schema fail, kid mismatch with embedded SPKI
 *   - key-mismatch       → caller checked the embedded keyId vs an expectedKeyId; surfaced upstream
 */
export async function verify(canonicalString, signatureBlock) {
  if (!signatureBlock) return { ok: false, reason: "no-signature" };
  if (typeof signatureBlock !== "object") return { ok: false, reason: "malformed-signature" };
  const { alg, publicKey, keyId, value } = signatureBlock;
  if (alg !== ALG) return { ok: false, reason: "malformed-signature" };
  if (typeof publicKey !== "string" || typeof value !== "string") {
    return { ok: false, reason: "malformed-signature" };
  }
  let spkiDer, sigBytes;
  try {
    spkiDer = Buffer.from(publicKey, "base64");
    sigBytes = Buffer.from(value, "base64");
  } catch {
    return { ok: false, reason: "malformed-signature" };
  }
  // Embedded keyId must match the SPKI it claims to describe (anti-spoofing).
  if (keyId && keyId !== keyIdOf(spkiDer)) {
    return { ok: false, reason: "malformed-signature" };
  }
  try {
    const cryptoKey = await webcrypto.subtle.importKey(
      "spki",
      spkiDer.buffer.slice(spkiDer.byteOffset, spkiDer.byteOffset + spkiDer.byteLength),
      { name: ALG },
      false,
      ["verify"],
    );
    const msg = encodeMessage(canonicalString);
    const ok = await webcrypto.subtle.verify(
      ALG, cryptoKey,
      sigBytes.buffer.slice(sigBytes.byteOffset, sigBytes.byteOffset + sigBytes.byteLength),
      msg.buffer.slice(msg.byteOffset, msg.byteOffset + msg.byteLength),
    );
    return { ok, reason: ok ? null : "bad-signature" };
  } catch {
    return { ok: false, reason: "malformed-signature" };
  }
}

/**
 * Resolve a signing key from operator-provided env / CLI / XDG default.
 * Lookup order matches docs/HONESTY.md §1.4 — NO ephemeral default, per
 * the A1 reviewer correction (ephemeral breaks delta_chain continuity).
 *
 *   1. SYNTHEX_SIGNING_KEY (inline pkcs8 PEM or base64 — serverless/CI)
 *   2. SYNTHEX_SIGNING_KEY_FILE (explicit path)
 *   3. ~/.config/apohara/synthex/synthex-ed25519.key (XDG default;
 *      XDG_CONFIG_HOME aware)
 *   4. null → caller treats as unsigned ('symmetric-only' seal)
 *
 * @returns {string|null} pkcs8 PEM (or null when no key configured)
 */
export function resolveSigningKey({ env = process.env, fs = null } = {}) {
  const inline = env.SYNTHEX_SIGNING_KEY;
  if (typeof inline === "string" && inline.length > 0) {
    return _normalizePkcs8(inline);
  }
  const explicitPath = env.SYNTHEX_SIGNING_KEY_FILE;
  if (typeof explicitPath === "string" && explicitPath.length > 0) {
    const f = fs ?? { readFileSync };
    return f.readFileSync(explicitPath, "utf8");
  }
  // XDG default
  const xdg = env.XDG_CONFIG_HOME || (env.HOME ? `${env.HOME}/.config` : null);
  if (!xdg) return null;
  const def = `${xdg}/apohara/synthex/synthex-ed25519.key`;
  try {
    const f = fs ?? { readFileSync };
    return f.readFileSync(def, "utf8");
  } catch {
    return null;
  }
}

// ─── internals ──────────────────────────────────────────────────────────

function _loadPrivateKey(input) {
  if (typeof input === "string") {
    return createPrivateKey(_normalizePkcs8(input));
  }
  // Buffer / Uint8Array → assume pkcs8 DER bytes
  return createPrivateKey({ key: Buffer.from(input), format: "der", type: "pkcs8" });
}

function _normalizePkcs8(s) {
  const trimmed = String(s).trim();
  if (trimmed.startsWith("-----BEGIN")) return trimmed;
  // Assume base64 pkcs8 DER; wrap as PEM for createPrivateKey
  const lines = trimmed.match(/.{1,64}/g) ?? [];
  return ["-----BEGIN PRIVATE KEY-----", ...lines, "-----END PRIVATE KEY-----"].join("\n");
}
