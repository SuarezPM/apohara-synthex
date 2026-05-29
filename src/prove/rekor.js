// Rekor v2 transparency-log anchor for the signing keyId (v0.9.0).
//
// What this gives Synthex: a public, append-only, monitorable record that the
// Ed25519 signing keyId existed at a point in time, anchored in Sigstore's Rekor
// v2 log. It UPGRADES the existence proof from a single TSA to a publicly
// auditable log. It does NOT add a new timestamp (the RFC 3161 TSA already does
// that) and it does NOT add identity (a bare key is anonymous — real identity is
// OIDC + Fulcio, an interactive opt-in outside the automatic seal). See
// HONESTY §1.3.
//
// Design constraints (binding):
//   - Anchor the keyId ONCE, never per-evidence (per-evidence is redundant with
//     the TSA, adds network to every seal, breaks deterministic offline sealing,
//     and the public instance caps payloads).
//   - Rekor v2 only (v1 is frozen). v2 removes the online search API; the model
//     is: capture the inclusion bundle at publish time, persist it next to the
//     keyId, and verify it OFFLINE against the TUF-pinned log key (rekor-anchors.js).
//   - Ed25519 stays the seal algorithm. Rekor v2 hashedrekord rejects Ed25519
//     (it is a sign-the-digest type), but the DSSE entry type accepts it — so the
//     keyId is anchored as a DSSE in-toto statement signed by the seal key.
import { createHash, createPublicKey, createPrivateKey, sign, verify } from "node:crypto";
import { Buffer } from "node:buffer";
import { REKOR_V2_LOGS, findLogByOrigin } from "./rekor-anchors.js";

const PAYLOAD_TYPE = "application/vnd.in-toto+json";
const PREDICATE_TYPE = "https://apohara.dev/synthex/keyid/v1";
const DEFAULT_LOG = REKOR_V2_LOGS[0];

// ─── DSSE / statement ──────────────────────────────────────────────────────

/** DSSE PAE (RFC: in-toto DSSE) — "DSSEv1 SP len(type) SP type SP len(body) SP body". */
export function pae(payloadType, payload) {
  const t = Buffer.from(payloadType);
  const b = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  return Buffer.concat([Buffer.from(`DSSEv1 ${t.length} `), t, Buffer.from(` ${b.length} `), b]);
}

/**
 * Build the in-toto statement that attests the signing keyId. PURE.
 * @param {{keyId:string, publicKeySpkiB64:string, alg?:string}} key
 * @returns {{payloadType:string, payload:Buffer}}
 */
export function buildKeyIdStatement({ keyId, publicKeySpkiB64, alg = "Ed25519" }) {
  if (!keyId || !publicKeySpkiB64) throw new TypeError("buildKeyIdStatement: keyId + publicKeySpkiB64 required");
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "apohara-synthex-signing-key", digest: { sha256: keyId.padEnd(64, "0") } }],
    predicateType: PREDICATE_TYPE,
    predicate: { keyId, alg, publicKeySpkiB64 },
  };
  return { payloadType: PAYLOAD_TYPE, payload: Buffer.from(JSON.stringify(statement)) };
}

// ─── publish (network) ─────────────────────────────────────────────────────

/**
 * Anchor the keyId in Rekor v2 as a DSSE in-toto statement. Returns a
 * self-contained bundle (envelope + seal pubkey + TransparencyLogEntry with the
 * inclusion proof + checkpoint) to persist next to the keyId for offline verify.
 *
 * @param {string} privateKeyPem  — the Ed25519 SEAL private key (pkcs8 PEM)
 * @param {{
 *   keyId:string, publicKeySpkiB64:string,
 *   logUrl?:string, timeoutMs?:number, fetchImpl?:typeof fetch
 * }} opts
 * @returns {Promise<object>} bundle
 */
export async function anchorKeyId(privateKeyPem, opts = {}) {
  const { keyId, publicKeySpkiB64 } = opts;
  const logUrl = opts.logUrl ?? process.env.SYNTHEX_REKOR_URL ?? DEFAULT_LOG.baseUrl;
  const timeoutMs = opts.timeoutMs ?? 25000;
  const fetchImpl = opts.fetchImpl ?? fetch;

  const { payloadType, payload } = buildKeyIdStatement({ keyId, publicKeySpkiB64 });
  const privKey = createPrivateKey(privateKeyPem);
  const sig = sign(null, pae(payloadType, payload), privKey);
  const spkiDer = Buffer.from(publicKeySpkiB64, "base64");

  const body = {
    dsseRequestV002: {
      envelope: {
        payload: payload.toString("base64"),
        payloadType,
        signatures: [{ sig: sig.toString("base64"), keyid: "" }],
      },
      verifiers: [{ publicKey: { rawBytes: spkiDer.toString("base64") }, keyDetails: "PKIX_ED25519" }],
    },
  };

  const res = await fetchImpl(`${logUrl}/api/v2/log/entries`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  if (res.status !== 201 && res.status !== 200) {
    throw new Error(`Rekor v2 anchor failed: HTTP ${res.status} ${text.slice(0, 200)}`);
  }
  const tlogEntry = JSON.parse(text);
  const origin = String(tlogEntry?.inclusionProof?.checkpoint?.envelope ?? "").split("\n")[0];

  return {
    format: "synthex-rekor-anchor-v1",
    keyId,
    logOrigin: origin,
    envelope: body.dsseRequestV002.envelope,
    publicKey: { rawBytes: spkiDer.toString("base64"), keyDetails: "PKIX_ED25519" },
    tlogEntry,
  };
}

// ─── offline verification ──────────────────────────────────────────────────

const sha256 = (...bufs) => createHash("sha256").update(Buffer.concat(bufs)).digest();
const leafHashOf = (data) => sha256(Buffer.from([0x00]), data);
const hashChildren = (l, r) => sha256(Buffer.from([0x01]), l, r);
const bitLength = (n) => { let c = 0; while (n > 0n) { c++; n >>= 1n; } return c; };
const popcount = (n) => { let c = 0; while (n > 0n) { c += Number(n & 1n); n >>= 1n; } return c; };

/** Reconstruct the Merkle root from an inclusion proof (RFC 6962 §2.1.1). */
export function rootFromInclusionProof(index, size, leafHash, proofB64) {
  const i = BigInt(index), n = BigInt(size);
  if (i < 0n || i >= n) throw new Error("inclusion proof: index out of range");
  const inner = bitLength(i ^ (n - 1n));
  const border = popcount(i >> BigInt(inner));
  if (proofB64.length !== inner + border) {
    throw new Error(`inclusion proof: length ${proofB64.length} != inner ${inner} + border ${border}`);
  }
  let res = leafHash;
  for (let k = 0; k < inner; k++) {
    const p = Buffer.from(proofB64[k], "base64");
    res = ((i >> BigInt(k)) & 1n) === 0n ? hashChildren(res, p) : hashChildren(p, res);
  }
  for (let k = inner; k < inner + border; k++) res = hashChildren(Buffer.from(proofB64[k], "base64"), res);
  return res;
}

/** Parse a C2SP signed-note checkpoint envelope into its parts. */
export function parseCheckpoint(envelope) {
  const env = String(envelope);
  const sep = env.indexOf("\n\n—");           // blank line precedes the signature block
  if (sep < 0) throw new Error("checkpoint: no signature block");
  const signedText = env.slice(0, sep + 1);   // body lines incl. trailing \n, WITHOUT the blank line
  const lines = signedText.split("\n");
  const sigBlock = env.slice(sep + 2);        // the "— name base64" lines
  return { origin: lines[0], treeSize: BigInt(lines[1]), rootHashB64: lines[2], signedText, sigBlock };
}

/** C2SP key ID for an Ed25519 log key: SHA-256(name || 0x0A || 0x01 || 32B pubkey)[:4]. */
function ed25519CheckpointKeyId(origin, spkiDer) {
  const rawPub = Buffer.from(spkiDer).subarray(-32);
  return sha256(Buffer.from(origin), Buffer.from([0x0a, 0x01]), rawPub).subarray(0, 4);
}

/**
 * Verify a Rekor anchor bundle fully OFFLINE. NEVER throws.
 * @param {object} bundle  — output of anchorKeyId()
 * @param {{logs?:Array}} [opts]  — pinned logs (defaults to rekor-anchors.js)
 * @returns {{ok:boolean, reason:string|null, checks:object}}
 */
export function verifyRekorBundle(bundle, opts = {}) {
  const checks = { dsseSig: false, statementKeyId: false, leaf: false, inclusion: false, checkpointSig: false, originPinned: false };
  try {
    if (!bundle?.tlogEntry?.inclusionProof?.checkpoint?.envelope) {
      return { ok: false, reason: "malformed-bundle", checks };
    }
    // 1. DSSE seal signature over the statement
    const sealPub = createPublicKey({ key: Buffer.from(bundle.publicKey.rawBytes, "base64"), format: "der", type: "spki" });
    const payload = Buffer.from(bundle.envelope.payload, "base64");
    const dsseSig = Buffer.from(bundle.envelope.signatures[0].sig, "base64");
    checks.dsseSig = verify(null, pae(bundle.envelope.payloadType, payload), sealPub, dsseSig);
    if (!checks.dsseSig) return { ok: false, reason: "bad-dsse-signature", checks };

    // 2. statement attests the bundle's keyId
    const stmt = JSON.parse(payload.toString("utf8"));
    checks.statementKeyId = stmt?.predicate?.keyId === bundle.keyId
      && stmt?.predicate?.publicKeySpkiB64 === bundle.publicKey.rawBytes;
    if (!checks.statementKeyId) return { ok: false, reason: "statement-keyid-mismatch", checks };

    // 3-4. leaf hash + Merkle inclusion → root
    const ip = bundle.tlogEntry.inclusionProof;
    const cp = parseCheckpoint(ip.checkpoint.envelope);
    const leaf = leafHashOf(Buffer.from(bundle.tlogEntry.canonicalizedBody, "base64"));
    checks.leaf = true;
    const root = rootFromInclusionProof(bundle.tlogEntry.logIndex, cp.treeSize, leaf, ip.hashes);
    checks.inclusion = root.toString("base64") === cp.rootHashB64;
    if (!checks.inclusion) return { ok: false, reason: "inclusion-proof-mismatch", checks };

    // 5. checkpoint origin is a pinned log + its key verifies the checkpoint signature
    const logs = opts.logs ?? REKOR_V2_LOGS;
    const log = (opts.findLog ?? findLogByOrigin)(cp.origin) ?? logs.find((l) => l.origin === cp.origin);
    checks.originPinned = !!log;
    if (!log) return { ok: false, reason: "unpinned-log-origin", checks };
    const logSpki = Buffer.from(log.publicKeySpkiB64, "base64");
    const expectKid = ed25519CheckpointKeyId(cp.origin, logSpki);
    const logPub = createPublicKey({ key: logSpki, format: "der", type: "spki" });
    // Find the signature line whose 4-byte key hint matches the pinned log key.
    let verified = false;
    for (const line of cp.sigBlock.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("—")) continue;
      const b64 = trimmed.split(" ").pop();
      let blob;
      try { blob = Buffer.from(b64, "base64"); } catch { continue; }
      if (blob.length < 5) continue;
      if (!blob.subarray(0, 4).equals(expectKid)) continue;
      if (verify(null, Buffer.from(cp.signedText), logPub, blob.subarray(4))) { verified = true; break; }
    }
    checks.checkpointSig = verified;
    if (!verified) return { ok: false, reason: "bad-checkpoint-signature", checks };

    return { ok: true, reason: null, checks };
  } catch (e) {
    return { ok: false, reason: `verify-error: ${e?.message ?? String(e)}`, checks };
  }
}
