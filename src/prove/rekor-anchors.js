// Pinned Rekor v2 transparency-log public keys.
//
// Source of truth: Sigstore's TUF-distributed trusted_root.json (the `tlogs`
// entry whose baseUrl is the Rekor v2 shard). Pinned here — same discipline as
// the DigiCert TSA anchors in tsa.js — so offline verification can check a log
// checkpoint's signature WITHOUT trusting the server's own response.
//
// Rekor v2 "shards" (rotates origin + checkpoint key) roughly every 6 months;
// when that happens, Sigstore publishes the new log pubkey via TUF and this file
// must be refreshed (operational follow-up, analogous to the F4 TSA-anchor
// monitor). A bundle anchored under an old shard stays verifiable as long as the
// old shard's pubkey remains pinned here.
export const REKOR_V2_LOGS = Object.freeze([
  Object.freeze({
    origin: "log2025-1.rekor.sigstore.dev",
    baseUrl: "https://log2025-1.rekor.sigstore.dev",
    keyDetails: "PKIX_ED25519",
    // DER SPKI of the log's Ed25519 checkpoint-signing key (trusted_root.json)
    publicKeySpkiB64: "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=",
    validFrom: "2025-09-23T00:00:00Z",
  }),
]);

/** Look up a pinned log by its checkpoint origin (the first checkpoint line). */
export function findLogByOrigin(origin) {
  return REKOR_V2_LOGS.find((l) => l.origin === origin) ?? null;
}
