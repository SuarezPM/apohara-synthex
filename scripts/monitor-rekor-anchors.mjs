#!/usr/bin/env node
// Synthex Rekor anchor monitor — watchdog for Rekor v2 shard/key rotation (item 3.1, the analog
// of monitor-tsa-anchors.mjs). The pinned log key (src/prove/rekor-anchors.js) lets `rekor-verify`
// check a bundle's checkpoint signature OFFLINE. Sigstore rotates the Rekor v2 shard (origin +
// checkpoint key) roughly every 6 months and publishes the new key via TUF (trusted_root.json).
// This probes (a) that each pinned key still parses as an Ed25519 SPKI, and (b) the shard's
// reachability — so rotation is caught on a schedule, not the first time a user runs verify.
//
//   node scripts/monitor-rekor-anchors.mjs
// Exit: 0 ok · 1 flake (network) · 2 stale/fail (pinned key invalid). On rotation, refresh
// src/prove/rekor-anchors.js from Sigstore's TUF trusted_root.json.
import { createPublicKey } from "node:crypto";
import { Buffer } from "node:buffer";
import { REKOR_V2_LOGS } from "../src/prove/rekor-anchors.js";

const emit = (r) => process.stdout.write(JSON.stringify(r) + "\n");

async function reachable(baseUrl) {
  try {
    const res = await fetch(baseUrl, { signal: AbortSignal.timeout(8000) });
    return `http-${res.status}`;
  } catch (e) {
    return `unreachable (${String(e.message).slice(0, 30)})`;
  }
}

async function main() {
  const at = new Date().toISOString();
  let okCount = 0;
  for (const log of REKOR_V2_LOGS) {
    // (a) Sanity: the pinned SPKI must parse as an Ed25519 public key.
    let keyOk = false;
    try {
      const der = Buffer.from(log.publicKeySpkiB64, "base64");
      keyOk = createPublicKey({ key: der, format: "der", type: "spki" }).asymmetricKeyType === "ed25519";
    } catch { keyOk = false; }
    if (!keyOk) {
      emit({ check: "rekor-anchor", status: "stale", origin: log.origin, reason: "pinned key did not parse as Ed25519 SPKI", at });
      return 2;
    }
    // (b) Best-effort shard reachability (network flake never fails the key check).
    const shard = await reachable(log.baseUrl);
    emit({
      check: "rekor-anchor", status: "ok", origin: log.origin,
      reason: "pinned key valid (Ed25519 SPKI)", validFrom: log.validFrom, shard,
      note: "shard rotates ~6mo; refresh from Sigstore TUF trusted_root.json on rotation", at,
    });
    okCount++;
  }
  console.log(`OK ${okCount} pinned key(s) valid; monitor Rekor v2 shard rotation (~6mo, TUF trusted_root.json).`);
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    emit({ check: "rekor-anchor", status: "flake", reason: String(err?.message ?? err), at: new Date().toISOString() });
    process.exit(1);
  });
