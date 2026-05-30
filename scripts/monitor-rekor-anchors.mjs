#!/usr/bin/env node
// Synthex Rekor anchor monitor — watchdog for Rekor v2 shard/key rotation (item 3.1 + R3 upgrade,
// the analog of monitor-tsa-anchors.mjs). The pinned log key (src/prove/rekor-anchors.js) lets
// `rekor-verify` check a bundle's checkpoint signature OFFLINE. Sigstore rotates the Rekor v2 shard
// (origin + checkpoint key) ~every 6 months and publishes the new key via TUF (trusted_root.json).
//
// This monitor does TWO things:
//   (a) validates each pinned key still parses as an Ed25519 SPKI (structural), and
//   (b) R3 LIVE-COMPARE: fetches the shard's LIVE checkpoint (GET /checkpoint) and verifies its
//       C2SP signature against the PINNED key. If the live checkpoint no longer carries / verifies
//       under the pinned key, it reports status:"rotated" (exit 2) with the live vs pinned 4-byte
//       key-hint and a remediation pointer.
//
// HONEST SCOPE (binding): this DETECTS rotation and POINTS to the fix. It does NOT auto-fetch +
// trust the new key — trusting Sigstore's trusted_root.json requires full TUF signature
// verification (root threshold sigs, snapshot/timestamp rollback protection), i.e. a TUF client =
// a NEW DEPENDENCY, which the zero-new-deps rule forbids. So TUF-SIGNED auto-refresh stays roadmap;
// on rotation a human re-pins src/prove/rekor-anchors.js from trusted_root.json (manual step).
//
//   node scripts/monitor-rekor-anchors.mjs
// Exit: 0 ok (incl. network flake — checkpoint unreachable but pinned key still parses) ·
//       1 flake (unexpected throw) · 2 rotated/stale (pinned key invalid OR live checkpoint no
//       longer verifies under the pin → re-pin from TUF trusted_root.json).
import { createPublicKey } from "node:crypto";
import { Buffer } from "node:buffer";
import { pathToFileURL } from "node:url";
import { REKOR_V2_LOGS } from "../src/prove/rekor-anchors.js";
import { checkpointMatchesPinnedKey } from "../src/prove/rekor.js";

const defaultEmit = (r) => process.stdout.write(JSON.stringify(r) + "\n");

/**
 * Run the monitor. Exported + injectable fetchImpl/emit so the live-compare is unit-testable offline
 * (inject `emit` to capture records without hijacking global stdout). Returns the process exit code
 * (does NOT call process.exit — the CLI guard does).
 * @param {{fetchImpl?:typeof fetch, emit?:(r:object)=>void}} [opts]
 * @returns {Promise<number>}
 */
export async function main({ fetchImpl = fetch, emit = defaultEmit } = {}) {
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

    // (b) R3 live-compare: fetch the shard's live checkpoint + verify under the pinned key.
    let liveCompare = "unreachable";
    let envelope = null;
    try {
      const res = await fetchImpl(`${log.baseUrl}/checkpoint`, { signal: AbortSignal.timeout(8000) });
      if (res.ok) envelope = await res.text();
      else liveCompare = `http-${res.status}`;
    } catch (e) {
      liveCompare = `unreachable (${String(e.message).slice(0, 30)})`;
    }

    if (envelope) {
      const cmp = checkpointMatchesPinnedKey(envelope, log);
      if (cmp.match) {
        liveCompare = "verified";
      } else if (cmp.reason === "parse-error") {
        liveCompare = "unparseable-checkpoint"; // treat as flake (don't page on a bad body)
      } else {
        // ROTATION/forgery detected: the live checkpoint no longer verifies under the pinned key.
        emit({
          check: "rekor-anchor", status: "rotated", origin: log.origin,
          reason: cmp.reason, // "keyhint-rotated" | "signature"
          pinnedKeyHintHex: cmp.pinnedKeyHintHex, liveKeyHintHex: cmp.liveKeyHintHex,
          suggestedRefresh: "re-pin src/prove/rekor-anchors.js from Sigstore TUF trusted_root.json (tlogs[].rawBytes); full TUF-signed auto-refresh needs a TUF client (new dep) → roadmap",
          at,
        });
        return 2;
      }
    }

    emit({
      check: "rekor-anchor", status: "ok", origin: log.origin,
      reason: "pinned key valid (Ed25519 SPKI)", validFrom: log.validFrom, liveCompare,
      note: "live-compare against the shard checkpoint; ~6mo shard rotation re-pinned from TUF trusted_root.json on rotation", at,
    });
    okCount++;
  }
  console.log(`OK ${okCount} pinned key(s) valid; live-compared against the shard checkpoint (Rekor v2, ~6mo rotation via TUF trusted_root.json).`);
  return 0;
}

// CLI guard: run only when invoked directly (so `export main` doesn't auto-run under test import).
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => {
      emit({ check: "rekor-anchor", status: "flake", reason: String(err?.message ?? err), at: new Date().toISOString() });
      process.exit(1);
    });
}
