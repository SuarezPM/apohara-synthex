#!/usr/bin/env node
/**
 * Synthex anchor monitor — defensive watchdog for DigiCert TSA anchor drift.
 *
 * Synthex pins DigiCert's TSA roots (src/prove/tsa-anchors.js). When DigiCert
 * rotates those roots, every freshly-minted RFC 3161 token stops chaining to
 * our pinned bundle and verification fails with reason "untrusted-anchor".
 * Because rotation is silent and out of our control, we probe for it on a
 * schedule instead of discovering it the first time a user runs `prove`.
 *
 * Each run mints a fresh token for a deterministic per-day hash and verifies
 * it against the SHIPPED anchors (no trustedCerts override -> loadAnchors()).
 * The single structured JSON line is the contract the CI workflow parses, and
 * "synthex-anchor-monitor" makes both the probe hash and this output greppable.
 *
 * Exit codes (consumed by .github/workflows/tsa-anchor-monitor.yml):
 *   0 -> ok    : token verified, anchors still trusted
 *   2 -> stale : signatureValidReason === "untrusted-anchor" -> DigiCert rotated
 *   1 -> flake : network/DNS/timeout/other transient -> do NOT page the operator
 */

import { createHash } from 'node:crypto'
import { requestTimestamp, verifyTimestamp } from '../src/prove/tsa.js'

const EXIT_OK = 0
const EXIT_FLAKE = 1
const EXIT_STALE = 2

// A new digest each day keeps tokens fresh (a stale cached token could mask a
// rotation) while staying deterministic enough to grep for in logs/issues.
// requestTimestamp expects 32 raw bytes, so we hand it the digest Buffer.
function dailyHashBytes(now) {
  const day = now.toISOString().slice(0, 10) // YYYY-MM-DD
  return createHash('sha256').update(`synthex-anchor-monitor-${day}`).digest()
}

// One line, machine-parseable. The workflow greps this verbatim into the issue.
function emit(record) {
  process.stdout.write(JSON.stringify(record) + '\n')
}

async function main() {
  const at = new Date().toISOString()
  const hashBytes = dailyHashBytes(new Date())

  // requestTimestamp returns the raw TimeStampResp DER (Uint8Array); the serial
  // only surfaces after we decode it in verifyTimestamp, hence "unknown" here.
  let tokenDer
  try {
    tokenDer = await requestTimestamp(hashBytes)
  } catch (err) {
    // Could not even obtain a token: DNS, TLS, timeout, TSA 5xx. Transient by
    // assumption -- a real rotation still answers, it just fails to verify.
    emit({
      check: 'tsa-anchor',
      status: 'flake',
      reason: `request-failed: ${err.message}`,
      at,
      serial: 'unknown',
    })
    return EXIT_FLAKE
  }

  let result
  try {
    // No trustedCerts -> verifyTimestamp falls back to the pinned anchor bundle.
    result = await verifyTimestamp(tokenDer, hashBytes)
  } catch (err) {
    emit({
      check: 'tsa-anchor',
      status: 'flake',
      reason: `verify-errored: ${err.message}`,
      at,
      serial: 'unknown',
    })
    return EXIT_FLAKE
  }

  const serial = result.serial ?? 'unknown'

  if (result.signatureValid === true) {
    emit({
      check: 'tsa-anchor',
      status: 'ok',
      reason: result.signatureValidReason ?? 'verified',
      at,
      serial,
    })
    return EXIT_OK
  }

  // The one failure mode worth paging for: the chain to our pinned roots broke.
  if (result.signatureValidReason === 'untrusted-anchor') {
    emit({
      check: 'tsa-anchor',
      status: 'stale',
      reason: 'untrusted-anchor',
      at,
      serial,
    })
    return EXIT_STALE
  }

  // Any other verify outcome ("forged" / "chain-incomplete" / null) is not an
  // anchor-rotation signal in this probe -- almost certainly a transient glitch
  // talking to DigiCert -- so treat as flake and don't page the operator.
  emit({
    check: 'tsa-anchor',
    status: 'flake',
    reason: result.signatureValidReason || 'verify-failed',
    at,
    serial,
  })
  return EXIT_FLAKE
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    // Last-resort guard: an unexpected throw must not masquerade as success.
    emit({
      check: 'tsa-anchor',
      status: 'flake',
      reason: `unexpected: ${err?.message ?? String(err)}`,
      at: new Date().toISOString(),
      serial: 'unknown',
    })
    process.exit(EXIT_FLAKE)
  })
