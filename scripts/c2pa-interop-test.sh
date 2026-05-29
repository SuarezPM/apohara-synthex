#!/usr/bin/env bash
# C2PA interop test — verifies our sidecar with c2patool when available.
#
# Status (v0.8.0): our c2pa.js emits a structurally-spec-shaped sidecar that
# OUR verifier round-trips (see test/prove/c2pa.test.js · 9/9 pass). Direct
# c2patool verification of our JSON sidecar is NOT supported (c2patool expects
# JUMBF-wrapped manifest stores embedded in media containers). c2patool also
# rejects our self-signed cert because it lacks C2PA-specific EKUs
# (1.3.6.1.5.5.7.3.36 id-kp-credentialSign and adjacent OIDs from C2PA v2 §14.10).
#
# Full c2patool interop is a v0.9 goal. Two paths:
#   (a) Emit JUMBF directly — significant additional work (JUMBF box structure,
#       binary CBOR with COSE_Sign1 in proper containers).
#   (b) Drive c2patool externally via --signer-path with our Ed25519 key + a
#       C2PA-EKU-equipped self-signed cert. Requires cert engineering to add
#       the specific EKU OIDs c2patool's allow-list/trust-anchor flow expects.
#
# This script is a placeholder for the v0.9 work. It prints the current state
# and exits 0 if c2patool is installed (so CI doesn't fail), 0 if it isn't.
set -euo pipefail

echo "== C2PA interop status (v0.8.0) =="
if ! command -v c2patool >/dev/null 2>&1; then
  echo "  c2patool: NOT INSTALLED — skip"
  echo "  install via: cargo install c2patool"
  exit 0
fi
echo "  c2patool: $(c2patool --version 2>&1 | head -1)"

if [ ! -f "samples/synthex-evidence-report.json" ]; then
  echo "  ERROR: samples/synthex-evidence-report.json not found (run from repo root)"
  exit 1
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "  Testing our own emitter + verifier round-trip..."
node bin/synthex.mjs keygen --out="$TMPDIR" >/dev/null
node bin/synthex.mjs c2pa-emit samples/synthex-evidence-report.json \
  --out="$TMPDIR/sidecar.c2pa.json" --key-dir="$TMPDIR" >/dev/null
if node bin/synthex.mjs c2pa-verify "$TMPDIR/sidecar.c2pa.json" \
     --evidence=samples/synthex-evidence-report.json >/dev/null; then
  echo "  own verifier round-trip: OK"
else
  echo "  own verifier round-trip: FAIL"
  exit 1
fi

echo ""
echo "  Testing c2patool acceptance of our sidecar..."
if c2patool "$TMPDIR/sidecar.c2pa.json" 2>/dev/null; then
  echo "  c2patool verify: OK — interop achieved!"
else
  echo "  c2patool verify: NOT YET (expected in v0.8 — see scripts/c2pa-interop-test.sh comments)"
fi
echo "== end =="
exit 0
