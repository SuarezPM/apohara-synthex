#!/usr/bin/env bash
# C2PA interop gate (v0.9.0) — PROVES interop with c2patool, doesn't just claim it.
#
# Two checks:
#   1. Own verifier round-trip on the JSON sidecar (no external deps; always runs).
#   2. REAL c2patool interop: render a PNG Evidence Card, embed a C2PA manifest
#      via c2patool, verify it with c2patool, and assert the com.apohara.synthex
#      assertion binds the card to the evidence's contentHash. This is the gate
#      that makes "C2PA interop" an empirical fact instead of a README claim.
#
# The signer is self-signed → c2patool reports the signer as an untrusted source,
# which is EXPECTED and documented (HONESTY §1.6); the manifest itself is Valid.
# Real trust needs a CA in the C2PA trust list (out of scope).
#
# Skips (exit 0) when an optional tool is missing so CI doesn't fail on
# environments without c2patool (Rust binary) or Playwright's Chromium:
#   - c2patool:  cargo install c2patool
#   - chromium:  npx playwright install chromium
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== C2PA interop gate (v0.9.0) =="

# ── 1. own verifier round-trip (sidecar JSON) ──────────────────────────────
TMP1="$(mktemp -d)"; trap 'rm -rf "$TMP1"' EXIT
node bin/synthex.mjs keygen --out="$TMP1" >/dev/null
if [ ! -f "samples/synthex-evidence-report.json" ]; then
  echo "  ERROR: samples/synthex-evidence-report.json not found (run from repo root)"; exit 1
fi
node bin/synthex.mjs c2pa-emit samples/synthex-evidence-report.json \
  --out="$TMP1/sidecar.c2pa.json" --key-dir="$TMP1" >/dev/null
if node bin/synthex.mjs c2pa-verify "$TMP1/sidecar.c2pa.json" \
     --evidence=samples/synthex-evidence-report.json >/dev/null; then
  echo "  [1] own verifier round-trip (sidecar) : OK"
else
  echo "  [1] own verifier round-trip (sidecar) : FAIL"; exit 1
fi

# ── 2. REAL c2patool interop (evidence card PNG) ───────────────────────────
if ! command -v c2patool >/dev/null 2>&1; then
  echo "  [2] c2patool interop : SKIP (c2patool not installed — cargo install c2patool)"
  echo "== end (1 ok, 1 skipped) =="; exit 0
fi
echo "  [2] c2patool: $(c2patool --version 2>&1 | head -1)"

# The card render needs Playwright's Chromium.
if ! node -e 'import("playwright").then(p=>p.chromium.launch({headless:true}).then(b=>b.close())).catch(()=>process.exit(7))' >/dev/null 2>&1; then
  echo "  [2] c2patool interop : SKIP (Chromium not installed — npx playwright install chromium)"
  echo "== end (1 ok, card skipped) =="; exit 0
fi

# Seal an evidence with the SAME key the card is signed with, then emit + verify the card.
SYNTHEX_SIGNING_KEY_FILE="$TMP1/synthex-ed25519.key" \
  node bin/synthex.mjs --demo security >"$TMP1/evidence.json" 2>/dev/null
node bin/synthex.mjs evidence-card "$TMP1/evidence.json" \
  --out="$TMP1/card.png" --key-dir="$TMP1" >/dev/null

# c2patool verdict must be Valid (signer untrusted self-signed, but manifest valid).
STATE="$(c2patool "$TMP1/card.png" 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).validation_state||"")}catch{console.log("")}})')"
if [ "$STATE" = "Valid" ]; then
  echo "  [2] c2patool verify (card)            : OK (validation_state=Valid)"
else
  echo "  [2] c2patool verify (card)            : FAIL (validation_state='$STATE')"; exit 1
fi

# Binding: com.apohara.synthex.contentHash MUST equal evidence.contentHash.
EVHASH="$(node -e "console.log(JSON.parse(require('fs').readFileSync('$TMP1/evidence.json')).contentHash)")"
CARDHASH="$(c2patool "$TMP1/card.png" --detailed 2>/dev/null | grep -oE '[a-f0-9]{64}' | grep -x "$EVHASH" | head -1 || true)"
if [ "$CARDHASH" = "$EVHASH" ]; then
  echo "  [2] binding com.apohara.synthex       : OK (card and evidence share contentHash)"
else
  echo "  [2] binding com.apohara.synthex       : FAIL (card hash != evidence hash)"; exit 1
fi

echo "== end (all checks passed) =="
exit 0
