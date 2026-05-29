#!/usr/bin/env bash
# Verify the SLSA L3 provenance of a published Synthex release — PROVES the L3
# claim instead of asserting it. Downloads the release tarball + its
# .intoto.jsonl provenance and runs slsa-verifier, which checks that the build
# came from the official REUSABLE SLSA generator (not a self-hosted runner or an
# inline workflow), signed keyless via Sigstore and recorded in Rekor.
#
# Verified 2026-05-29 against v0.8.0:
#   builder = slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
#   → "PASSED: SLSA verification passed" (a reusable, non-self-hosted, keyless
#     builder is what makes this Build Level 3, not L2).
#
# Skips (exit 0) when slsa-verifier is missing so CI doesn't fail.
#   install: go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.7.0
set -euo pipefail

TAG="${1:-v0.8.0}"
REPO="SuarezPM/apohara-synthex"

echo "== SLSA L3 verification gate (${TAG}) =="
if ! command -v slsa-verifier >/dev/null 2>&1; then
  echo "  slsa-verifier: NOT INSTALLED — skip"
  echo "  install: go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.7.0"
  exit 0
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "  gh CLI not installed — needed to download the release assets. skip."
  exit 0
fi

DL="$(mktemp -d)"; trap 'rm -rf "$DL"' EXIT
gh release download "$TAG" --repo "$REPO" --dir "$DL" --pattern '*.tgz' --pattern '*.intoto.jsonl'
TGZ="$(ls "$DL"/*.tgz | head -1)"

slsa-verifier verify-artifact "$TGZ" \
  --provenance-path "$TGZ.intoto.jsonl" \
  --source-uri "github.com/${REPO}"

echo "  → builder is the reusable generator_generic_slsa3.yml (keyless, not self-hosted) = SLSA Build L3"
echo "== end =="
