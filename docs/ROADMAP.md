# Apohara Synthex — Roadmap (post-v1.0.0 future work)

> **Honesty (binding):** everything in this file is **future work — NOT shipped, NOT claimed**.
> It is documented so the v1.0.0 surface stays honest about where the seal could go next. If a
> capability here is ever implemented, it moves into the code + `docs/HONESTY.md` with a measured
> claim, and out of this file. Nothing below should be read as a current feature.

## Provenance & identity (extending the seal)

- **CAWG Organizational Identity** (`cawg.x509.cose`) — the [Creator Assertions Working Group](https://cawg.io)
  identity assertion would let the Evidence Card carry an **organization-level** identity assertion
  (X.509 over COSE) alongside the existing Ed25519 keyId, so a verifier sees "issued by org X"
  rather than only "signed by this anonymous key". Today identity is the publishable keyId
  (DNS/`.well-known`) — CAWG would add a standardized org-identity layer to the C2PA manifest.
- **eIDAS qualified timestamps (QTSP)** — the current RFC 3161 timestamp is from **DigiCert**
  (a commercial TSA), which proves time-of-existence but is **not** an EU **qualified** electronic
  timestamp. Adding a QTSP such as **Actalis** (an eIDAS-listed trust service provider) would make
  the timestamp qualified under eIDAS (Regulation (EU) 910/2014), raising its legal weight in the
  EU. This is additive: the seal already supports multiple timestamp anchors.
- **Shared `aegis` seal layer** — lifting the seal/verify core into the shared **Apohara Aegis**
  layer (a cross-product crypto/attestation library) so Synthex and sibling products share one
  audited implementation of Ed25519 + RFC 3161 + C2PA + Rekor, instead of each re-implementing it.

## Coverage & resilience (already partially scaffolded)

- **Rekor v2 shard-rotation auto-refresh** — `scripts/monitor-rekor-anchors.mjs` (v1.0.0, item 3.1)
  *detects* pinned-key drift; a future step is to **auto-fetch** the new shard key from Sigstore's
  TUF `trusted_root.json` and open a PR to refresh `src/prove/rekor-anchors.js` (TUF-fetch fallback).
- **EPSS exploitation weighting** — fold FIRST.org EPSS scores into the security-lens Risk Score
  (named in `docs/compliance-mapping.md` as a future input; the severity axis is already CVSS-scaled).
- **Bright Data `discover_new` collector** — the async `trigger→poll→collect` adapter ships in
  v1.0.0 (item 2.7), but a true `discover_new` discovery collector requires a discovery-capable
  `dataset_id`; wiring Scene-3 watchlist→discover_new→delta is gated on that dataset.

## Distribution

- **Cognee cloud backend** — local OSS is the default + only backend in v1.0.0 (item 2.3); a cloud
  backend is gated on a confirmed programmatic Cognee SaaS API (the platform key currently exposes
  the dashboard, not an ingest API — see `docs/HONESTY.md` §10.5).
