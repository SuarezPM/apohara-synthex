# Apohara Synthex — Roadmap

> **Honesty (binding):** the "Future work" items below are **NOT shipped, NOT claimed**. Anything
> implemented moves to "Shipped" with a measured claim + lands in code + `docs/HONESTY.md`, and out
> of the future list. Gate-before-trust applies: nothing is built on an unconfirmed external surface.

## Shipped from this roadmap (v1.0.0, items R1–R6)

Each was gate-before-trust verified live, built additively, and is documented in `docs/HONESTY.md`:

- **EPSS exploitation weighting (R1, §10.8)** — opt-in (`SYNTHEX_EPSS_ENABLED`), non-sealed, render-time enrichment of the Security Risk Score from FIRST.org EPSS. Best-effort (CVE ids regex-extracted from finding text). `src/prove/epss.js`.
- **CAWG `cawg.x509.cose` identity assertion (R2, §1.6)** — self-signed, our-verifier-validated org-identity assertion in the C2PA sidecar, bound to the same `c2pa.hash.data` hash. NOT CA-rooted, NOT c2patool-validated in the sidecar path. `src/prove/c2pa.js`.
- **Rekor live-key-compare (R3, §10.7)** — the monitor fetches the live shard checkpoint and verifies it against the pinned key, reporting `status:"rotated"` on drift. DETECTS rotation + points to the TUF fix. `scripts/monitor-rekor-anchors.mjs`.
- **Multi-TSA resilience (R4, §10.9)** — Actalis pinned as a 2nd RFC 3161 TSA anchor alongside DigiCert (resilience). **NOT eIDAS-qualified** (free endpoint, non-qualified policy/CA). `src/prove/tsa-anchors.js`.
- **Cognee cloud backend (R6, §10.5)** — opt-in (`COGNEE_CLOUD=1`) pluggable cloud memory over the tenant REST API (`tenant-<id>.aws.cognee.ai`, `X-Api-Key` + `X-Tenant-Id`); local OSS stays default; CaMeL gate covers both. `src/memory/cognee-client.js`.

## Future work — NOT shipped, NOT claimed

These are gated on a resource we don't have (paid service, capable dataset) or a cross-cutting effort, and are documented honestly rather than faked:

- **eIDAS QUALIFIED timestamps** — the multi-TSA work (R4) added Actalis's FREE TSA for resilience; a QUALIFIED eIDAS timestamp requires the **paid** Actalis qualified service (a different CA + ETSI policy OID), i.e. a contract we don't hold. Pin the qualified CA + assert the ETSI policy when that exists.
- **c2patool-NATIVE CAWG identity** — R2 ships the CAWG assertion in our own sidecar (our-verifier-validated). A c2patool-VALIDATED CAWG identity embedded in the PNG Evidence Card needs c2patool's native `[cawg_x509_signer]` + `--identity-signer-path` flow wired into `evidence-card.js`. Separate, larger.
- **TUF-signed Rekor auto-refresh** — R3 DETECTS rotation; auto-fetching + TRUSTING the new key from Sigstore `trusted_root.json` requires full TUF signature verification = a TUF client = a new dependency (forbidden by zero-new-deps). Until then, re-pinning on rotation is a human step.
- **CAWG Organizational Identity Profile** — the full profile mandates CA-rooted X.509 trust + spec versions; our assertion is self-signed/untrusted. Requires a CA-issued org cert.
- **Shared `aegis` seal layer** — lifting the seal/verify core into the cross-product **Apohara Aegis** layer. DEFERRED: aegis is a **Python** project (`apohara-aegis/`, `pyproject.toml`) while Synthex is JS — a shared seal would need a cross-language shared spec or a native module, a multi-day architectural effort, not an additive feature. Tracked, not started.
- **Bright Data `discover_new` collector** — the async `trigger→poll→collect` adapter ships (item 2.7), but a true `discover_new` discovery collector requires a discovery-capable `dataset_id`; the available dataset (`gd_m6gjtfmeh43we6cqc`) is a crawl dataset that does not expose it. Wiring Scene-3 watchlist→discover_new→delta is gated on such a dataset.
- **LangChain/CrewAI deeper integration** — the framework-shaped tool wrappers ship (item 3.3); deeper native integrations (memory, callbacks) are future.
