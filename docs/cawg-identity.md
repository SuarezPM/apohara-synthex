# CAWG Organizational Identity on the C2PA Evidence Card

> **What this doc is.** A precise statement of what the c2patool-NATIVE CAWG x509 identity
> assertion on the Evidence Card proves — and, just as precisely, what it does NOT prove.
> **What this doc is NOT.** A claim of trusted, CA-rooted, or DIF-anchored organizational
> identity. The signer is self-signed and c2patool reports it `untrusted`. That caveat is
> the whole point and is never dropped.

This is the source of truth for the **P3.4** capability. It pairs with `docs/HONESTY.md §1.6`
(the binding honesty contract) and the emitter `scripts/emit-cawg-card.mjs`.

---

## TL;DR

`scripts/emit-cawg-card.mjs` emits a C2PA Evidence Card PNG whose manifest carries a
`cawg.identity` assertion produced by **c2patool's native `[cawg_x509_signer]` flow**
(c2patool 0.26.60 / c2pa-rs 0.85). c2patool then **validates** that assertion as
`cawg.identity.well-formed` ("CAWG X.509 identity signature valid").

- **Proves:** the CAWG identity-assertion **SHAPE**, validated by the standard tool itself.
- **Does NOT prove:** trusted / CA-rooted / DIF-anchored organizational identity. The signer
  is the same **self-signed** Ed25519 cert `synthex keygen` produces, so c2patool ALSO emits
  `signingCredential.untrusted` ("signing certificate untrusted").

---

## What's new vs. the existing sidecar

There are now two CAWG paths in the repo, and they are disjoint by design:

| | `src/prove/c2pa.js` (sidecar) | `scripts/emit-cawg-card.mjs` (P3.4) |
|---|---|---|
| Carrier | JSON sidecar (`synthex-c2pa-sidecar-v1`) | **PNG Evidence Card** (real C2PA/JUMBF) |
| CAWG assertion | hand-rolled `cawg.identity` COSE_Sign1 | **c2patool-native** `[cawg_x509_signer]` |
| Validated by | our own `verifyC2paManifest` only | **c2patool** (`cawg.identity.well-formed`) |
| Signer | self-signed Ed25519 | self-signed Ed25519 (same shape) |
| Trust | UNTRUSTED | UNTRUSTED (`signingCredential.untrusted`) |

The sidecar was honest that its CAWG assertion was *"structurally spec-shaped, verified by our
own verifier only … NOT validated by c2patool"* (HONESTY §1.6). P3.4 closes exactly that gap:
the assertion is now validated by **c2patool itself** — but trust is still UNTRUSTED, because
the credential is still self-signed.

---

## How it works (the native dual-signer)

c2patool runs a **dual signer** when a `[cawg_x509_signer.local]` section is present in the
settings file alongside the manifest's claim signer:

1. **Main claim signature** comes from the manifest's `private_key` / `sign_cert` (the existing
   card flow — Ed25519, self-signed).
2. **The `cawg.identity` assertion** is added and signed by the `[cawg_x509_signer.local]`
   signer (the same self-signed Ed25519 cert, `alg = "ed25519"`).

The CAWG signer's `referenced_assertions = ["com.apohara.synthex"]` binds the org-identity
claim to our evidence-binding assertion, so the identity does not float free of the evidence.

Settings shape (`alg`, `sign_cert`, `private_key`, `referenced_assertions` — schema per
[c2patool CAWG x509 docs](https://opensource.contentauthenticity.org/docs/c2patool/docs/cawg_x509_signing/)):

```toml
version = 1

[cawg_x509_signer.local]
alg = "ed25519"
referenced_assertions = ["com.apohara.synthex"]
sign_cert = """-----BEGIN CERTIFICATE-----
…(self-signed Ed25519 end-entity cert)…
-----END CERTIFICATE-----"""
private_key = """-----BEGIN PRIVATE KEY-----
…(pkcs8 Ed25519)…
-----END PRIVATE KEY-----"""
```

Emit invocation:

```
c2patool --settings settings.toml card.png -m manifest.json -o cawg-card.png -f
```

---

## What c2patool reports (measured, not narrated)

Running the emitter against a freshly-emitted card (`c2patool <card> --detailed`) yields:

| Validation result | Meaning |
|---|---|
| `validation_state: Valid` | the manifest is structurally sound |
| `cawg.identity.well-formed` (success) | **"CAWG X.509 identity signature valid"** — the SHAPE is validated by c2patool |
| `assertion.hashedURI.match` (success) | the `cawg.identity` assertion is correctly hash-bound into the claim |
| `signingCredential.untrusted` (failure ×2) | **"signing certificate untrusted"** — for BOTH the claim signer and the CAWG x509 signer; self-signed, NOT CA-rooted |
| `com.apohara.synthex.contentHash == evidence.contentHash` | the card binds to the exact sealed evidence |

`validation_state` stays `Valid` even though `signingCredential.untrusted` appears, because in
c2pa-rs a self-signed credential produces a well-formed-but-untrusted result, not an invalid
manifest. The emitter's honest success criteria require **all four** of: `Valid`,
`cawg.identity.well-formed`, `signingCredential.untrusted`, and the binding-hash match — so a
run that somehow became "trusted" (e.g. a misconfigured CA anchor) would FAIL the gate, not
silently pass. We assert the *self-signed* posture, not just the absence of errors.

---

## What this does NOT prove (the hard limits)

- **NOT trusted / CA-rooted.** The cert is self-signed. Real trust requires a cert from a CA in
  the C2PA trust list (out of scope). c2patool's `signingCredential.untrusted` is the correct,
  expected verdict and we keep it.
- **NOT the CAWG Organizational Identity Profile.** The CAWG **Organizational Identity Profile**
  was **DIF-ratified on 05 Feb 2026** and requires **C2PA 2.2/2.3** trust anchoring to mean
  "this organization is who it says it is." What we ship is the CAWG **X.509 identity-assertion
  SHAPE** (`cawg.x509.cose`), c2patool-validated — not the anchored Organizational Identity
  Profile.
- **NOT third-party-anchored identity.** No DID resolution, no identity-claims-aggregation
  credential, no external verifier vouches for the org. The assertion states **WHO claims** the
  organizational identity (self-attested), not that anyone independent vouches for it.
- **NOT a replacement for the seal.** The load-bearing guarantee remains the Evidence Report
  PDF seal (HMAC-SHA256 + Ed25519 + RFC 3161 TSA). The card + CAWG assertion are the standard
  Content-Credentials / organizational-identity *shape* on top, bound to the same `contentHash`.

The honest one-liner: **everything signed, nothing trusted** — the CAWG identity-assertion
shape is now validated by the standard tool, but the signer is still self-signed, so the
*identity* is asserted, not anchored.

---

## Running it

```bash
# Full path needs c2patool + Playwright's Chromium:
#   cargo install c2patool
#   npx playwright install chromium
node scripts/emit-cawg-card.mjs --out=out/cawg-evidence-card.png

# If c2patool or Chromium is absent, the script SKIPs (exit 0) — like
# scripts/c2pa-interop-test.sh — so CI never fails on a missing optional tool.
```

The script generates an ephemeral self-signed Ed25519 keypair, seals a demo evidence with the
SAME key, renders the card, emits with the native CAWG x509 signer, and **dry-verifies** the
result with c2patool (asserting the four criteria above) before reporting PASS.

---

## References

- c2patool CAWG x509 signing: <https://opensource.contentauthenticity.org/docs/c2patool/docs/cawg_x509_signing/>
- `c2pa::settings` (`cawg_x509_signer` / `SignerSettings`): <https://docs.rs/c2pa/latest/c2pa/struct.Settings.html>
- HONESTY §1.6 — the binding self-signed/UNTRUSTED contract for C2PA + CAWG
- `scripts/emit-cawg-card.mjs` — the emitter + dry-verify gate
- `src/prove/c2pa.js` — the disjoint JSON sidecar (own-verifier-only) CAWG path
