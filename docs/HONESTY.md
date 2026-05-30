# Honesty — Apohara Synthex

> **Single source of truth for "what we don't claim."** If this file says one thing and the README or pitch deck says another, this file wins. The "Honesty" anchor in [README.md](../README.md#-honesty) and `SLIDES.md §12` both link here.

The product pitches *verifiable honesty over polished claims*. That rule applies to us too: any caveat that materially shapes how a user should read a Synthex evidence report belongs here, with an inline pointer to the code path that enforces it.

---

## §1 · Cryptographic seal — what it does and doesn't prove

### 1.1 RFC 3161 TSA · what `tsaSignatureValid:true` means (M1 v0.7.0 · validity hardened v0.8 commit 1)
> **v0.8 rename** — what v0.7 reported as `signatureValid` (the TSA CMS chain verdict) is now reported as `tsaSignatureValid` / `tsaSignatureValidReason`. The `signatureValid` key now carries the Ed25519 asymmetric verdict introduced in v0.8 (see §1.4). Same checks, distinct fields.

- **What the verifier now checks** (`src/prove/tsa.js verifyTimestamp` + `verifyCmsSigned`):
  1. `status: granted` on the `TimeStampResp`.
  2. `messageImprint` inside the token equals our `SHA-256(contentHash)`.
  3. The CMS `messageDigest` signed attribute equals `SHA-256(TSTInfo bytes)`.
  4. The CMS signature math verifies against the signer cert's public key (RSA-PKCS1-v1_5).
  5. **v0.8** — the signer cert carries the `id-kp-timeStamping` Extended Key Usage (OID 1.3.6.1.5.5.7.3.8 — RFC 3161 §2.3 requirement).
  6. **v0.8** — every cert in the chain has `notBefore ≤ genTime ≤ notAfter`. The check is anchored at `tstInfo.genTime`, **not** `Date.now()`, so tokens stay verifiable forever as of when they were stamped (even if the signer cert eventually expires).
  7. The certificate chain (signer → intermediate → root) terminates at one of the two pinned DigiCert anchors in `src/prove/tsa-anchors.js`, verified link-by-link by issuer DN + signature.
- **What it does NOT prove**:
  - Not OCSP / CRL revocation — we don't go online to ask DigiCert "is this responder still trusted today?"; we only check that the responder cert was issued by our pinned anchors. (v0.8 Commit 3 adds opt-in OCSP — see §1.5.)
  - Not the *truth* of the sealed content — only that the bytes existed at `genTime` and have not been altered.
  - Not a court ruling — "court-grade" tone in marketing copy was a 2026-05-29 audit finding and was reworded across README/SLIDES to "timestamped, third-party-verifiable evidence". Admissibility depends on jurisdiction and dispute.
- **Failure modes operators must distinguish** (returned as `tsaSignatureValidReason`):
  - `"forged"` — the signature math fails. The token was edited or the responder cert is wrong.
  - `"untrusted-anchor"` — the math passes but the chain doesn't reach our pinned anchors. **Most common cause: DigiCert rotated the TSA CA and our pin is stale.** A genuine fresh token shows this; it is NOT a forgery alert. The anchor-rotation runbook (Follow-up F4) is the response.
  - `"chain-incomplete"` — the signer cert isn't in the CMS or the chain can't be walked.
  - **v0.8** `"cert-missing-eku"` — the signer cert lacks `id-kp-timeStamping`. RFC 3161 §2.3 violation; not a forgery, an issuer-policy break.
  - **v0.8** `"gentime-outside-validity"` — the TSTInfo `genTime` is outside the signer cert's `notBefore` / `notAfter` window. A token signed by a cert that wasn't valid at that instant.
  - **v0.8** `"cert-expired"` / `"cert-not-yet-valid"` — same idea for an intermediate or root cert in the chain at the time of stamping.
  - `null` — there is no TSA token in this evidence (HMAC-only seal); we never called `.verify()`. NOT a failure.
- **The HMAC-only fallback is honest by design**: if the TSA call fails at seal time, `rfc3161Tsa` is `null` and the evidence is sealed with HMAC-SHA256 alone (plus Ed25519 if a signing key is configured). The seal `method` string composes from the layers present (`"HMAC-SHA256"`, `"HMAC-SHA256 + Ed25519"`, `"HMAC-SHA256 + RFC 3161 TSA"`, `"HMAC-SHA256 + Ed25519 + RFC 3161 TSA"`). v0.5 / v0.6 / v0.7 evidence files still verify under v0.8 — `tsaSignatureValid` short-circuits to `null` when there's no TSA token, and `signatureValid` reports `'symmetric-only'` (explainer string, not failure) when there's no Ed25519 layer.

### 1.4 Asymmetric signature · what `signatureValid:true` means (v0.8 Commit 2 — Ed25519)
**This is the load-bearing fix for the 2026-05-29 audit finding that HMAC-SHA256 is symmetric → no non-repudiation.** Anyone with `SYNTHEX_HMAC_KEY` could forge any report. v0.8 adds an additive `seal.signature` block: an Ed25519 signature over the same canonical bytes the HMAC signs, with the public key embedded for offline verification.

- **What `signatureValid:true` proves**: the holder of the private half of the embedded public key signed these exact canonical bytes. Anyone with the public key verifies; **only** the private-key holder can sign. That's non-repudiation **relative to the embedded key**.
- **What it does NOT prove without out-of-band publication — the binding identity-vs-key gap**: embedding the public key in the report is *circular*. The report attests its own key. Anyone can generate a keypair, sign their own report, and embed the matching pubkey — Ed25519 math will verify. For a third party to know **WHO** signed (not just **THAT** someone with a specific key signed), the keyId must be published through a channel the verifier trusts independently of the report:
  - **DNS TXT record** — `_synthex-keyid.<domain>` (recommended; signed by the DNS operator's TLS / DNSSEC; visible to anyone resolving the domain).
  - **`.well-known` JSON** — `https://<domain>/.well-known/synthex-keys.json` (signed by the domain's TLS cert; standard discovery convention).
  - **Transparency log — Sigstore Rekor v2 (v0.9.0, shipped)**: `npx synthex rekor-anchor` records the keyId ONCE in Sigstore's Rekor v2 log as a DSSE in-toto statement signed by the seal key (`synthex-rekor-anchor.json` holds the inclusion proof + checkpoint; `npx synthex rekor-verify` checks it fully offline — DSSE sig + Merkle inclusion proof RFC 6962 + checkpoint Ed25519 signature against the TUF-pinned log key in `src/prove/rekor-anchors.js`). **Honest framing:** Rekor gives a public, append-only, *monitorable* record of the keyId. It does NOT add a new timestamp (the RFC 3161 TSA already does that) and it does NOT add identity (a bare key is anonymous; real identity is still OIDC + Fulcio, an interactive opt-in outside the automatic seal). Rekor *upgrades the existence proof* from a single TSA to a publicly auditable log — a stronger publication channel for the keyId, not a new capability. Anchor the keyId ONCE, never per-evidence (per-evidence would be redundant with the TSA, add network to every seal, and break deterministic offline sealing). Rekor v2 only (v1 is frozen); `hashedrekord` rejects Ed25519 so the anchor uses the DSSE entry type. The pinned log key must be refreshed when Sigstore shards the log (~every 6 months) — operational follow-up, like the F4 TSA-anchor monitor.
  - **v1.0.0 (D6) — the in-toto subject digest is now a real digest**: `subject[0].digest.sha256` is the **full SHA-256 of the SPKI DER**, not `keyId.padEnd(64,"0")` (a fabricated digest the v0.9 code shipped). `verifyRekorBundle` now **actively verifies** it (`checks.subjectDigest`; mismatch → `{ok:false, reason:"subject-digest-mismatch"}`), and the test fixture was **re-anchored against real Rekor v2** (logIndex 4729698), not asserted-around. The old fabricated-digest fixture now fails the active check — proving the check is load-bearing, not decorative. // ES: el subject digest pasó de keyId padeado a SHA-256 real del SPKI, ahora verificado activamente, fixture re-anclado de verdad.
  - The verifier pins via `--expected-keyid=<hex>` (or `SYNTHEX_EXPECTED_KEYID`); the comparison happens against the embedded `seal.signature.keyId` and surfaces as `identityVerified: true|false`. Without `--expected-keyid`, the verifier returns `identityVerified: null` — signature math is good, identity is **not** pinned. This distinction is contractual.
  - `npx synthex publish-keyid --domain=<your-domain>` prints both publication formats for the operator to copy-paste. Run it once after `npx synthex keygen`.
- **Persistent default · NO ephemeral, NO auto-generation** (per reviewer A1):
  - The signing key is resolved in this order: `SYNTHEX_SIGNING_KEY` (env inline) → `SYNTHEX_SIGNING_KEY_FILE` (env path) → `~/.config/apohara/synthex/synthex-ed25519.key` (XDG default; `XDG_CONFIG_HOME` aware) → unsigned.
  - Ephemeral-per-run was rejected because (a) it's demo theatre — "some random key signed this" is not what a General Counsel wants to read; (b) it breaks `delta_chain` continuity (the chain's whole point is that the *same custodian* signed every link from `previous_tsa_serial → current_tsa_serial`; rotating keys per snapshot makes the chain structurally valid but custodially meaningless). The operator must explicitly opt in to signing by running `npx synthex keygen` and persisting the key.
- **Tri-modal `signatureValid` value**:
  - `true` — Ed25519 verify passed.
  - `false` — verify failed; `signatureValidReason` carries one of: `"bad-signature"` (math fail = tamper alarm), `"malformed-signature"` (block decode failed, or `keyId` mismatches the embedded SPKI), `"key-mismatch"` (caller supplied `--expected-keyid` and it didn't match).
  - `"symmetric-only"` — no `seal.signature` block present (v1 / v2 fixtures + v3 without a signing key). **NOT a failure** — it's an explainer string: the report's integrity rests on HMAC + (if present) TSA, but no asymmetric layer was produced. Distinct from `false` which means "we ran an asymmetric check and it FAILED".
  - `null` — malformed evidence (shape-guard path).
- **`delta_chain` continuity caveat**: when a chain spans multiple snapshots, the verifier flags rotation in the future via the same `keyId` field — if two consecutive snapshots in a delta chain have different `seal.signature.keyId`, the custodian rotated. The chain is structurally still valid (each snapshot signs its own bytes), but custodial continuity is interpretive: a human reviewer should decide whether the rotation was authorized.
- **Why "Ed25519 over canonical bytes" is what we ship and not something else**: the canonical pre-image is the same `_serializeForHmac(payload)` string the HMAC signs. Byte-identity is the equivalence argument with C2PA `c2pa.hash.data` + claim signature (Commit 3 builds the C2PA sidecar on top of this exact same signature material). Single source of truth for "what got signed" across all layers.

### 1.5 Revocation (OCSP) — opt-in, surfacing-only (v0.8 Commit 3)
- **Default off, ZERO network**: `revocationChecked: false`, `revocationStatus: null`. The verifier behaves identically to v0.7 unless an operator explicitly opts in. This preserves the offline-verify guarantee that's load-bearing for archive scenarios where the TSA's OCSP responder may not exist forever.
- **Opt-in via `--check-revocation`** (CLI) or `checkRevocation: true` (programmatic): the verifier parses the TSA signer cert's Authority Information Access (AIA) extension, extracts the `id-ad-ocsp` URL, builds an `OCSPRequest` with a SHA-1 `CertID` (per RFC 6960 §4.1.1), POSTs it, decodes the `BasicOCSPResponse`, and returns `revocationStatus: "good" | "revoked" | "unknown"`.
- **Fail-open contract**: ANY failure path (no AIA, network down, non-200 HTTP, parse error, non-success `responseStatus`, missing `singleResponse`) returns `{status:'unknown', reason:<short-token>}` — NEVER throws. A valid offline verify never becomes a hard fail because OCSP went down.
- **v0.8 policy — surfacing-only, NOT auto-fail**: `revocationStatus: "revoked"` does NOT flip `tsaSignatureValid:false`. The operator decides what a revoked timestamp means for their threat model (a revoked TSA cert may still produce verifiable historical timestamps in archive contexts). "Strict revoked = hard-fail flag" is a v0.9 knob.
- **Zero new dependencies**: hand-rolled on the existing `pkijs` (`src/prove/ocsp.js`). Same dep discipline as the v0.7 custom CMS verifier in `tsa.js`. The pkijs `OCSPRequest` / `OCSPResponse` / `BasicOCSPResponse` classes were already imported transitively; we just expose them at the right layer.
- **Implementation**: `src/prove/ocsp.js extractOcspUrl` + `checkRevocation`. Wired through `src/prove/tsa.js verifyTimestamp(opts.checkRevocation)` and `src/prove/evidence-report.js verifyEvidence(opts.checkRevocation)`. Tests in [`test/prove/ocsp.test.js`](../test/prove/ocsp.test.js) cover the full fail-open contract.

### 1.6 C2PA — real c2patool interop via the Evidence Card (v0.9.0)
- **What changed in v0.9.0**: C2PA interop is now REAL, not narrative. `synthex evidence-card <evidence.json>` renders a PNG Evidence Card and embeds a genuine C2PA manifest **that c2patool verifies as `validation_state: Valid`**. The v0.8 "c2patool verify not yet" gap is closed. The two v0.8 obstacles were diagnosed empirically against the c2pa-rs 0.85 source and fixed:
  1. **Container** — c2pa-rs cannot WRITE PDF (`asset_handlers/pdf_io.rs` is read-only: `save_cai_store → NotImplemented`). So the C2PA container is a **PNG card**, not the PDF. The Evidence Report PDF keeps the load-bearing seal (HMAC + Ed25519 + RFC 3161 TSA); the card carries the Content Credential. PNG embedding is fully supported by c2patool.
  2. **Certificate** — c2pa-rs's `check_certificate_profile` requires the end-entity (CA:FALSE) cert to carry an allow-listed **EKU `id-kp-documentSigning` (1.3.6.1.5.5.7.3.36, RFC 9336)** PLUS an **AuthorityKeyIdentifier** and a KeyUsage of digitalSignature. The v0.8 cert had only KeyUsage + BasicConstraints, so c2patool rejected it as "the certificate is invalid". `buildSelfSignedEd25519Cert` now emits EKU + AKI + SKI. No mini-PKI is needed: c2pa-rs's self-signed check only rejects self-signed **CA** certs, and our end-entity is CA:FALSE.
- **Algorithm**: Ed25519 was never the blocker — c2pa-rs supports EdDSA natively (`Ed25519Signer`). The seal stays Ed25519; no ES256 second key.
- **The binding is the point (non-negotiable)**: the card's C2PA manifest carries a custom `com.apohara.synthex` assertion with the evidence `contentHash` + the seal `keyId`, and the card is signed with the **same** Ed25519 key that sealed the evidence. So the card cert keyId, the seal keyId, and the assertion keyId all coincide, and **the card and the PDF attest the same `contentHash`**. Without that binding the Content Credential would float free of the evidence it certifies. Enforced by `scripts/c2pa-interop-test.sh`.
- **Trust is honest**: the signer is **self-signed**, so c2patool reports `signingCredential.untrusted` ("signing certificate untrusted") — EXPECTED. The manifest is cryptographically valid; the *signer identity* is not CA-rooted. Real trust requires a cert from a CA in the C2PA trust list, which is out of scope. C2PA here proves integrity + provenance shape, NOT third-party-anchored identity. Signer identity is closed separately via the Ed25519 keyId published out-of-band (§1.4), with Sigstore/Rekor as the v0.9+ transparency-log path.
- **The own sidecar still ships**: `synthex c2pa-emit` / `c2pa-verify` (JSON sidecar + own COSE verifier, 11/11 in [`test/prove/c2pa.test.js`](../test/prove/c2pa.test.js)) remain for offline inspection without c2patool. The PNG card is the path for standard-tool interop (c2patool, contentcredentials.org).
- **CI proves it, doesn't claim it**: [`scripts/c2pa-interop-test.sh`](../scripts/c2pa-interop-test.sh) renders a card, has c2patool verify it (`validation_state=Valid`), and asserts `com.apohara.synthex.contentHash == evidence.contentHash`. It SKIPs (not fails) when c2patool or Chromium is absent.

### 1.2 Model confidence is NOT part of the seal (AI-2)
- The cryptographic seal proves the *evidence bytes existed*; it does not say anything about the classifier's confidence. Classifier output (severity, summary, signals) is advisory — the PDF disclaimers in `src/prove/pdf-report.js` state this on the rendered page.
- No ensemble / cross-model agreement scoring ships in OSS. Tier-level confidence is conveyed by the tier labels `flash` (default/bulk) and `pro` (spot/council/L3) — both `deepseek/deepseek-v4-*` (v1.0.0). The v0.6 `free`/`oss`/`paid` labels and the `free-low-quality` flag were retired when Nemotron was removed (item 1.4). // ES: confianza por etiqueta de tier; el flag de baja-calidad del free tier se retiró al eliminar Nemotron.

### 1.3 PDF rendering responsibilities (AI-5)
- Evidence JSON carries the raw model text (truncated only on the LLM *input*, never on the sealed bytes — see §3 below).
- Synthex itself renders to PDF via `PDFKit`, which has no JS context (no XSS surface in the PDF).
- The web UI escapes via `escapeHtml` before injecting model text.
- **We do NOT strip / sanitize text before signing.** Doing so would invalidate the cryptographic seal because the verifier would re-hash a different byte stream than the LLM produced. Downstream renderers that interpret the JSON as HTML (custom integrations) MUST escape.

---

## §2 · Network and abuse posture

### 2.1 SSRF guard scope (H1)
- `src/guard.js assertSafeTarget` blocks RFC1918 + loopback + link-local literal hostnames and their obfuscated / IPv6 / decimal-encoded forms. The egress path is Bright Data's remote proxy, so there is no `169.254.169.254` instance-metadata endpoint reachable from our process; the comment at `src/guard.js:6-10` already documents this.

**Threat-model explainer — why we do NOT resolve DNS in the guard.** A "DNS rebinding" attack would be: an attacker registers `attacker.example`, points it at a public IP during the SSRF block check, then re-points it at a private IP between the check and the fetch. Most SSRF-hardened guards mitigate this by resolving the hostname themselves and re-checking the resolved IP. We intentionally do not, and the reason is not laziness — it's the deployment topology:

1. **The scrape does not run on the Vercel function's network.** The Vercel function calls Bright Data's REST API (`api.brightdata.com` over HTTPS). Bright Data then performs the actual scrape from its own remote proxy network. The function never opens a TCP socket to the user-supplied target.
2. **Bright Data's proxy network is the actual egress.** A DNS rebind that flips to `127.0.0.1` would resolve, at fetch time, **on Bright Data's residential / data-center proxy**, not on our function. `127.0.0.1` on a Bright Data proxy node is *their* loopback, not *ours*. There is no metadata endpoint of ours to reach, no internal service of ours to call, no AWS IMDSv2 secret to exfiltrate from our function's perspective.
3. **The same rebind on a self-hosted node fetch would be exploitable.** If a future contributor wires a direct `fetch(target)` from the function (no Bright Data hop), that path **must** add DNS resolution + re-check. Today no such code path exists. The grep gate: `grep -rn "fetch(target" api/ src/` should return no direct fetches of user-supplied URLs. The only `fetch()` calls in `api/` are to `api.brightdata.com` and `api.aimlapi.com`.
4. **What a sync `dns.lookup()` in the guard would cost.** Resolving DNS in `assertSafeTarget` would either (a) block the event loop on the sync variant — unacceptable for a serverless function under concurrent requests — or (b) make the guard async and force every caller (`api/analyze.js`, `api/stream.js`, `api/report.js`) to await it, threading a 20–80 ms latency into the cold-path of every public request. Both trades are worse than the current zero-real-risk posture.
5. **What changes the threat model.** If Synthex ever ships a direct-fetch surface (e.g., a "Save the raw scraped HTML to our blob store" feature that hits the target without Bright Data in the middle), the threat model changes and DNS resolution becomes mandatory. That delta is tracked as [Follow-up F1 in the v0.7.0 PRD](../.omc/plans/synthex-v0.7.0-security-roadmap.md) and would be the first ticket of that release.

The honest summary: the guard's hostname check is *defense-in-depth* against literal abuse (people typing `http://169.254.169.254` into the playground); DNS rebinding cannot reach us because we are not the network that performs the fetch.

### 2.2 Public rate limit is best-effort (H3)
- The live endpoint rate limit is **in-memory, per warm Vercel instance** (see `src/guard.js:2-4`). With multiple warm instances, the effective limit is the per-instance cap × instance count. **The hard backstop is the Bright Data credit quota** — we cannot scrape past the budget regardless of how the limiter behaves.
- This is a deliberate design choice for an OSS demo; a durable multi-instance limiter (Upstash / KV) is Follow-up F2, gated on observed abuse.

### 2.3 stdio MCP server (L3)
- `server.js` is a stdio FastMCP subprocess invoked by Kiro / Claude Code, not an HTTP listener. There is no request-timeout middleware because there are no incoming HTTP requests. Long-running pipeline calls rely on the platform cap (`api/*` use Vercel's `maxDuration:60`).

---

## §3 · PII and data scope

### 3.1 Where the 25-rule PII filter actually runs (M2)
- The marketing claim of "3 layers of pre-LLM defense (78 DJL + 32 prefilter + 25 PII)" describes the *available* layers, **not** the layers active on every request. The realities:
  - The main `runPipeline` path applies **2 layers**: DJL (`src/forge/djl.js`, 78 rules — prompt-level harm/PII/jailbreak) + prefilter (`src/forge/prefilter.js`, 32 rules — web-injection / Spanish-voseo PI / SSRF / proto-pollution / MCP tool-poisoning).
  - The **25-rule PII gate** (`src/forge/pii-filter.js`) runs on the **monitor / stress / KG-ingest path** only — the place where we forward to Cognee. It is by design scoped there, not in the main `runPipeline`.
- We do not claim GDPR compliance. The PII gate reduces obvious leak surface during KG ingest; it is not a substitute for downstream data handling.

### 3.2 Truncation flag is emit-metadata, never attested (M3, v0.7.0 T4)
- The classifier truncates its **LLM input** at `src/classify/aiml-client.js:61`. The raw `text` in the sealed payload is unchanged.
- v0.7.0 adds `truncated` + `charsSeen` to the classify return as emit-metadata. These keys are listed in `HMAC_EXCLUDED_KEYS` in `src/prove/evidence-report.js`, so they are stripped from the canonical bytes before HMAC. **A run with and without the same content produces the same `contentHash`** (regression test in [`test/prove/hmac-excluded-keys.test.js`](../test/prove/hmac-excluded-keys.test.js)).

---

## §4 · Risk Score and tri-lens semantics (M5)

- The PDF Risk Score is an **internal heuristic estimate**, not an industry benchmark. The formula and its inputs are printed on the same PDF page that displays the number.
- The score renders on the **Broker page** of the report (`pdf-report.js pageBroker`), not the CISO page. README and SLIDES list four buyer personas under the score; the placement of the rendered number is Broker.
- A "lens-bleed" appearance can occur only on `lens=all` runs (security findings can pull the score up when the user requested an all-lens snapshot); the on-page disclaimer says so. A future security-lens-only variant (Follow-up F5) is opt-in.

---

## §5 · Durability and I/O (M7)

- `src/memory/store.js` writes ring-buffer snapshots synchronously by design. **Durable-by-default**: if the process crashes immediately after a write, the snapshot is already on disk.
- We deliberately do **not** debounce or defer writes; a write-coalescing change could drop the last sealed evidence on crash, which would break the chain we sell. The PRD records this rejection (v0.7.0 §3 "Must NOT Have").

---

## §6 · What we don't claim (parity with `SLIDES.md §12`)

- We don't bypass any Terms of Service — we use Bright Data's compliant infrastructure.
- v0.5 verified 6 Bright Data surfaces live; v0.6 stress exercised 2 (Web Unlocker + SERP) over 500 URLs (src: `out/stress-500-2026-05-28/report.json`).
- The 3 pre-LLM layers are **heuristic regex deterministic** (inspired by adversarial-resilient guard patterns referenced in SkillFortify, arXiv 2603.00195; the paper itself argues *against* purely heuristic approaches in favor of formal methods — we use the paper for its threat taxonomy, not as endorsement of regex) — **not** a formal proof.
- "78/78 fixtures pass identically" for DJL means measured coverage on 156 curated positive+negative pairs, NOT every possible adversarial input.
- v0.6 FREE tier (`nvidia/nemotron-nano-9b-v2`) was labeled `free-low-quality` because 50% of fixtures had Δseverity > 1.5 vs DeepSeek (src: [`docs/v060-calibration.md`](v060-calibration.md)). **Removed in v1.0.0 (item 1.4):** Nemotron is no longer in the tier map; the classifier now runs `deepseek/deepseek-v4-flash` (default/bulk) and `deepseek/deepseek-v4-pro` (spot/council/L3), both smoke-tested live via `scripts/probe-aiml-models.mjs`.
- The Delta Engine combines scrape + diff + HMAC + RFC 3161 + KG — a directed search at 2026-05-28 found no open-source combination of the five, but we make no "first in world" claim (see [`docs/PRIOR_ART.md`](PRIOR_ART.md) for reproducible queries).
- **INV-15 is prior-art, not a shipped feature (v1.0.0 hygiene)** — `computeJcrRisk` / `shouldUseDensePrefill` (the INV-15 KV-cache gate) had **0 callers** in `src/` and was moved to `experimental/` in v1.0.0. Synthex has no KV-cache surface for it to protect, so it is kept as reproducible prior-art only (see [`experimental/README.md`](../experimental/README.md)). // ES: INV-15 es prior-art sin cablear; movido a experimental/, fuera del forge de producción.

---

## §7 · Where to find the proof

- **Verifier (CMS chain)**: `src/prove/tsa.js verifyTimestamp` — custom CMS verify path (we don't use `pkijs.SignedData.verify()` because of an upstream bug with constructed OCTET STRING `eContent`; see file header).
- **Pinned anchors**: `src/prove/tsa-anchors.js` — both PEMs were extracted from the embedded chain inside `samples/synthex-evidence-report.json`; the file's load-time guard refuses to start if a PEM was edited without updating its fingerprint.
- **Acceptance tests**: [`test/prove/tsa-cms-verify.test.js`](../test/prove/tsa-cms-verify.test.js) covers AC1 (positive), AC2a (untrusted-anchor), AC2b (forged), AC4 (HMAC-only short-circuit), AC4b (piloto-50 batch back-compat), AC6 (v1+TSA legacy), the anchor-guard, and the pre-demo smoke that separates `untrusted-anchor` from `forged`.
- **Decoder CLI**: `node bin/decode-evidence.js <path>` prints `hash`, `HMAC`, `TSA`, and `sig` (post-v0.7.0) per evidence.
- **HMAC determinism**: [`test/prove/hmac-excluded-keys.test.js`](../test/prove/hmac-excluded-keys.test.js) — proves emit-metadata never enters the seal.
- **Audit response**: [`docs/v070-audit-response.md`](v070-audit-response.md) records the 4 drops from the Kiro security audit with per-drop empirical evidence.

---

## §8 · Layer-2 injection-guard, CaMeL-style flow gate, and schema enforcement (v0.8 Commit 3)

The 2026-05-29 audit framed three orthogonal concerns the regex layers (DJL/prefilter) alone don't address. v0.8 ships each as a separately-auditable mechanism, with framing the reviewer's binding correction A3 made non-negotiable: **a detector is not a CaMeL replacement; we ship the detector AND apply CaMeL-style gating where it matters, and we say so in docs.**

### 8.A Layer-2 detector (`src/forge/injection-guard.js`) — what it is and isn't

**What it is** — a stronger Layer-2 prompt-injection detector than regex, opt-in via `SYNTHEX_GUARD_URL`. When the env var points at a self-hosted Prompt-Guard endpoint (Meta Prompt-Guard 86M / mDeBERTa multilingual, served via vLLM / HF Inference Server / TEI), each doc that survived DJL + prefilter is screened by the model. The verdict is calibrated as REVIEW-by-default with a high-confidence BLOCK threshold:
- `score ≥ 0.95` → BLOCK (doc removed from the pipeline)
- `0.5 ≤ score < 0.95` → REVIEW (doc KEPT, annotated in `decisions[]` with `outcome:"REVIEW"`)
- `score < 0.5` → ALLOW

**What it is NOT, and what we DO NOT claim**:
- ✗ "Resolves injection." It doesn't. It's a detector. An adaptive adversary can evade detectors. We do not claim defeat.
- ✗ "CaMeL replacement." It isn't. CaMeL is an architectural pattern (flow-data separation that makes detection unnecessary). What we ship here is a detector. The CaMeL-style discipline is applied separately in §8.B where it belongs.
- ✗ "Zero false positives on technical content." Prompt-Guard was trained on **prompts**; we feed it scraped **documents** (security blogs, CVE write-ups, prompt-injection tutorials, vendor security pages). Domain mismatch → false positives are expected. The REVIEW band (0.5–0.95) exists exactly for this: surface the decision in `decisions[]` without dropping the doc.
  - **MEASURED, not asserted (v0.9.0; pipeline behavior updated v1.0.0)**: on a real benign security corpus (5 pages: security blogs + OWASP cheat sheets + PortSwigger + a CVE page), the *isolated-module* false-positive rate is **80% union / 80% DJL / 60% prefilter / 20% injection-guard heuristic** — i.e. the regex layers fire heavily on security *vocabulary and example payloads*. **v1.0.0 (D5 FP fix):** at the **pipeline** level, L1 regex (DJL + prefilter) is now **REVIEW-only on ingest** — a `BLOCK`-grade hit (sev ≥ 8) no longer drops the scraped doc, it marks it `REVIEW` and keeps it (severity sealed in `decisions[]`). So the **pipeline drop rate from L1 regex is now 0/5** (was 3/5), verified by `node scripts/measure-pipeline-fp.mjs` → `dropped_by_regex: 0`. Full method + per-page table + the pre/post pipeline table: [`docs/guard-fp-measurement.md`](guard-fp-measurement.md); reproduce with `node scripts/measure-guard-fp.mjs` (isolated) and `node scripts/measure-pipeline-fp.mjs` (pipeline). Honest implication: pointing Synthex at security domains surfaces legitimate content for review instead of silently dropping it; **BLOCK authority on ingest now belongs only to a qualified Layer-2 (Phase 1, gated on its own measured FP) and L3 AlignmentCheck**, never to L1 regex.
- ✗ "More confidence than 0.95 via heuristics alone." When the model endpoint is unreachable, `screen()` fails open to `heuristicScreen()` — a zero-dep deterministic fallback whose top-line confidence is capped at 0.97 (stacking ≥2 distinct labels). The heuristic catches the obvious + multilingual prompt-injection vectors the regex layer also catches; it is NOT a substitute for the model.

**v1.0.0 (item 1.1) — Featherless / Qwen3Guard-Gen-8B as the L2 model path.** v0.9 only spoke the self-hosted Prompt-Guard classifier shape (`{text}` → softmax). v1.0.0 adds a second provider branch, selected by `SYNTHEX_GUARD_PROVIDER=featherless` (or autodetected when `SYNTHEX_GUARD_URL` contains `featherless.ai`). The real model id is **`Qwen/Qwen3Guard-Gen-8B`** (the bare `Qwen3Guard-8B` 404s on Featherless). Mapping: `Safe → allow`, `Controversial → review`, `Unsafe → block` (score 0.0 / 0.6 / 0.97 onto the existing 0.95-block / 0.5-review thresholds). // ES: segunda rama de proveedor (Featherless) con Qwen3Guard-Gen-8B; mapeo 3-tier Safe/Controversial/Unsafe → allow/review/block.
- **GATE-BEFORE-TRUST finding (probe, 2026-05-29), documented because it is non-obvious:** Featherless's `/chat/completions` applies its OWN generic chat template and IGNORES the model's bundled moderation `chat_template`, so a naive `{role:"user",content:<doc>}` POST makes Qwen3Guard **chat** (benign → explanation, injection → refusal) and it NEVER emits the `Safety:`/`Categories:` verdict. The fix that classifies: render the OFFICIAL moderation template ourselves (`renderQwen3GuardPrompt` — SAFETY POLICY + 9 UNSAFE CONTENT CATEGORIES + a primed empty `<think></think>`) and POST it to `/completions` RAW (no server-side templating). Verified probe output: benign → `Safety: Safe / Categories: None`; injection → `Safety: Unsafe / Categories: Jailbreak`. Reproduce: `set -a; source ~/.config/apohara/secrets.env; set +a; node scripts/probe-featherless.mjs` → prints `OK Qwen/Qwen3Guard-Gen-8B benign=Safe injection=Unsafe` (or an honest `FAIL <reason>`, in which case L2 stays on the heuristic fallback and L3 backstops — non-blocking). // ES: Featherless ignora el template de moderación del modelo; lo renderizamos nosotros y lo mandamos a /completions crudo. Si la probe FALLA, L2 cae al heurístico y L3 respalda.
- **BLOCK authority gate — MEASURED 2026-05-29 (item 1.2).** A model `Unsafe` verdict is demoted to `review` unless `SYNTHEX_GUARD_BLOCK_ENABLED` is truthy (`_capVerdict`); the raw block-band score is always sealed. **Measured benign FP of `Qwen/Qwen3Guard-Gen-8B` on the 5-page corpus = 2/5 (40%)** — computed live by `node scripts/measure-guard-fp.mjs --provider=featherless` (0/5 unparsed, deterministic at `temperature:0`, reproduced 2×; the two FPs are page 01 (Simon Willison's prompt-injection blog) and page 04 (PortSwigger SQLi), both quoting literal attack payloads — the OWASP cheat sheets + the CVE page classify `Safe`). **Decision rule ([`guard-fp-measurement.md`](guard-fp-measurement.md)):** a guard earns BLOCK only if benign FP ≤ 20% (the L1-heuristic bar). 40% > 20% → **DISQUALIFIED.** **Recommended `SYNTHEX_GUARD_BLOCK_ENABLED=0` (leave unset) — BLOCK stays disabled for L2; every `Unsafe` degrades to REVIEW.** This is exactly the shipped default, so the measurement *confirms* the conservative fail-safe rather than changing it; **L3 AlignmentCheck (item 1.3) is the path to real BLOCK authority** (L2 = volume filter, L3 = FP-killer — an L2 FP that only REVIEWs is recoverable, an L2 BLOCK that drops a benign security page is not). Optional probes `google/shieldgemma-9b` + `OpenSafetyLab/MD-Judge-v0.1` → HTTP 404 on Featherless (**NOT MEASURED**, honest FAIL); `meta-llama/Llama-Guard-3-8B` is GATED → **NOT ATTEMPTED**. Fail-safe: an unmeasured/unqualified guard never drops a scraped doc. // ES: FP medido de Qwen3Guard-Gen-8B = **2/5 (40%)**; regla: BLOCK sólo si FP ≤ 20%; 40% > 20% ⇒ NO califica; recomendado `SYNTHEX_GUARD_BLOCK_ENABLED=0` (sin setear) — BLOCK queda deshabilitado para L2 (todo a REVIEW), que es el default actual; L3 (1.3) es el camino a BLOCK real.

**Auditable mode + model hash in the seal (A3 binding)** — when two runs over identical content can diverge (GPU drops → fallback to heuristic), the divergence must be visible, not silent. Every guard-derived row in `payload.decisions[]` carries:
- `guard_mode: "featherless" | "prompt-guard" | "heuristic"` — which path produced the verdict (`source`)
- `guard_score: 0..1` — the calibrated score
- **The 4 sealed §4 fields, ALWAYS present, NEVER undefined** — `guard_model`, `guard_provider`, `guard_version`, `model_hash`. The featherless path seals `guard_model:"Qwen/Qwen3Guard-Gen-8B"`, `guard_provider:"featherless"`, `guard_version:"qwen3guard-gen-v1"` (template/contract version), `model_hash:null` (Featherless does not expose weight hashes). **The heuristic fallback seals a coherent shape too** — `guard_provider:"heuristic"`, `guard_model:"heuristic-zero-dep"`, `guard_version: POLICY_BUNDLE_VERSION`, `model_hash:null` — so a degraded run is auditable, not silently blank. The mode that ran is always sealed. // ES: los 4 campos del §4 se sellan SIEMPRE (modelo/proveedor/versión/hash), también en el fallback heurístico — nunca undefined.

The pure operational `guard_endpoint_status` (a run-dependent ops surface) is intentionally NOT sealed — it would be different on every run and would break `contentHash` determinism. The `guard_mode` per-decision IS sealed because it is content-policy-relevant.

**Threshold rationale**: 0.95 BLOCK is intentionally high. The audit's binding framing: in a hackathon-scale OSS demo with scraped content from arbitrary domains, a model trained on prompts will false-positive enough on technical content that a 0.85 BLOCK would burn legitimate scrapes silently. REVIEW (0.5–0.95) keeps the doc + records the suspicion; a human can audit the trail via [`bin/decode-evidence.js`](../bin/decode-evidence.js).

### 8.B CaMeL-style flow-data gate — applied to `react → webhook` and `Cognee ingest`, NOT to classify

The reviewer's real architectural point in A3: detector ≠ architecture. CaMeL discipline belongs where verdicts trigger **actions** or **persist state**, not on label-only paths. Two paths get the gate:

1. **`watch → react → webhook`** (`src/sinks.js webhookSink`). When an alert would fire AND any contributing doc was marked `REVIEW` (or `BLOCK`) by a gating layer, the webhook is **suppressed** unless the operator explicitly opted in via `SYNTHEX_REACT_TRUST_REVIEWED=1`. Reason: a webhook is a *real action* — it pages oncall, fires a Slack alert, opens a SIEM ticket. Triggering one on REVIEW'd content (a layer said "this looks like injection but isn't certain") rather than ALLOW'd content propagates uncertainty into someone's pager.

2. **Cognee ingest** (`src/sinks.js cogneeSink`). When any source for a sealed evidence was REVIEW'd, the ingest is **suppressed** unless `SYNTHEX_COGNEE_TRUST_REVIEWED=1`. Reason: knowledge-graph ingest is **memory persistence** — REVIEW'd content that survives into Cognee can poison future recall. Better default: don't persist what a layer flagged for review.

**v1.0.0 (A1) — which layers gate.** v0.8 scoped the gate to `layer === "injection-guard"` only. The D5 FP fix makes L1 regex (DJL + prefilter) emit `REVIEW` rows on ingest, so the gate was widened to honor any `decisions[]` row with `outcome ∈ {REVIEW, BLOCK}` from `layer ∈ {injection-guard, djl, prefilter}` **or** `stage === "ALIGNMENT_CHECK"` (the L3 stage, which lands in Phase 1 — the predicate is ready now and matches by `stage` because L3 rows carry no `layer`). This closes an inter-phase gap: from the moment L1 regex started emitting REVIEW rows, a doc REVIEW'd by DJL/prefilter must NOT silently fire a webhook or poison Cognee. The gate set is `_GATING_LAYERS` / `_GATING_OUTCOMES` in `src/sinks.js`.

**Why NOT classify**: classification is label-only. The classifier output never triggers a downstream action (no webhook, no persistence, no exfiltration). It just attaches `{lens, severity, summary, signals}` to the doc. A REVIEW verdict on a doc still gets classified — the operator sees both the classification AND the REVIEW flag in `decisions[]`. CaMeL discipline applied to classify would be cargo-cult; we don't do it.

**Surfacing**: when a gate suppresses, the suppression is logged via `console.warn` when `SYNTHEX_DEBUG` is set. The REVIEW decision itself is already sealed in `evidence.payload.decisions[]` — an operator can replay any run from the sealed record to see which docs were REVIEW'd and inferred-suppressed.

**Tests**: [`test/sinks.test.js`](../test/sinks.test.js) covers the matrix (REVIEW'd + no opt-in → suppress; REVIEW'd + opt-in → fire; clean → fire; **v1.0.0**: REVIEW from DJL/prefilter → suppressed via the widened gate (A1); REVIEW from a non-gating layer → NOT suppressed; an Evidence Report whose only REVIEW row is `layer:"djl"` suppresses BOTH webhook and Cognee).

### 8.C Schema enforcement via `zod.strict()` on classifier output (orthogonal hardening)

Independent from injection detection, the classifier output gets strict-mode schema validation (`src/classify/schema.js`):
```js
ClassificationSchema = z.object({
  lens:     z.string().min(1),
  severity: z.number().int().min(0).max(10),
  summary:  z.string().max(400),
  signals:  z.array(z.string()).max(32),
}).strict();   // additionalProperties:false — rejects smuggled keys
```

**Why this is non-trivial despite `parseClassification` already whitelisting**: whitelisting drops unexpected keys **silently**. Strict-mode validation **announces** the rejection so the pipeline can record a `SCHEMA_VIOLATION` event. The threat model is drift: a future change to `parseClassification` (or a new code path that bypasses it) might let a smuggled key through. Strict mode catches that drift in test instead of in prod.

**Wire** (`src/classify/aiml-client.js`): validation runs AFTER `parseClassification` and BEFORE emit-metadata (`truncated` / `charsSeen` / `lowConfidenceTier`) is attached — those three keys intentionally fail strict mode by design (they live in `HMAC_EXCLUDED_KEYS`, never sealed, only for UI/PDF). On validation failure, the safe fallback `{lens, severity:0, summary:"model output failed schema validation", signals:[]}` substitutes; `opts.onSchemaViolation` fires so the pipeline can record the violation.

**Orthogonal to injection detection** — this handles a different threat: the model returning a structurally-wrong shape (e.g., severity=15 / an extra `system_prompt` key / a `signals` entry that's a number not a string). It does NOT detect prompt-injection content; that's §8.A's job.

**Tests**: [`test/classify/schema.test.js`](../test/classify/schema.test.js) — 13 tests covering smuggled keys, out-of-range severity, non-integer severity, oversized summary, oversized signals array, emit-metadata rejection, garbage input no-throw, stable `SCHEMA_POLICY_BUNDLE_VERSION`.

---

## §9 · Two `guard`s in the tree — naming-collision note

Per A3, the v0.8 module is named `src/forge/injection-guard.js`, NOT `src/guard.js`. There are now two unrelated `guard` modules and the distinction is load-bearing:

| File | Role | Layer |
|---|---|---|
| [`src/guard.js`](../src/guard.js) | Network-edge guard for the public live endpoint — SSRF block-list + in-memory rate-limit. See §2.1, §2.2. | Pre-pipeline (HTTP request entry). |
| [`src/forge/injection-guard.js`](../src/forge/injection-guard.js) | Layer-2 prompt-injection detector — Featherless Qwen3Guard-Gen-8B or self-hosted Prompt-Guard, with heuristic fallback. See §8.A. | Pre-LLM (Forge step, after DJL + prefilter). |

They share a word in their name and nothing else. The first protects the **HTTP boundary** of the public endpoint from abuse; the second hardens the **content path** of every pipeline run. Tests live in different directories (`test/guard.test.js` vs `test/forge/injection-guard.test.js`).
