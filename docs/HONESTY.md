# Honesty — Apohara Synthex

> **Single source of truth for "what we don't claim."** If this file says one thing and the README or pitch deck says another, this file wins. The "Honesty" anchor in [README.md](../README.md#-honesty) and `SLIDES.md §12` both link here.

The product pitches *verifiable honesty over polished claims*. That rule applies to us too: any caveat that materially shapes how a user should read a Synthex evidence report belongs here, with an inline pointer to the code path that enforces it.

---

## §1 · Cryptographic seal — what it does and doesn't prove

### 1.1 RFC 3161 TSA · what `signatureValid:true` means (M1, v0.7.0)
- **What the verifier now checks** (`src/prove/tsa.js verifyTimestamp`):
  1. `status: granted` on the `TimeStampResp`.
  2. `messageImprint` inside the token equals our `SHA-256(contentHash)`.
  3. The CMS `messageDigest` signed attribute equals `SHA-256(TSTInfo bytes)`.
  4. The CMS signature math verifies against the signer cert's public key (RSA-PKCS1-v1_5).
  5. The certificate chain (signer → intermediate → root) terminates at one of the two pinned DigiCert anchors in `src/prove/tsa-anchors.js`, verified link-by-link by issuer DN + signature.
- **What it does NOT prove**:
  - Not OCSP / CRL revocation — we don't go online to ask DigiCert "is this responder still trusted today?"; we only check that the responder cert was issued by our pinned anchors.
  - Not the *truth* of the sealed content — only that the bytes existed at `genTime` and have not been altered.
  - Not a court ruling — the term "court-grade" in marketing copy means "cryptographically reproducible and standards-based"; admissibility depends on the jurisdiction and the dispute.
- **Failure modes operators must distinguish** (returned as `signatureValidReason`):
  - `"forged"` — the signature math fails. The token was edited or the responder cert is wrong.
  - `"untrusted-anchor"` — the math passes but the chain doesn't reach our pinned anchors. **Most common cause: DigiCert rotated the TSA CA and our pin is stale.** A genuine fresh token shows this; it is NOT a forgery alert. The anchor-rotation runbook (Follow-up F4, v0.7.1) is the response.
  - `"chain-incomplete"` — the signer cert isn't in the CMS or the chain can't be walked.
  - `null` — there is no TSA token in this evidence (HMAC-only seal); we never called `.verify()`. NOT a failure.
- **The HMAC-only fallback is honest by design**: if the TSA call fails at seal time, `rfc3161Tsa` is `null` and the evidence is sealed with HMAC-SHA256 alone. The seal method string says so explicitly (`"HMAC-SHA256"` vs `"HMAC-SHA256 + RFC 3161 TSA"`). A v0.5 / v0.6 evidence file (or any HMAC-only fixture in [`out/stress-piloto-50-2026-05-28/`](../out/stress-piloto-50-2026-05-28)) still verifies under the v0.7 verifier — `signatureValid` short-circuits to `null`.

### 1.2 Model confidence is NOT part of the seal (AI-2)
- The cryptographic seal proves the *evidence bytes existed*; it does not say anything about the classifier's confidence. Classifier output (severity, summary, signals) is advisory — the PDF disclaimers in `src/prove/pdf-report.js` state this on the rendered page.
- No ensemble / cross-model agreement scoring ships in OSS. Tier-level confidence is conveyed by tier labels (`free-low-quality`, `oss`, `paid`) and by the visible low-confidence flag on free-tier output (v0.7.0 T11).

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
- v0.6 FREE tier (`nvidia/nemotron-nano-9b-v2`) is labeled `free-low-quality` because 50% of fixtures had Δseverity > 1.5 vs DeepSeek (src: [`docs/v060-calibration.md`](v060-calibration.md)).
- The Delta Engine combines scrape + diff + HMAC + RFC 3161 + KG — a directed search at 2026-05-28 found no open-source combination of the five, but we make no "first in world" claim (see [`docs/PRIOR_ART.md`](PRIOR_ART.md) for reproducible queries).

---

## §7 · Where to find the proof

- **Verifier (CMS chain)**: `src/prove/tsa.js verifyTimestamp` — custom CMS verify path (we don't use `pkijs.SignedData.verify()` because of an upstream bug with constructed OCTET STRING `eContent`; see file header).
- **Pinned anchors**: `src/prove/tsa-anchors.js` — both PEMs were extracted from the embedded chain inside `samples/synthex-evidence-report.json`; the file's load-time guard refuses to start if a PEM was edited without updating its fingerprint.
- **Acceptance tests**: [`test/prove/tsa-cms-verify.test.js`](../test/prove/tsa-cms-verify.test.js) covers AC1 (positive), AC2a (untrusted-anchor), AC2b (forged), AC4 (HMAC-only short-circuit), AC4b (piloto-50 batch back-compat), AC6 (v1+TSA legacy), the anchor-guard, and the pre-demo smoke that separates `untrusted-anchor` from `forged`.
- **Decoder CLI**: `node bin/decode-evidence.js <path>` prints `hash`, `HMAC`, `TSA`, and `sig` (post-v0.7.0) per evidence.
- **HMAC determinism**: [`test/prove/hmac-excluded-keys.test.js`](../test/prove/hmac-excluded-keys.test.js) — proves emit-metadata never enters the seal.
- **Audit response**: [`docs/v070-audit-response.md`](v070-audit-response.md) records the 4 drops from the Kiro security audit with per-drop empirical evidence.
