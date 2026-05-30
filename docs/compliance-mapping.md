# Compliance mapping — Apohara Synthex v0.7.x / v0.8

> **What this doc is.** A concrete map from specific regulatory obligations to the Synthex features that address them. **What this doc is NOT.** A compliance certification. We do not claim "Synthex is EU AI Act compliant" or "Synthex is SB 942 compliant" — we claim that specific Synthex features address specific obligations, and we cite article numbers + file paths so an auditor can trace each claim.

The reviewer of 2026-05-29 flagged that the page mentions "EU AI Act / DORA" without mapping concrete obligations to concrete features. This doc closes that gap.

---

## EU AI Act (Regulation (EU) 2024/1689)

### Article 14 — Human Oversight of high-risk AI systems

> "High-risk AI systems shall be designed and developed in such a way, including with appropriate human-machine interface tools, that they can be effectively overseen by natural persons during the period in which they are in use."

**What Synthex provides:**

- **Per-stage audit trail in the sealed evidence.** Every BLOCKED document carries a row in `payload.decisions[]` with `{stage, layer, rule_matched, outcome, policy_bundle_version, at}` — see `src/pipeline.js:177-186`. A human reviewer can inspect *every* automated decision the pipeline took, including which rule fired and which version of the policy bundle was in effect.
- **Cryptographically-attested verifier output.** `verifyEvidence` (`src/prove/evidence-report.js:109`) returns explicit per-layer verdicts (`hashOk`, `hmacOk`, `tsaOk`, `signatureValid` + `signatureValidReason`) so a human reviewer can determine *exactly* what was checked and what passed. The verifier never returns a single "valid/invalid" bit — every layer is surfaced separately.
- **Anchor-rotation monitor.** `scripts/monitor-tsa-anchors.mjs` (cron job) pages on `signatureValidReason: "untrusted-anchor"` so a human is in the loop when the trust chain degrades. Runbook: `docs/F4-tsa-anchor-rotation.md`.
- **CLI inspector.** `node bin/decode-evidence.js <evidence.json>` renders the entire decision trail + verification output in human-readable form. No SDK, no special tooling.

**What this does NOT do:** auto-enforce human approval on individual classifications. The human-oversight obligation under Article 14 requires the *deployer* to set up review workflows around the artifacts Synthex produces.

### Article 50 — Transparency Obligations for content that interacts with humans

> "Providers of AI systems generating synthetic audio, image, video or text content shall ensure that the outputs of the AI system are marked in a machine-readable format and detectable as artificially generated or manipulated."

**What Synthex provides:**

- **Provenance hash in every output.** `payload.contentHash` = SHA-256 of canonicalized payload (`src/prove/evidence-report.js:60`). Machine-readable.
- **RFC 3161 timestamp from a third-party authority.** `payload.seal.rfc3161Tsa` carries a DigiCert-signed timestamp with the original message imprint. Anyone can verify *when* this content existed without trusting Synthex (`src/prove/tsa.js verifyTimestamp`).
- **Sealed source list.** `payload.sources` records the URLs the classifier saw. The seal binds them.
- **(v0.8) Asymmetric signature.** `seal.signature` (Ed25519, planned for v0.8) lets a third party verify *who* signed the report without holding any shared secret. Until v0.8 ships, the HMAC layer alone is integrity-to-keyholder, **not** non-repudiation — see `docs/HONESTY.md` §7 for the explicit acknowledgment.

**Honesty:** Synthex's outputs are CLASSIFICATIONS of scraped content (severity scores, signals, summaries). They are not "synthetic content" in the Article 50 sense (we don't generate articles). The provenance machinery applies regardless — judges/regulators reviewing decisions made on top of Synthex outputs benefit from the timestamp + sealed source list.

### Article 12 — Record-keeping

> "High-risk AI systems shall technically allow for the automatic recording of events ('logs') over the lifetime of the system."

**What Synthex provides:**

- **OpenTelemetry GenAI spans** per stage (`src/telemetry/otel.js`). When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, every FETCH/FORGE/CLASSIFY/PROVE stage emits a span with token usage, blocked counts, and latency. OTLP-compatible backends (Tempo, Honeycomb, etc.) ingest natively.
- **Sealed evidence files persist independently of telemetry.** The evidence file IS the durable record — even if telemetry is off, the `decisions[]` + `policy_bundle_version` + `contentHash` + seal constitute a per-run audit log.

### Article 11 — Technical documentation

> "The technical documentation of a high-risk AI system shall be drawn up before that system is placed on the market … and shall be kept up-to-date."

**What Synthex provides — RAG status: 🟢 GREEN (supports):**

- The Evidence Report itself IS technical documentation of a decision: it records the sources scraped, the per-layer `decisions[]` (DJL/prefilter/L2/L3/grounding), the `policy_bundle_version` of every rule set, the model ids used, and the seal — drawn up automatically *at decision time*, not reconstructed after the fact.
- **What this does NOT do:** it does not document the *deployer's* overall AI system (its training, intended purpose, risk-management system). Article 11 is a system-level obligation on the provider; Synthex documents the *per-run evidence*, one input to that dossier.

### Article 13 — Transparency and provision of information to deployers

> "High-risk AI systems shall be designed and developed … to enable deployers to interpret a system's output and use it appropriately."

**What Synthex provides — RAG status: 🟡 AMBER (partially supports):**

- Every classification ships with the **inputs it was derived from** (sealed source list + the `charsSeen` window the model actually saw, via the grounding verifier) and the **per-layer rationale** in `decisions[]` (e.g. an L3 `ALIGNMENT_CHECK` row carries its `rationale` + `confidence`). The Risk Score page prints its exact formula. This is interpretability of the *output*.
- **AMBER, not GREEN:** the frontier-model classification step is not itself fully explainable; we surface the inputs, the grounding verdicts, and the deterministic-layer decisions, but the LLM's internal reasoning is summarized, not proven. A deployer interprets the output with these aids; we do not claim full model transparency.

---

## NIST AI RMF (AI 100-1) — risk-management framing

The Synthex Risk Score and `decisions[]` ledger map onto the four NIST AI RMF functions (mapping, **not** endorsement — NIST does not certify tools):

| NIST AI RMF function | Synthex feature |
|---|---|
| **GOVERN** | `policy_bundle_version` sealed per run + `docs/HONESTY.md` (documented limits) make the governing rule set auditable. |
| **MAP** | The 4-lens classification + sealed source list MAP the context of what the agent scraped. |
| **MEASURE** | Measured guard FP (L2) + L3 false-BLOCK (`docs/guard-fp-measurement.md`) + the CVSS-scaled severity are the MEASURE function — quantified, not asserted. |
| **MANAGE** | The CaMeL-gated react/webhook + L3 BLOCK authority (drop the poisoned doc) are the MANAGE/response function. |

---

## Risk Score grounding — CVSS / EPSS

The Synthex Risk Score (`src/prove/pdf-report.js riskScore`) is **anchored in named public scoring frameworks** rather than presented as a private heuristic (do-not §9). This is a **mapping, not an endorsement** — neither FIRST (CVSS/EPSS) nor any body has reviewed the number:

- **CVSS (Common Vulnerability Scoring System, FIRST.org)** — the severity axis (`maxSev`, 0–10) uses the **CVSS base-score scale**, and the bands align to CVSS severity ratings: **High ≥ 7.0**, Medium 4.0–6.9, Low < 4.0. The Synthex `HIGH ≥ 70 / MEDIUM ≥ 40` cutoffs are the CVSS bands × 10.
- **EPSS (Exploit Prediction Scoring System, FIRST.org)** — **shipped as an OPT-IN, additive, NON-SEALED enrichment** (`SYNTHEX_EPSS_ENABLED`, `src/prove/epss.js`). When a security-lens finding's text names a CVE, Synthex fetches that CVE's daily EPSS exploitation probability (public FIRST.org API) at report-RENDER time and weights the severity term (factor `1 + 0.3·epss`). **Honest limits:** best-effort — CVE ids are regex-extracted from finding text (the classifier emits no structured CVE field), so an un-named CVE is missed; EPSS is exploitation *probability*, not severity/CVSS (a separate FIRST framework, mapping-not-endorsement); and it is **never sealed** (changes daily → fetched at render, excluded from the canonical pre-image, so offline verification is unchanged). With the flag unset / no network / no CVE, the score is byte-identical to the base formula.
- The compliance framing maps to **EU AI Act** risk categories (Article 11/12/13/14 above) and **NIST AI RMF** (table above).

---

## California SB 942 (AI Transparency Act, effective 2026-01-01)

> Requires "covered providers" of generative AI systems to make available an AI detection tool that allows users to assess whether content was generated by the provider's AI system.

**What Synthex provides:**

- **`bin/decode-evidence.js`** — open-source detection tool. Anyone with a Synthex-sealed evidence file can verify it without contacting us. The CLI prints per-layer verdicts (`hash`, `HMAC`, `TSA`, `sig`) so the verifier reads the *exact same* truth Synthex saw at seal time. No SaaS dependency.
- **(v0.9) `npx synthex evidence-card`** — REAL C2PA Content Credentials. Emits a PNG card whose embedded manifest **`c2patool` verifies as Valid** (CI gate in `scripts/c2pa-interop-test.sh`), bound to the same `contentHash` as the PDF; the own `c2pa-verify` checks the JSON sidecar offline. Self-signed signer → "untrusted source" (HONESTY §1.6).
- **(v0.9) `npx synthex rekor-anchor`** — anchors the keyId in Sigstore Rekor v2 (public append-only log); `rekor-verify` checks the inclusion proof + checkpoint signature fully offline.
- **Sealed `policy_bundle_version`** in every payload — a verifier can determine *which version* of the DJL+prefilter+PII rules was in effect when the classification happened (`src/pipeline.js:173-176`). Version drift is visible.

**Honesty:** Synthex is not itself a "covered provider" of generative AI — we don't generate the synthetic content SB 942 targets. We're an intelligence/evidence layer over scraping. The detection-tool obligation is what generative providers ship; Synthex's verification tooling is the model for what *third-party verification* should look like, applicable to any provenance system.

---

## DORA (Regulation (EU) 2022/2554) — Digital Operational Resilience Act

DORA targets financial-sector ICT resilience. Synthex is general-purpose, not financial-specific, but two Synthex features address DORA-style operational-resilience obligations:

- **Article 9 (ICT risk management) — verifiable records of ICT operations.** Synthex's sealed evidence files (HMAC + RFC 3161 timestamp) are durable, third-party-verifiable records of what was scraped, what was classified, and what was blocked. The verifier (`bin/decode-evidence.js`) runs offline — auditors do not need Synthex's online infrastructure.
- **Article 17 (Major ICT-related incident reporting) — anchor rotation monitor.** `scripts/monitor-tsa-anchors.mjs` (weekly cron + manual workflow_dispatch) pages on `signatureValidReason: "untrusted-anchor"`, which is the early-warning indicator that the trust chain has degraded (DigiCert rotation OR a real forgery). The F4 runbook (`docs/F4-tsa-anchor-rotation.md`) is the response procedure.

---

## What we deliberately do NOT claim

- **"Synthex is GDPR/HIPAA/PCI-DSS compliant."** Compliance is the deployer's burden; we provide primitives (PII pre-filter via DJL, sealed audit trail, key-management for the HMAC/Ed25519 layers) that *support* compliance work but do not *constitute* it.
- **"Synthex is a generative AI provider."** It's a classifier over scraped content. The Article 50 / SB 942 / EU AI Act Article 14 obligations land on the *deployer* and on any *downstream* generative system using Synthex outputs.
- **"The cryptographic seal proves authenticity."** It proves *integrity* (hash + HMAC + timestamp) and, starting v0.8, *non-repudiation* (Ed25519 asymmetric signature) — see `docs/HONESTY.md` §1 for the full breakdown of what each layer does and doesn't prove. It does **not** prove the truth of the scraped content; it proves the content existed at the time it was sealed and that the seal is intact.

---

## How to use this doc

1. **For auditors / counsel:** each section above maps a specific regulatory obligation to a specific feature with a file:line reference. Click through to verify each claim against the code.
2. **For developers:** when you add a new compliance-relevant feature, add a section here with the obligation citation + the file:line where the feature lives. Don't let this doc rot.
3. **For Pablo / future maintainers:** this doc is binding. If the README mentions "EU AI Act compliance" anywhere, the relevant section here is the source of truth for what we mean by that.

References:
- EU AI Act: <https://eur-lex.europa.eu/eli/reg/2024/1689/oj>
- California SB 942 (AI Transparency Act): <https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=202320240SB942>
- DORA: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>
