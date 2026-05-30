<!-- Hallmark · PDF design spec · pre-emit critique: P5 H5 E4 S5 R5 V4
     redesign (not rebuild) · brand EXTRACTED from public/index.html, not invented · medium: PDFKit -->

# Evidence Report — Locked Design Spec (v2 · "Screen it · Seal it")

> Source of truth for the enterprise Evidence Report PDF rebuild (`src/prove/pdf-report.js`).
> Brand tokens are **extracted from `public/index.html`** (the deployed synthex.apohara.dev), not invented.
> This is a **redesign within the existing PDFKit generator**, not a rebuild. Honesty-doc bound: every
> claim measured (`docs/HONESTY.md`); no "court-grade"; "mapping, not endorsement" on any score.

## 0. Paper model — Option C (dark cover · light interior)

- **Page 1 (cover / executive summary)** — full-bleed **dark** (`--void`), brand-faithful, screen-native.
  It is the brand moment + the at-a-glance verdict/seal. Print assumption: **may not be printed**.
- **Pages 2–N (interior)** — full **light paper** `#FAFAF8`, dark ink. ALL content — tables, hashes,
  the verify commands — **light and printable** (buyer prints the interior only). No dark code blocks
  in the interior (toner + Pablo's directive): command/hash boxes are a light tinted box with a hairline.
- **Transition is intentional, not a jump**: the cover is full-bleed dark edge-to-edge; the first
  interior page opens full light edge-to-edge. No half-dark page, no dark band bleeding into interior.
  The cover carries a single thin lime rule at its base as the "fold" signal.

## 1. Locked color tokens (PDFKit RGB hex) — contrast VERIFIED

PDFKit takes hex directly (`doc.fillColor('#RRGGBB')`). Ratios computed WCAG 2.1, real (not asserted).

### Cover (bg `--void #090a10`)
| token | hex | role | ratio on void |
|---|---|---|---|
| `cover.bg` | `#090a10` | page bg | — |
| `cover.ink` | `#EDEFF0` | body/headline | **17.1:1 AAA** |
| `cover.violet` | `#9775fa` | seal/heading accent | **5.87:1 AA** |
| `cover.lime` | `#25B13F` | verdict-ok / QR / fold rule | **7.0:1 AAA** |
| `cover.amber` | `#e8a13a` | REVIEW accent | **9.0:1 AAA** |
| `cover.red` | `#e5484d` | BLOCK/critical | **5.05:1 AA** |
| `cover.muted` | `#888fb0` | meta/labels | (large only) |

### Interior (paper `#FAFAF8`) — brand violet/lime DARKENED to pass AA on light
| token | hex | role | ratio on paper |
|---|---|---|---|
| `paper.bg` | `#FAFAF8` | page bg | — |
| `paper.ink` | `#1a1d29` | body | **16.0:1 AAA** |
| `paper.muted` | `#5a6080` | secondary/labels | (verify per use; large) |
| `paper.violet` | `#5733b8` | persona tag / headings / seal | **7.82:1 AAA** |
| `paper.green` | `#17772a` | RAG green / verified / OK | **5.42:1 AA** |
| `paper.red` | `#c0392b` | RAG red / BLOCK / FAIL | **5.20:1 AA** |
| `paper.amber` | `#8a5a08` | RAG amber / REVIEW / partial | **5.67:1 AA** |
| `paper.rule` | `#e3e3df` | hairline table/section rules | — |
| `paper.zebra` | `#f3f3f0` | zebra row tint | — |
| `paper.codebg` | `#f0f0ec` | hash/command box bg (light) | — |

RAG legend uses `paper.green / paper.amber / paper.red`. Never the cover brights in the interior body.

## 2. Typography — embed the brand fonts (OFL, shippable)

PDFKit built-ins are Helvetica/Times/Courier only. Embed the real brand faces via `doc.registerFont`:
- **Inter** (OFL) → `Inter` — body + headings. Ship `Inter-Regular/Medium/SemiBold/Bold.ttf` in `assets/fonts/`.
- **JetBrains Mono** (OFL) → `Mono` — hashes, commands, IDs, table numerics, kickers.
- **Press Start 2P** (OFL) → `Pixel` — **cover wordmark accent ONLY** (one use). Never in the interior body
  (pixel type fails enterprise legibility at small sizes). If unavailable, the cover wordmark falls back to `Mono`.
- Fallback if TTFs absent: `Helvetica` (sans) + `Courier` (mono). Ship the TTFs — it's a $2,500/mo artifact.

### Type scale (PDF points)
| role | font | size/leading |
|---|---|---|
| Cover wordmark | Pixel→Mono | 22 / 30, tracking 1 |
| Cover verdict (big) | Inter Bold | 30 / 34 |
| Page H1 (persona title) | Inter SemiBold | 19 / 24 |
| Section title | Inter SemiBold | 12.5 / 16, tracking 0.4 |
| Kicker / persona tag | Mono | 8.5 / 12, tracking 1.4, UPPERCASE |
| Body | Inter Regular | 9.5 / 14 |
| Table header | Mono | 8 / 11, tracking 0.6, UPPERCASE |
| Table cell | Inter Regular | 8.5 / 12 (numerics → Mono, right-aligned) |
| Hash / command (mono box) | Mono | 8 / 12 |
| Footer disclaimer | Inter Regular | 7.5 / 10 |

## 3. Layout & page template

- **Page**: A4 (595×842 pt). Margins: 54 pt L/R, 54 pt top, 64 pt bottom (footer band).
- **Baseline**: 14 pt body grid; section gap 22 pt; intra-section 12 pt.
- **Every interior page** carries, top-to-bottom:
  1. **Persona tag** (kicker, `paper.violet`): e.g. `● SECURITY BRIEFING · FOR CISO`.
  2. **H1** persona title.
  3. content.
  4. **Footer band** (drawn in the buffered pass, every page incl. cover-appropriate variant):
     - left: report ID `SYNTHEX-EVR-<8hex of contentHash>`
     - center: **verbatim disclaimer** (§7)
     - right: `p. N / M`
- Cover footer is the dark variant (ink on void); interior footer is `paper.muted` on paper.

## 4. Tables — NEVER overflow (the audit's hard line)

- Column widths **sized to content**, summing to the text column (487 pt). Fixed widths per page, computed
  so the widest realistic cell fits; the URL/hash column gets the slack and **truncates in-body**.
- **Long values** (URLs, hashes, signatures, keyIds): truncate with a real ellipsis `…` showing
  head+tail (e.g. `a1b2c3d4…9f0e1d2c`), and the **FULL value lives in the sidecar `evidence.json`** —
  never a truncated value with no path to the full one (audit P0 / non-negotiable #3).
- **Numerics right-aligned**, Mono. Text left-aligned, Inter.
- **Hairline rules** (`paper.rule`, 0.5 pt) between rows; **zebra** (`paper.zebra`) on alternating rows.
  No heavy borders, no full grid. Header row underlined with a 1 pt `paper.ink` rule.
- Before drawing a row, measure with `doc.heightOfString`; if a cell wraps to >2 lines, the row grows —
  never clip. If a table would cross the footer band, **paginate** (continue on a new page with a repeated
  header + `(cont.)`), per the report-structure "split if a page would overflow".

## 5. Component patterns

- **Seal block (cover + page 9)** — lead with **Ed25519**, never HMAC as headline. Order:
  `Ed25519 signature` (keyId + truncated value) → `RFC 3161 TSA` (authority · genTime · serial) →
  `Sigstore Rekor v2` (logIndex, present-gated) → `C2PA Content Credentials` (present-gated) →
  `SHA-256 contentHash` → `HMAC-SHA256` labeled **"internal integrity checksum"** (not the headline).
  Each row present-gated: render only the layers the evidence object / passed sidecars actually carry.
- **3-tier guard ledger (CISO page)** — render from `payload.decisions[]`: L1 (DJL/prefilter, REVIEW-only) ·
  L2 (`INJECTION_GUARD`, opt-in) · L3 (`ALIGNMENT_CHECK`, describing-vs-executing verdict + rationale).
  **Honestly label** each: `LIVE` / `DEGRADED (fail-safe REVIEW)` / `DEMO STUB` from the row's
  `degraded` flag and `model_id`/`guard_model` `(DEMO STUB)` marker. Never imply regex is the whole defense.
- **RAG status** — green `✓` / amber `▲` / red `✗` with the `paper.{green,amber,red}` tokens + a text label
  (never color alone — a11y). Coverage legend printed once: `full = pack-validated AND policy-covered ·
  partial = one signal · none = none`.
- **Hash/command box (interior)** — light `paper.codebg` bg, 0.5 pt `paper.rule` border, Mono ink text,
  6 pt padding. Printable. (Dark code styling lives only on the cover.)
- **QR** — on the cover, lime on void; encodes the verifiable-bundle pointer (sidecar URL or contentHash+keyId).

## 6. Voice (extracted taglines — exact)

- Footer signature (cover): `APOHARA SYNTHEX · everything signed, nothing trusted.`
- Cover couplet: `Screen what your agents ingest. Seal what they found.`
- Verify page kicker: `VERIFY IT YOURSELF · RUN IT`.
- Proof phrasing = hard numbers + pinned anchors (`RFC 3161 · DigiCert · CMS chain verify`), never adjectives.
- **Banned**: "court-grade", any legal-admissibility claim, any invented metric, any premium/$ quote on the
  Underwriter page (risk EVIDENCE only — non-negotiable #6), any meta-prose explaining the layout.

## 7. Verbatim footer disclaimer (every interior page)

> The seal proves **when** these bytes existed and that they are **unchanged** — not that the claims are
> **true**. Identity is **self-signed** (not a public trust-list certificate). Evidence record + mapping
> aid, not legal advice. Full verification: page « Verify It Yourself ».

## 8. Page map (Option C dark/light)

| pg | persona | paper | core |
|---|---|---|---|
| 1 | Decision-maker (cover) | **dark** | one-line value · verdict (band-matched) · full seal stack named · target/fetched/sealed/sources/blocked · QR |
| 2 | CISO — Data-BOM | light | per-source table (URL · BD surface · fetched · SHA-256 · bytes · dedup · L1/L2/L3 verdict) |
| 3 | CISO — Security Briefing | light | 3-tier ledger + catch · OWASP LLM/Agentic + MITRE ATLAS map w/ full/partial/none legend · L3 describing-vs-executing · benign-control contrast · STIX 2.1 ref · FORGE copy = REVIEW-only |
| 4 | CFO — Cost & Efficiency | light | exact dedup savings · per-stage latency · cost/run + tier · incident-cost business case (cited real figure) |
| 5 | General Counsel — Compliance Trace | light | multi-framework matrix (EU AI Act Art 11/12/13 · NIST AI RMF) RAG + citations · tamper-evidence · TSA · Rekor · honest disclaimer |
| 6 | Compliance/Model-Risk — Model & Pipeline Attestation | light | model ids + versions + hashes (L2 Qwen3Guard/Featherless, classify, L3) · policy/rubric SHA-256 · guard_mode · SR 11-7 / NYDFS map |
| 7 | Underwriter — Risk Snapshot | light | CVSS/EPSS-grounded score + honest formula · **band-matched** verdict · NIST/EU framing · "mapping not endorsement" verbatim · 3 questions · NO premium |
| 8 | Anyone — Honest Gap Declaration | light | what it does NOT prove · NOT covered · self-signed limit · L1 heuristic-not-formal · measured guard FP |
| 9 | Anyone — Verify It Yourself | light | 3-way verify w/ real commands + exit codes (openssl ts · c2patool · rekor offline) + Ed25519 vs pubkey · `synthex verify <bundle>` · sidecar evidence.json w/ FULL values |

Delta Evidence Chain page is inserted (light) only when `payload.delta_chain` present.

## 9. Build notes

- Embed TTFs first (`assets/fonts/`), register once at the top of `buildPDFReport`.
- Keep the existing generator architecture (autoFirstPage:false · bufferPages:true · per-page fns ·
  buffered footer pass). Add a `theme` token module so cover vs interior pull from one source.
- **Render-test EVERY page** (open the actual PDF, check overflow/truncation/disclaimer/contrast) before
  declaring a page done. Generate from the **real signed run** (hero injection-catch), not the symmetric sample.
