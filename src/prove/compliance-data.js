// PROVE/compliance-data — the single, reusable, framework-mapped compliance dataset.
//
// Today the Evidence Report's Counsel + Model-Attestation pages each carry their own INLINE matrix
// rows. This module extracts that knowledge into one pure, zero-dependency dataset so both pages
// (and STIX/audit consumers) read from ONE source of truth with canonical, verbatim citations.
//
// HONESTY (load-bearing, mirrors HONESTY.md): every entry here is a MAPPING, NOT AN ENDORSEMENT —
// no framework body, regulator, or standards organisation has reviewed or certified this software.
// `synthex_mapping` says WHICH Synthex artefact addresses a control; `rag_status` is an honest,
// evidence-driven self-assessment (green/amber/red/n-a) with a one-line `basis`. A `rag_status` of
// 'green' means "Synthex produces the artefact the control asks for", NOT "the control is satisfied
// for your deployment" — applicability is always the deployer's determination.
//
// Citations are CANONICAL and VERBATIM — the exact legal/standard names, never paraphrased. Do not
// reword "Record-keeping", "Technical documentation", an ATLAS version string, or an OWASP id; the
// tests assert their literal presence so a drift is caught.

/**
 * @typedef {'green'|'amber'|'red'|'n/a'} RagStatus
 *
 * @typedef {object} ComplianceControl
 * @property {string}    id              Stable, framework-scoped id (e.g. "EU-AI-ACT-ART-12").
 * @property {string}    title           Canonical, verbatim control title.
 * @property {string}    requirement     What the control asks for, in one neutral sentence.
 * @property {string}    synthex_mapping Which Synthex artefact addresses it (mapping, not proof).
 * @property {RagStatus} rag_status      Honest self-assessment — mapping, NOT endorsement.
 * @property {string}    basis           One-line, evidence-driven justification for the status.
 *
 * @typedef {object} ComplianceFramework
 * @property {string}             framework Short, stable framework key.
 * @property {string}             citation  Canonical, verbatim citation string.
 * @property {ComplianceControl[]} controls
 */

// Repeated, load-bearing honesty caveat. Centralised so every consumer renders the SAME disclaimer.
export const MAPPING_DISCLAIMER =
  "Mapping, NOT endorsement — no framework body has reviewed this. A 'green' status means Synthex " +
  "produces the artefact the control describes, not that the control is satisfied for a given " +
  "deployment; applicability is the deployer's determination.";

/** @type {ComplianceFramework[]} */
export const COMPLIANCE_FRAMEWORKS = Object.freeze([
  {
    framework: "EU AI Act",
    // Canonical: the Act's instrument name. Verbatim — tests assert "Regulation (EU) 2024/1689".
    citation: "EU AI Act (Regulation (EU) 2024/1689)",
    controls: [
      {
        id: "EU-AI-ACT-ART-11",
        title: "Art 11 — Technical documentation",
        requirement:
          "Maintain up-to-date technical documentation of the AI system before it is placed on " +
          "the market or put into service (Annex IV scope).",
        synthex_mapping:
          "The Model & Pipeline Attestation page documents defenses, model ids/versions, and " +
          "pipeline stages from the sealed decision ledger.",
        rag_status: "amber",
        basis: "Synthex documents the pipeline it runs; full Annex IV coverage is the deployer's.",
      },
      {
        id: "EU-AI-ACT-ART-12",
        // Canonical Art 12 title is "Record-keeping" — NOT "logging". Tests assert this verbatim.
        title: "Art 12 — Record-keeping",
        requirement:
          "Automatically record events (logs) over the lifetime of the AI system to ensure an " +
          "appropriate level of traceability.",
        synthex_mapping:
          "The sealed, timestamped audit trail IS the automatic record: inputs, pre-filter blocks, " +
          "and classifier outputs, sealed per run.",
        rag_status: "green",
        basis: "Each run emits a tamper-evident, timestamped record of the data lifecycle.",
      },
      {
        id: "EU-AI-ACT-ART-13",
        // Canonical Art 13 title, verbatim.
        title: "Art 13 — Transparency and provision of information to deployers",
        requirement:
          "Design high-risk AI systems so deployers can interpret output and use it appropriately; " +
          "provide them clear information.",
        synthex_mapping:
          "The verdict, sources, and full seal stack are disclosed to the deployer; system prompts " +
          "are not exposed (Art 13 does not require it).",
        rag_status: "green",
        basis: "The report discloses verdict, sources, and the cryptographic seal stack.",
      },
    ],
  },
  {
    framework: "NIST AI RMF",
    citation: "NIST AI RMF 1.0",
    controls: [
      {
        id: "NIST-AI-RMF-GOVERN",
        title: "GOVERN",
        requirement:
          "Cultivate a culture of risk management; establish policies, roles, and accountability " +
          "for the AI system's risks.",
        synthex_mapping:
          "The sealing + record-keeping policy is encoded in the pipeline; organisational " +
          "governance remains the deployer's responsibility.",
        rag_status: "amber",
        basis: "Technical policy is encoded; organisational governance is out of scope.",
      },
      {
        id: "NIST-AI-RMF-MAP",
        title: "MAP",
        requirement:
          "Establish the context to frame risks: map sources, intended use, and the surfaces the " +
          "system interacts with.",
        synthex_mapping:
          "Source URLs and their surfaces are recorded in the sealed payload for every run.",
        rag_status: "green",
        basis: "Each run records the scraped source URLs and surfaces in the sealed payload.",
      },
      {
        // Anchor control called out in the prompt: MEASURE 2.5.
        id: "NIST-AI-RMF-MEASURE-2.5",
        title: "MEASURE 2.5",
        requirement:
          "Evaluate AI system validity and reliability (robustness) and document the results of " +
          "such evaluations.",
        synthex_mapping:
          "The 3-tier injection defense measures and records the catch on every scraped document; " +
          "see the Security Briefing page.",
        rag_status: "green",
        basis: "Robustness against injection is measured and recorded per scraped document.",
      },
      {
        id: "NIST-AI-RMF-MANAGE",
        title: "MANAGE",
        requirement:
          "Allocate resources to and act on mapped, measured risks; document residual-risk " +
          "decisions.",
        synthex_mapping:
          "Risks are surfaced and bounded (REVIEW/BLOCK) and sealed; residual-risk acceptance is " +
          "a human decision outside this record.",
        rag_status: "amber",
        basis: "Risks are bounded and sealed; residual-risk acceptance is a human decision.",
      },
    ],
  },
  {
    framework: "NYDFS Part 500",
    // Canonical citation incl. the controlling amendment + its effective date.
    citation: "NYDFS 23 NYCRR Part 500 (Second Amendment, effective Nov 1, 2023)",
    controls: [
      {
        id: "NYDFS-500-AUDIT-TRAIL",
        title: "23 NYCRR 500.06 — Audit trail",
        requirement:
          "Maintain systems that include audit trails designed to detect and respond to " +
          "cybersecurity events, retained as required.",
        synthex_mapping:
          "Each run emits a tamper-evident, timestamped decision ledger that can be re-verified " +
          "offline.",
        rag_status: "green",
        basis: "A tamper-evident, timestamped decision ledger is produced per run.",
      },
    ],
  },
  {
    framework: "SR 11-7",
    // Canonical: SR 11-7 is the same guidance as OCC Bulletin 2011-12 — keep both verbatim.
    citation: "SR 11-7 (= OCC Bulletin 2011-12) model risk management",
    controls: [
      {
        id: "SR-11-7-MODEL-INVENTORY",
        title: "Model inventory & identity",
        requirement:
          "Maintain a comprehensive inventory of models with their identity, version, and intended " +
          "use.",
        synthex_mapping:
          "Every model id + version + policy hash that ran is part of the signed decision record.",
        rag_status: "green",
        basis: "Each model's id, version, and policy hash is in the signed record.",
      },
      {
        id: "SR-11-7-ONGOING-MONITORING",
        title: "Ongoing monitoring",
        requirement:
          "Monitor models in use to confirm they perform as intended and to flag degradation or " +
          "failure.",
        synthex_mapping:
          "Fail-safe REVIEW + a degraded:true flag are sealed when a model is unreachable; this is " +
          "not a full validation programme.",
        rag_status: "amber",
        basis: "Degraded-state is logged and sealed; not a full model-validation programme.",
      },
    ],
  },
  {
    framework: "OWASP LLM Top 10",
    // Canonical 2025 edition name; ids LLM01..LLM10.
    citation: "OWASP Top 10 for LLM Applications 2025",
    controls: [
      {
        id: "LLM01",
        title: "LLM01 — Prompt Injection",
        requirement:
          "Mitigate manipulation of an LLM via crafted inputs that alter its behaviour, including " +
          "indirect (data-borne) injection.",
        synthex_mapping:
          "Layered defense: L1 regex (DJL/prefilter, REVIEW-only on ingest) → opt-in L2 guard → L3 " +
          "AlignmentCheck, plus nonce-tagged Spotlighting.",
        rag_status: "green",
        basis: "A 3-tier injection defense gates scraped content before it reaches an agent.",
      },
      {
        id: "LLM02",
        title: "LLM02 — Sensitive Information Disclosure",
        requirement:
          "Prevent exposure of sensitive data (PII, secrets, credentials) through LLM inputs or " +
          "outputs.",
        synthex_mapping:
          "A 25-rule PII gate plus a Luhn credential check run in the forge layer before content is " +
          "classified or sealed.",
        rag_status: "amber",
        basis: "A PII + credential gate runs pre-classify; coverage is rule-based, not exhaustive.",
      },
    ],
  },
  {
    framework: "OWASP Agentic Top 10",
    // Canonical 2026 edition — note: 2026, NOT 2025. ids ASI01..ASI10. Tests assert "ASI01"+"2026".
    citation: "OWASP Top 10 for Agentic Applications 2026",
    controls: [
      {
        id: "ASI01",
        title: "ASI01 — Agentic AI Threat (anchor)",
        // NOTE: the per-id titles/scope of the 2026 Agentic list are not asserted here verbatim
        // beyond the id; only confirmed facts (edition year + id grammar) are stated. The control
        // narrative is framed as Synthex's own mapping, not a quote of the OWASP entry text.
        // TODO(verify): pin the official ASI01 entry title before quoting it verbatim.
        requirement:
          "Address risks unique to autonomous agents acting on untrusted data and tools — the core " +
          "threat this dataset's anchor id tracks.",
        synthex_mapping:
          "A CaMeL-style flow gate constrains react/Cognee actions, and scraped content is sealed " +
          "as evidence before any agent acts on it.",
        rag_status: "amber",
        basis: "A flow gate + sealed-before-act evidence address agentic data/tool misuse partially.",
      },
    ],
  },
  {
    framework: "MITRE ATLAS",
    // Canonical version string — tests assert "v5.6.0" literally.
    citation: "MITRE ATLAS v5.6.0",
    controls: [
      {
        // Anchor technique: AML.T0051 (LLM Prompt Injection).
        id: "AML.T0051",
        title: "AML.T0051 — LLM Prompt Injection",
        requirement:
          "Adversary crafts prompts that cause an LLM to behave in unintended ways via direct " +
          "input.",
        synthex_mapping:
          "The 3-tier injection defense (L1 regex → L2 guard → L3 AlignmentCheck) detects and " +
          "bounds injection in scraped content.",
        rag_status: "green",
        basis: "Direct prompt injection is detected and bounded by the 3-tier defense.",
      },
      {
        // .001 sub-technique: indirect (data-borne) prompt injection.
        id: "AML.T0051.001",
        title: "AML.T0051.001 — LLM Prompt Injection: Indirect",
        requirement:
          "Adversary injects an instruction into data the LLM later ingests (indirect / data-borne " +
          "prompt injection).",
        synthex_mapping:
          "Scraped pages are the exact indirect-injection surface Synthex gates: nonce-tagged " +
          "Spotlighting isolates untrusted content before classification.",
        rag_status: "green",
        basis: "Indirect, data-borne injection in scraped pages is the primary surface gated.",
      },
    ],
  },
]);

const VALID_RAG = Object.freeze(new Set(["green", "amber", "red", "n/a"]));

/**
 * Is this a valid honest RAG status?
 * @param {unknown} status
 * @returns {boolean}
 */
export function isValidRagStatus(status) {
  return typeof status === "string" && VALID_RAG.has(status);
}

/**
 * Flatten every control to a row tagged with its framework + citation. Pure, sync, returns new
 * objects (never the frozen source rows). Handy for table renderers and audit exports.
 * @returns {Array<ComplianceControl & {framework:string, citation:string}>}
 */
export function allControls() {
  return COMPLIANCE_FRAMEWORKS.flatMap((fw) =>
    fw.controls.map((c) => ({ ...c, framework: fw.framework, citation: fw.citation })),
  );
}

/**
 * Look up one framework by its short key (case-insensitive). Returns a NEW shallow copy or null.
 * @param {string} framework
 * @returns {ComplianceFramework | null}
 */
export function getFramework(framework) {
  const key = String(framework ?? "").toLowerCase();
  const fw = COMPLIANCE_FRAMEWORKS.find((f) => f.framework.toLowerCase() === key);
  return fw ? { ...fw, controls: fw.controls.map((c) => ({ ...c })) } : null;
}

/**
 * Select the controls relevant to a given Evidence Report, scoped by framework key(s). This is a
 * deliberately conservative selector: it does NOT invent applicability from payload heuristics
 * (that would over-claim). It returns the canonical, framework-mapped rows for the requested
 * frameworks so a page can render them consistently. Pure, sync, fail-safe, returns NEW objects.
 *
 * @param {object} [evidence]            a full report ({payload, contentHash, seal}); reserved for
 *                                       future evidence-driven scoping, unused today by design.
 * @param {object} [opts]
 * @param {string[]} [opts.frameworks]   framework keys to include (default: all).
 * @returns {Array<ComplianceControl & {framework:string, citation:string}>}
 */
export function selectControlsForReport(evidence, opts = {}) {
  const wanted = Array.isArray(opts.frameworks)
    ? new Set(opts.frameworks.map((f) => String(f).toLowerCase()))
    : null;
  return allControls().filter(
    (row) => wanted === null || wanted.has(row.framework.toLowerCase()),
  );
}
