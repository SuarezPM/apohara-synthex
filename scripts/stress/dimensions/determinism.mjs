// ============================================================================
// STRESS DIMENSION (6) — DETERMINISM. Pure + injectable. NO live run.
//
// Thesis: same input → same contentHash → same seal, modulo the timestamp.
// Synthex seals a canonical pre-image (src/prove/evidence-report.js): the
// contentHash is sha256 over the canonical payload, so identical content MUST
// collapse to exactly one contentHash across N runs. The only legitimate
// variation between two seals of the same bytes lives in the wall-clock /
// third-party fields (sealedAt, RFC 3161 TSA genTime+serial+token). Those are
// VOLATILE by construction and are stripped before comparing the seal.
//
// HONESTY (the moat): this module MEASURES, it does not assert a number. It
// runs an INJECTED `runFn` (a real pipeline sealer in the capstone, a stub in
// the suite), counts the distinct contentHashes it actually observed, and
// reports `deterministic` = (exactly one across N). It never fabricates a
// metric: if runFn yields two hashes for identical content, this reports
// deterministic:false with the evidence (the distinct hashes). Zero network —
// the harness's `--live` flag is irrelevant here; determinism runs fully
// offline.
//
// Reproduce (capstone): wire runFn = (input) => buildEvidence(payload(input),
// { hmacKey, signingKey, requestTsa:true }) and call checkDeterminism over the
// corpus with n>=2. In the suite it runs against a deterministic stub.
// ============================================================================

// Volatile fields that legitimately differ between two seals of identical
// content. Stripped from the seal pre-image before comparison so a TSA token /
// timestamp never masquerades as non-determinism. Frozen — read-only contract.
export const VOLATILE_FIELDS = Object.freeze([
  "sealedAt", // ISO wall-clock of the seal
  "genTime", // RFC 3161 TSA generation time
  "serial", // RFC 3161 TSA serial number
  "token", // RFC 3161 TSA token (carries genTime+serial)
  "timestamp", // generic per-run timestamp
  "tookMs", // per-run timing sample
  "latencyMs", // per-run timing sample
  "durationMs", // per-run timing sample
]);

// Recursively drop VOLATILE_FIELDS without mutating the input (deep copy).
// Used to derive the stable seal pre-image: everything that SHOULD be identical
// across runs of the same content. Pure.
function stripVolatile(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(stripVolatile);
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (VOLATILE_FIELDS.includes(k)) continue;
    out[k] = stripVolatile(v);
  }
  return out;
}

// Stable, key-order-independent serialization for the seal pre-image so that
// two structurally-equal objects compare equal regardless of key insertion
// order. Sorts object keys recursively. Pure; throws on cycles (fail-safe — a
// seal MUST be a finite acyclic object).
function stableStringify(value) {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value, seen = new WeakSet()) {
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) {
    throw new Error("determinism: seal object contains a cycle — cannot serialize");
  }
  seen.add(value);
  if (Array.isArray(value)) {
    const arr = value.map((v) => sortKeysDeep(v, seen));
    seen.delete(value);
    return arr;
  }
  const out = {};
  for (const k of Object.keys(value).sort()) {
    out[k] = sortKeysDeep(value[k], seen);
  }
  seen.delete(value);
  return out;
}

// Fail-safe extraction of the contentHash an evidence object exposes. The
// shipped shape is `{ contentHash: '<hex>' }`; a malformed run yields null
// rather than a fabricated value. NEVER invents a hash.
function extractContentHash(evidence) {
  if (!evidence || typeof evidence !== "object") return null;
  const ch = evidence.contentHash;
  return typeof ch === "string" && ch.length > 0 ? ch : null;
}

/**
 * Determinism dimension — pure, injectable, offline.
 *
 * Runs `runFn(input)` exactly `n` times, then measures how many DISTINCT
 * contentHashes were actually produced. Identical content must collapse to ONE
 * contentHash; the seal pre-image (minus VOLATILE_FIELDS) must likewise collapse
 * to one. `deterministic` is true iff both collapse to a single value across all
 * n runs AND every run produced a usable contentHash.
 *
 * This MEASURES — it does not assert. If runFn is non-deterministic, the result
 * reports it honestly (deterministic:false + the distinct hashes observed).
 *
 * @param {*} input            opaque input handed verbatim to every runFn call.
 * @param {(input:*) => object} runFn  injected sealer; returns an evidence-shaped
 *                                     object `{ contentHash, seal?, sealedAt?, ... }`.
 *                                     In the capstone this is the real pipeline
 *                                     seal; in the suite it is a stub. No live
 *                                     call is made by this module.
 * @param {number} [n=2]       number of runs (>=2 to be meaningful; >=1 enforced).
 * @returns {{
 *   runs: number,
 *   uniqueContentHashes: number,
 *   deterministic: boolean,
 *   contentHashes: string[],
 *   uniqueSealPreImages: number,
 *   nullRuns: number
 * }}
 */
export function checkDeterminism(input, runFn, n = 2) {
  if (typeof runFn !== "function") {
    throw new TypeError("checkDeterminism: runFn must be a function (injectable sealer)");
  }
  const runs = Number.isInteger(n) && n >= 1 ? n : 1;

  const contentHashes = [];
  const sealPreImages = [];
  let nullRuns = 0;

  for (let i = 0; i < runs; i++) {
    const evidence = runFn(input);
    const ch = extractContentHash(evidence);
    if (ch === null) {
      // Fail-safe: a run that did not produce a usable contentHash is recorded
      // honestly (it cannot count as a match). It poisons determinism on purpose.
      nullRuns += 1;
      continue;
    }
    contentHashes.push(ch);
    // Seal pre-image: the seal block stripped of volatile fields. If the run has
    // no `seal`, fall back to the whole evidence minus volatile fields so the
    // comparison still has something stable to anchor on.
    const sealSource = evidence && typeof evidence === "object" && evidence.seal !== undefined
      ? evidence.seal
      : evidence;
    sealPreImages.push(stableStringify(stripVolatile(sealSource)));
  }

  const uniqueContentHashes = new Set(contentHashes).size;
  const uniqueSealPreImages = new Set(sealPreImages).size;

  // Deterministic iff: every run produced a hash (no nulls), exactly one
  // distinct contentHash, and exactly one distinct seal pre-image.
  const deterministic =
    nullRuns === 0 &&
    contentHashes.length === runs &&
    uniqueContentHashes === 1 &&
    uniqueSealPreImages === 1;

  return Object.freeze({
    runs,
    uniqueContentHashes,
    deterministic,
    contentHashes: Object.freeze([...contentHashes]),
    uniqueSealPreImages,
    nullRuns,
  });
}

/**
 * Harness adapter — matches the `dimension` contract every run.mjs dimension
 * returns (`{ status, dimension, ... , reproduce }`). Runs checkDeterminism over
 * each corpus artifact with the injected sealer and aggregates. Pure w.r.t. the
 * network: the sealer is injected; this module makes no live call.
 *
 * @param {{ artifacts: ReadonlyArray<object> }} corpus  loaded corpus.
 * @param {(input:*) => object} runFn  injected per-artifact sealer.
 * @param {number} [n=2]               runs per artifact.
 */
export function runDeterminismDimension(corpus, runFn, n = 2) {
  const artifacts = corpus && Array.isArray(corpus.artifacts) ? corpus.artifacts : [];
  const perArtifact = artifacts.map((a) => checkDeterminism(a, runFn, n));
  const total = perArtifact.length;
  const deterministicCount = perArtifact.filter((r) => r.deterministic).length;
  const allDeterministic = total > 0 && deterministicCount === total;

  return Object.freeze({
    status: total > 0 ? "OK" : "NOT_IMPLEMENTED",
    dimension: "determinism",
    runs_per_artifact: n,
    artifacts: total,
    deterministic_artifacts: deterministicCount,
    all_deterministic: allDeterministic,
    detail:
      total > 0
        ? `${deterministicCount}/${total} artifacts produced one contentHash + one seal pre-image across ${n} runs (volatile fields stripped: ${VOLATILE_FIELDS.join(", ")})`
        : "no artifacts loaded — nothing to measure",
    reproduce:
      "node scripts/stress/run.mjs --manifest=scripts/stress/corpus.json --dimensions=determinism",
  });
}
