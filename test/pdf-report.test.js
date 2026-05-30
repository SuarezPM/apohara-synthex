// Test del Evidence Report en PDF (6 páginas, framing 4-buyer). Valida que se genera un PDF real
// (magic %PDF) sin red, para los distintos shapes de evidence, y que el Risk Score es honesto.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildPDFReport, riskScore, riskScoreWeighted } from "../src/prove/pdf-report.js";

const baseEvidence = (overrides = {}) => ({
  payload: {
    target: "https://competitor.example",
    lens: "security",
    fetchedAt: "2026-05-27T00:00:00.000Z",
    sources: ["https://competitor.example"],
    blocked: [{ url: "https://x", reason: "prompt-injection" }],
    dedup: { uniqueBlocks: 2, duplicateBlocks: 1, bytesSaved: 4096, dedupRatio: 1 / 3 },
    findings: [{ url: "https://competitor.example", lens: "security", severity: 9, summary: "Breach expuesto.", signals: ["breach", "cve"] }],
    ...overrides.payload,
  },
  contentHash: "a".repeat(64),
  seal: { hmacSha256: "b".repeat(64), rfc3161Tsa: { standard: "RFC 3161", authority: "digicert", genTime: "2026-05-27T00:00:01Z", serial: "deadbeef" }, method: "HMAC-SHA256 + RFC 3161 TSA" },
  sealedAt: "2026-05-27T00:00:02.000Z",
  timings: { FETCH: 812.4, FORGE: 1.2, CLASSIFY: 430.9, PROVE: 95.3 },
  ...overrides,
});

function assertIsPdf(buf) {
  assert.ok(Buffer.isBuffer(buf), "debe ser Buffer");
  assert.ok(buf.length > 5000, `PDF demasiado chico para 6 páginas: ${buf.length} bytes`);
  assert.equal(buf.subarray(0, 5).toString("latin1"), "%PDF-", "debe empezar con el magic %PDF-");
}

test("pdf: genera un PDF válido (>5KB, 6 páginas) para evidence con TSA (shape plano)", async () => {
  const buf = await buildPDFReport(baseEvidence());
  assertIsPdf(buf);
});

test("pdf: genera un PDF válido para evidence HMAC-only (sin TSA)", async () => {
  const ev = baseEvidence();
  ev.seal = { hmacSha256: "b".repeat(64), rfc3161Tsa: null, method: "HMAC-SHA256" };
  const buf = await buildPDFReport(ev);
  assertIsPdf(buf);
});

test("pdf: genera un PDF válido para findings tri-lens (lens='all')", async () => {
  const ev = baseEvidence({
    payload: {
      target: "acme.com", lens: "all", sources: ["acme.com"], blocked: [],
      findings: [{ url: "acme.com", trilens: {
        gtm: { severity: 7, summary: "price cut", signals: ["pricing"] },
        finance: { severity: 4, summary: "vendor risk", signals: ["soc2"] },
        security: { severity: 9, summary: "exposed key", signals: ["secret"] },
      } }],
    },
  });
  const buf = await buildPDFReport(ev);
  assertIsPdf(buf);
});

test("pdf: genera un PDF válido sin dedup/timings (campos opcionales ausentes)", async () => {
  const ev = baseEvidence();
  delete ev.payload.dedup;
  delete ev.timings;
  const buf = await buildPDFReport(ev);
  assertIsPdf(buf);
});

test("riskScore: fórmula honesta sobre severidad máxima + bloqueos", () => {
  // maxSev=9 (70%) + blockTerm = min(1,5)/5*10 = 2 (30%) → round((9*0.7 + 2*0.3)*10) = round(69) = 69
  const r = riskScore(baseEvidence());
  assert.equal(r.maxSev, 9);
  assert.equal(r.blocked, 1);
  assert.equal(r.score, 69);
  assert.equal(r.band, "MEDIUM");
});

test("riskScore: trilens toma la severity máxima entre lentes", () => {
  const ev = baseEvidence({
    payload: {
      blocked: [],
      findings: [{ url: "a", trilens: { gtm: { severity: 3 }, finance: { severity: 4 }, security: { severity: 10 } } }],
    },
  });
  const r = riskScore(ev);
  assert.equal(r.maxSev, 10);
  assert.equal(r.blocked, 0);
  // round((10*0.7 + 0*0.3)*10) = 70 → HIGH
  assert.equal(r.score, 70);
  assert.equal(r.band, "HIGH");
});

test("riskScore: sin findings ni bloqueos → 0 / LOW", () => {
  const ev = baseEvidence({ payload: { findings: [], blocked: [] } });
  const r = riskScore(ev);
  assert.equal(r.score, 0);
  assert.equal(r.band, "LOW");
});

// v0.7.0 T9/L4 — regression test contra el Kiro audit que asume score=62.
// La fórmula real (pdf-report.js:56-57):
//   blockTerm = min(blocked, 5) / 5 * 10  = min(2,5)/5*10 = 4
//   score = round((maxSev * 0.7 + blockTerm * 0.3) * 10)
//         = round((8 * 0.7 + 4 * 0.3) * 10)
//         = round((5.6 + 1.2) * 10)
//         = round(68) = 68    ← NO 62
test("riskScore T9/L4: maxSev=8, blocked=2 → score=68 (NOT 62 — Kiro audit was arithmetically wrong)", () => {
  const ev = baseEvidence({
    payload: {
      blocked: [{ url: "https://x", reason: "x" }, { url: "https://y", reason: "y" }],
      findings: [{ url: "a", severity: 8, summary: "x", signals: [] }],
    },
  });
  const r = riskScore(ev);
  assert.equal(r.maxSev, 8, "fixture sanity: maxSev=8");
  assert.equal(r.blocked, 2, "fixture sanity: blocked=2");
  assert.equal(
    r.score,
    68,
    "REGRESSION: formula = round((maxSev*0.7 + min(blocked,5)/5*10*0.3)*10). Update this comment if you change the formula at src/prove/pdf-report.js:56-57.",
  );
  assert.equal(r.band, "MEDIUM");
});

// ─── R1: EPSS-weighted Risk Score (additive, opt-in, non-sealed) ──────────────

test("riskScoreWeighted: epssMap null/vacío → IDÉNTICo a riskScore base (opt-out no-op)", () => {
  const ev = baseEvidence();
  const base = riskScore(ev);
  const w0 = riskScoreWeighted(ev, null);
  const w1 = riskScoreWeighted(ev, new Map());
  assert.equal(w0.weighted, false);
  assert.equal(w0.score, base.score); // 69 — formula intacta
  assert.equal(w1.weighted, false);
  assert.equal(w1.score, base.score);
});

test("riskScoreWeighted: con CVE en el finding maxSev → score base intacto + weightedScore mayor", () => {
  const ev = baseEvidence(); // conserva blocked=1 (mutar findings post-construcción evita el footgun de overrides)
  ev.payload.findings = [{ url: "u", lens: "security", severity: 9, summary: "Log4Shell CVE-2021-44228", signals: ["CVE-2021-44228", "rce"] }];
  const base = riskScore(ev); // maxSev 9, blocked 1 → 69 (MEDIUM)
  const w = riskScoreWeighted(ev, new Map([["CVE-2021-44228", { epss: 0.94 }]]));
  assert.equal(w.weighted, true);
  assert.equal(w.score, base.score, "el score SELLADO/base no cambia");
  assert.equal(w.cve, "CVE-2021-44228");
  assert.ok(w.weightedScore > base.score, `weighted ${w.weightedScore} debe superar base ${base.score}`);
  assert.equal(w.weightedScore, 76); // min(10,9*1.282)=10 → round((10*0.7+2*0.3)*10)=76
  assert.equal(w.weightedBand, "HIGH");
});

test("riskScoreWeighted: maxSev sin CVE en el texto → weighted:false (best-effort, no inventa)", () => {
  const ev = baseEvidence(); // signals ["breach","cve"] — sin un CVE id real
  const w = riskScoreWeighted(ev, new Map([["CVE-2021-44228", { epss: 0.94 }]]));
  assert.equal(w.weighted, false);
});

test("pdf: render con opts.epssMap sigue produciendo un PDF válido (la línea extra no rompe layout)", async () => {
  const ev = baseEvidence();
  ev.payload.findings = [{ url: "u", lens: "security", severity: 9, summary: "CVE-2021-44228 RCE", signals: ["CVE-2021-44228"] }];
  const buf = await buildPDFReport(ev, { epssMap: new Map([["CVE-2021-44228", { epss: 0.94 }]]) });
  assertIsPdf(buf);
});
