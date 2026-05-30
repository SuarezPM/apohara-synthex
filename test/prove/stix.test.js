// Tests del export STIX 2.1 — mapeo puro de findings → indicators + report, con el
// contentHash sellado + keyId Ed25519 en external_references (liga el bundle a la evidencia).
import { test } from "node:test";
import assert from "node:assert/strict";
import { toStixBundle } from "../../src/prove/stix.js";

const SAMPLE = {
  contentHash: "abc123",
  seal: { signature: { keyId: "key-xyz" } },
  payload: {
    target: "Competitor X",
    lens: "security",
    fetchedAt: "2026-05-30T00:00:00.000Z",
    findings: [
      { url: "https://a.example", lens: "security", severity: 9, summary: "leaked creds", signals: ["cred-leak", "exfil"] },
      { url: "https://b.example", lens: "security", severity: 4, summary: "cve mention", signals: ["CVE-2021-44228"] },
    ],
  },
};

test("stix: bundle 2.1 válido con report + un indicator por finding", () => {
  let i = 0;
  const bundle = toStixBundle(SAMPLE, { newId: () => `id${i++}` });
  assert.equal(bundle.type, "bundle");
  assert.equal(bundle.spec_version, "2.1");
  const report = bundle.objects.find((o) => o.type === "report");
  const inds = bundle.objects.filter((o) => o.type === "indicator");
  assert.ok(report, "hay un report SDO");
  assert.equal(inds.length, 2);
  assert.equal(report.object_refs.length, 2, "el report referencia ambos indicators");
  assert.equal(report.report_types[0], "threat-report");
});

test("stix: external_references llevan el contentHash sellado + keyId", () => {
  const bundle = toStixBundle(SAMPLE);
  for (const o of bundle.objects) {
    const ref = o.external_references.find((r) => r.external_id === "abc123");
    assert.ok(ref, "cada objeto liga al contentHash sellado");
    assert.match(ref.description, /key-xyz/, "y al keyId Ed25519");
  }
});

test("stix: indicator usa pattern STIX + confidence derivada de severity", () => {
  const bundle = toStixBundle(SAMPLE);
  const inds = bundle.objects.filter((o) => o.type === "indicator");
  assert.equal(inds[0].pattern_type, "stix");
  assert.match(inds[0].pattern, /^\[url:value = '/);
  assert.equal(inds[0].spec_version, "2.1");
  assert.ok(inds.some((o) => o.confidence === 90), "severity 9 → confidence 90");
});

test("stix: todo id lleva prefijo de tipo (bundle-- / report-- / indicator--)", () => {
  const bundle = toStixBundle(SAMPLE);
  assert.match(bundle.id, /^bundle--/);
  assert.ok(bundle.objects.every((o) => o.id.startsWith(`${o.type}--`)));
});

test("stix: lens='all' (trilens) → un indicator por lente", () => {
  const triEvidence = {
    contentHash: "h",
    payload: {
      target: "t",
      lens: "all",
      fetchedAt: "2026-05-30T00:00:00.000Z",
      findings: [{ url: "https://x.example", trilens: { gtm: { severity: 5, summary: "g", signals: ["a"] }, security: { severity: 8, summary: "s", signals: ["b"] } } }],
    },
  };
  const bundle = toStixBundle(triEvidence);
  assert.equal(bundle.objects.filter((o) => o.type === "indicator").length, 2);
});
