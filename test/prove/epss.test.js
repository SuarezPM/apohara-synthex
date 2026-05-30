// Tests de EPSS enrichment (R1) — 100% offline, fetchImpl inyectado, sin red ni secrets.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractCveIds, cveIdsFromFinding, fetchEpss, epssWeight, EPSS_RE } from "../../src/prove/epss.js";

// Response-like helper for injected fetchImpl.
const resp = (body, ok = true, status = 200) => ({ ok, status, json: async () => body });

test("extractCveIds: dedup + uppercase, ignora basura", () => {
  assert.deepEqual(
    extractCveIds(["see CVE-2021-44228 and cve-2017-5638", "no cve here", "CVE-2021-44228"]),
    ["CVE-2021-44228", "CVE-2017-5638"],
  );
  assert.deepEqual(extractCveIds(["nothing", ""]), []);
  assert.deepEqual(extractCveIds([]), []);
});

test("cveIdsFromFinding: extrae de summary + signals (dedup)", () => {
  const ids = cveIdsFromFinding({ summary: "Log4Shell CVE-2021-44228", signals: ["CVE-2021-44228", "breach"] });
  assert.deepEqual(ids, ["CVE-2021-44228"]);
});

test("fetchEpss happy path: parsea epss/percentile a NÚMERO", async () => {
  const fetchImpl = async () => resp({ status: "OK", data: [{ cve: "CVE-2021-44228", epss: "0.943580000", percentile: "0.999640000" }] });
  const m = await fetchEpss(["CVE-2021-44228"], { fetchImpl });
  assert.ok(m.get("CVE-2021-44228"));
  assert.equal(typeof m.get("CVE-2021-44228").epss, "number");
  assert.ok(Math.abs(m.get("CVE-2021-44228").epss - 0.94358) < 1e-6);
});

test("fetchEpss ORDER-INDEPENDENCE: indexa por data[].cve, no por posición (regresión del gate)", async () => {
  // La API NO preserva el orden — el response viene en orden distinto al request.
  const fetchImpl = async () => resp({ data: [
    { cve: "CVE-2017-5638", epss: "0.5", percentile: "0.9" },
    { cve: "CVE-2021-44228", epss: "0.94", percentile: "0.99" },
  ] });
  const m = await fetchEpss(["CVE-2021-44228", "CVE-2017-5638"], { fetchImpl });
  assert.equal(m.get("CVE-2021-44228").epss, 0.94);
  assert.equal(m.get("CVE-2017-5638").epss, 0.5);
});

test("fetchEpss unknown/empty data → Map vacío, sin throw", async () => {
  const m = await fetchEpss(["CVE-0000-00000"], { fetchImpl: async () => resp({ data: [] }) });
  assert.equal(m.size, 0);
});

test("fetchEpss FAIL-SAFE: error/500/non-JSON/abort → Map vacío, NUNCA lanza", async () => {
  const throws = async () => { throw new Error("network down"); };
  const http500 = async () => resp({}, false, 500);
  const badJson = async () => ({ ok: true, status: 200, json: async () => { throw new Error("bad json"); } });
  for (const fetchImpl of [throws, http500, badJson]) {
    const m = await fetchEpss(["CVE-2021-44228"], { fetchImpl });
    assert.equal(m.size, 0);
  }
});

test("fetchEpss sin ids → Map vacío y NO llama a la red (call-count 0)", async () => {
  let calls = 0;
  const m = await fetchEpss([], { fetchImpl: async () => { calls++; return resp({ data: [] }); } });
  assert.equal(m.size, 0);
  assert.equal(calls, 0, "no debe haber red cuando no hay nada que buscar");
});

test("epssWeight: factor = 1 + 0.3*epss; multi-CVE → MAX epss; sin match → factor 1", () => {
  const m = new Map([["CVE-2021-44228", { epss: 0.94 }], ["CVE-2017-5638", { epss: 0.5 }]]);
  const w = epssWeight(m, ["CVE-2021-44228", "CVE-2017-5638"]);
  assert.ok(Math.abs(w.factor - (1 + 0.3 * 0.94)) < 1e-9);
  assert.equal(w.epss, 0.94); // max
  assert.equal(w.cve, "CVE-2021-44228");
  const none = epssWeight(m, ["CVE-9999-9999"]);
  assert.equal(none.factor, 1);
  assert.equal(none.epss, null);
});
