// Tests del dataset de compliance — verifican que el módulo carga, que CADA framework lleva su
// citación canónica VERBATIM (sin parafrasear), que los ids están bien formados y son únicos, y
// que rag_status es honesto. Cero red, rápido (mapeo puro de datos).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  COMPLIANCE_FRAMEWORKS,
  MAPPING_DISCLAIMER,
  allControls,
  getFramework,
  selectControlsForReport,
  isValidRagStatus,
} from "../../src/prove/compliance-data.js";

const byKey = (key) => COMPLIANCE_FRAMEWORKS.find((f) => f.framework === key);

test("compliance-data: el módulo carga y exporta un dataset no vacío", () => {
  assert.ok(Array.isArray(COMPLIANCE_FRAMEWORKS));
  assert.ok(COMPLIANCE_FRAMEWORKS.length >= 7, "los 7 frameworks confirmados están presentes");
  for (const fw of COMPLIANCE_FRAMEWORKS) {
    assert.equal(typeof fw.framework, "string");
    assert.equal(typeof fw.citation, "string");
    assert.ok(Array.isArray(fw.controls) && fw.controls.length > 0);
  }
});

test("compliance-data: cada framework lleva su citación canónica VERBATIM", () => {
  // EU AI Act — el instrumento legal exacto.
  assert.ok(byKey("EU AI Act").citation.includes("Regulation (EU) 2024/1689"));
  // NIST AI RMF 1.0.
  assert.ok(byKey("NIST AI RMF").citation.includes("NIST AI RMF 1.0"));
  // NYDFS — la segunda enmienda + fecha efectiva exactas.
  assert.ok(byKey("NYDFS Part 500").citation.includes("23 NYCRR Part 500"));
  assert.ok(byKey("NYDFS Part 500").citation.includes("Second Amendment, effective Nov 1, 2023"));
  // SR 11-7 = OCC Bulletin 2011-12 (ambos nombres verbatim).
  assert.ok(byKey("SR 11-7").citation.includes("SR 11-7"));
  assert.ok(byKey("SR 11-7").citation.includes("OCC Bulletin 2011-12"));
  // OWASP LLM Top 10 — edición 2025.
  assert.ok(byKey("OWASP LLM Top 10").citation.includes("OWASP Top 10 for LLM Applications 2025"));
  // OWASP Agentic — edición 2026 (NO 2025) + id ASI01.
  assert.ok(byKey("OWASP Agentic Top 10").citation.includes("Agentic Applications 2026"));
  assert.ok(byKey("OWASP Agentic Top 10").citation.includes("2026"));
  assert.ok(!byKey("OWASP Agentic Top 10").citation.includes("2025"), "Agentic NO es 2025");
  // MITRE ATLAS — versión exacta.
  assert.ok(byKey("MITRE ATLAS").citation.includes("v5.6.0"));
});

test("compliance-data: títulos canónicos clave aparecen VERBATIM (no parafraseados)", () => {
  const titles = allControls().map((c) => c.title);
  // Art 12 es "Record-keeping", NO "logging".
  assert.ok(titles.some((t) => t.includes("Art 12") && t.includes("Record-keeping")));
  // Art 11 — "Technical documentation".
  assert.ok(titles.some((t) => t.includes("Art 11") && t.includes("Technical documentation")));
  // Art 13 — título completo.
  assert.ok(titles.some((t) =>
    t.includes("Transparency and provision of information to deployers")));
  // NIST anchor control MEASURE 2.5.
  assert.ok(allControls().some((c) => c.id === "NIST-AI-RMF-MEASURE-2.5"));
});

test("compliance-data: ids ancla de OWASP/ATLAS presentes", () => {
  const ids = new Set(allControls().map((c) => c.id));
  assert.ok(ids.has("LLM01"), "OWASP LLM Top 10 LLM01");
  assert.ok(ids.has("ASI01"), "OWASP Agentic 2026 ASI01");
  assert.ok(ids.has("AML.T0051"), "ATLAS LLM Prompt Injection");
  assert.ok(ids.has("AML.T0051.001"), "ATLAS indirect (.001)");
});

test("compliance-data: ids de control bien formados y SIN duplicados", () => {
  const ids = allControls().map((c) => c.id);
  // Well-formed: non-empty, no whitespace, uppercase-ish grammar (letters, digits, . and -).
  for (const id of ids) {
    assert.equal(typeof id, "string");
    assert.ok(id.length > 0, "id no vacío");
    assert.match(id, /^[A-Z0-9][A-Z0-9.\-]*$/, `id mal formado: ${id}`);
  }
  // No duplicates across the whole dataset.
  assert.equal(new Set(ids).size, ids.length, "no hay control ids duplicados");
});

test("compliance-data: rag_status es honesto (green|amber|red|n/a) con basis", () => {
  for (const c of allControls()) {
    assert.ok(isValidRagStatus(c.rag_status), `rag_status inválido en ${c.id}: ${c.rag_status}`);
    assert.equal(typeof c.basis, "string");
    assert.ok(c.basis.length > 0, `falta basis en ${c.id}`);
    assert.equal(typeof c.requirement, "string");
    assert.ok(c.requirement.length > 0, `falta requirement en ${c.id}`);
    assert.equal(typeof c.synthex_mapping, "string");
    assert.ok(c.synthex_mapping.length > 0, `falta synthex_mapping en ${c.id}`);
  }
  // El disclaimer encuadra todo como mapeo, NO endorsement.
  assert.match(MAPPING_DISCLAIMER, /NOT endorsement/);
});

test("compliance-data: isValidRagStatus rechaza valores fuera de vocabulario", () => {
  assert.ok(isValidRagStatus("green"));
  assert.ok(isValidRagStatus("n/a"));
  assert.ok(!isValidRagStatus("yellow"));
  assert.ok(!isValidRagStatus("GREEN"));
  assert.ok(!isValidRagStatus(undefined));
});

test("compliance-data: getFramework devuelve una copia (no muta la fuente congelada)", () => {
  const fw = getFramework("eu ai act"); // case-insensitive
  assert.ok(fw, "encuentra EU AI Act sin importar el caso");
  assert.equal(fw.framework, "EU AI Act");
  // Mutar la copia no debe tocar la fuente.
  fw.controls[0].title = "MUTATED";
  assert.notEqual(byKey("EU AI Act").controls[0].title, "MUTATED");
  assert.equal(getFramework("does-not-exist"), null);
});

test("compliance-data: selectControlsForReport filtra por framework y devuelve copias nuevas", () => {
  const all = selectControlsForReport({});
  assert.equal(all.length, allControls().length, "sin filtro → todos los controles");

  const only = selectControlsForReport({}, { frameworks: ["MITRE ATLAS"] });
  assert.ok(only.length >= 2);
  assert.ok(only.every((c) => c.framework === "MITRE ATLAS"));

  // Cada fila lleva su citación (para que la página la renderice sin re-buscar).
  assert.ok(only.every((c) => c.citation.includes("v5.6.0")));

  // Returned rows are new objects, not the frozen source rows.
  only[0].rag_status = "red";
  assert.notEqual(byKey("MITRE ATLAS").controls[0].rag_status, "red");

  // Framework desconocido → vacío, sin lanzar.
  assert.deepEqual(selectControlsForReport({}, { frameworks: ["nope"] }), []);
});
