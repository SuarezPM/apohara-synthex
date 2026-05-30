// Test P2.6a — the Red-Team Evidence Report page renderer (src/prove/report/page-redteam.js).
// Renders into an in-memory PDFKit doc with (a) a fixture carrying sealed REDTEAM_* rows and (b)
// one with none. Asserts the page does not throw, registers a footer for its page, and — proven
// IN-PROCESS, not by grepping the compressed PDF stream — that the page reads payload.decisions[].
// Fast + zero network (PDFKit is fully in-memory; no live service is touched).
import { test } from "node:test";
import assert from "node:assert/strict";
import PDFDocument from "pdfkit";
import { PAGE, FONTS } from "../../src/prove/report/theme.js";
import { makeFooterRegistry } from "../../src/prove/report/components.js";
import { pageRedteam } from "../../src/prove/report/page-redteam.js";

// Alias every brand font ROLE name (Inter/Mono/…) to a PDFKit built-in, exactly as pdf-report's
// registerFonts() does on the TTF-missing path. doc.font("Mono") otherwise tries to open a file
// named "Mono". No TTFs needed — this is a render smoke test, not a glyph-fidelity test.
const BUILTIN_FOR_ROLE = {
  [FONTS.body]: "Helvetica", [FONTS.medium]: "Helvetica", [FONTS.semibold]: "Helvetica-Bold",
  [FONTS.bold]: "Helvetica-Bold", [FONTS.mono]: "Courier", [FONTS.monoBold]: "Courier-Bold",
  [FONTS.pixel]: "Courier",
};

// A throwaway in-memory doc, set up like buildPDFReport (bufferPages so footer registration via the
// registry is valid).
function makeDoc() {
  const doc = new PDFDocument({
    size: PAGE.size, margins: PAGE.margins, bufferPages: true, autoFirstPage: false,
  });
  for (const [role, builtin] of Object.entries(BUILTIN_FOR_ROLE)) doc.registerFont(role, builtin);
  doc.on("data", () => {}); // drain so the stream never back-pressures
  doc.addPage();
  return doc;
}

// Sealed 5-lens red-team rows as they land in payload.decisions[] (stage:"REDTEAM_<KEY>"), mirroring
// the shape src/redteam/index.js seals: persona/name/risk/concerns/rationale/grounding/degraded.
function redteamDecisions() {
  return [
    { stage: "REDTEAM_CFO", persona: "CFO", name: "Chief Financial Officer", risk: 82,
      concerns: ["Cash runway under 6 months at the stated $2.1M/mo burn"], rationale: "Going-concern risk.", degraded: false },
    { stage: "REDTEAM_Market", persona: "Market", name: "Market Analyst", risk: 55,
      concerns: ["TAM assumes 100% conversion of a $40B figure"], rationale: "TAM realism.", degraded: false },
    { stage: "REDTEAM_Legal", persona: "Legal", name: "General Counsel", risk: 40,
      concerns: ["Pending patent litigation under-disclosed"], rationale: "IP exposure.", degraded: false },
    { stage: "REDTEAM_Competitor", persona: "Competitor", name: "Competitive Strategist", risk: 30,
      concerns: [], rationale: "Moat appears defensible.", degraded: false },
    { stage: "REDTEAM_Execution", persona: "Execution", name: "Operating Partner", risk: 20,
      concerns: [], rationale: "Team depth adequate.", degraded: true },
  ];
}

// Fixture evidence with red-team rows. payload.decisions is a Proxy that records every read of the
// array (any index/length/iterator/method access) into `seen` — this is how we prove IN-PROCESS that
// the page actually consumed the rows, without grepping the compressed PDF bytes.
function withRedteam() {
  const seen = { read: false };
  const base = redteamDecisions();
  const decisions = new Proxy(base, {
    get(target, prop, receiver) {
      seen.read = true;
      return Reflect.get(target, prop, receiver);
    },
  });
  const ev = { contentHash: "a".repeat(64), payload: { target: "https://example.com/s1", decisions } };
  return { ev, seen };
}

// Fixture evidence with NO red-team rows (other stages present, but no REDTEAM_*).
function withoutRedteam() {
  return {
    contentHash: "b".repeat(64),
    payload: {
      target: "https://example.com/plain",
      decisions: [{ stage: "ALIGNMENT_CHECK", url: "https://example.com/x", outcome: "ALLOW" }],
    },
  };
}

test("pageRedteam: renders red-team rows without throwing and registers a footer", () => {
  const doc = makeDoc();
  const registry = makeFooterRegistry();
  const { ev } = withRedteam();
  const before = doc.bufferedPageRange().count;

  assert.doesNotThrow(() => pageRedteam(doc, ev, { reportId: "SYNTHEX-EVR-AAAAAAAA", registry }));

  // The page registered exactly one footer entry, pinned to the page it drew on.
  assert.equal(registry.length, 1, "expected one footer registration");
  assert.equal(registry[0].reportId, "SYNTHEX-EVR-AAAAAAAA");
  assert.equal(registry[0].dark, false, "interior pages register a light footer");
  assert.equal(registry[0].pageIndex, before - 1, "footer pinned to the current page");
});

test("pageRedteam: actually reads payload.decisions[] (proven in-process, not via the PDF bytes)", () => {
  const doc = makeDoc();
  const registry = makeFooterRegistry();
  const { ev, seen } = withRedteam();

  pageRedteam(doc, ev, { reportId: "SYNTHEX-EVR-AAAAAAAA", registry });

  assert.equal(seen.read, true, "page must read payload.decisions[] to reconstruct the red-team");
});

test("pageRedteam: no red-team rows → honest note, no throw, still registers a footer", () => {
  const doc = makeDoc();
  const registry = makeFooterRegistry();
  const ev = withoutRedteam();

  assert.doesNotThrow(() => pageRedteam(doc, ev, { reportId: "SYNTHEX-EVR-BBBBBBBB", registry }));
  assert.equal(registry.length, 1, "the no-data page still registers its footer");
  assert.equal(registry[0].reportId, "SYNTHEX-EVR-BBBBBBBB");
});

test("pageRedteam: empty/absent payload does not throw (fail-safe) and registers a footer", () => {
  const doc = makeDoc();
  const registry = makeFooterRegistry();

  assert.doesNotThrow(() => pageRedteam(doc, {}, { reportId: "SYNTHEX-EVR-CCCCCCCC", registry }));
  assert.equal(registry.length, 1);
});
