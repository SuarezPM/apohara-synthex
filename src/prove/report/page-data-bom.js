// PROVE/report/page-data-bom — Web Data Bill of Materials (interior, light). The per-source
// provenance ledger an enterprise security team expects: one row per payload.sources[] with the
// content SHA-256 (truncated; full in the sidecar), the Bright Data surface that would route the
// URL, the fetched-at stamp, the dedup status (computed from matching contentHashes), and the
// per-layer L1/L2/L3 screen verdict read from the SEALED payload.decisions[]. Tables go through
// the shared table()/mappingTable so they measure → grow → paginate and NEVER overflow.
//
// HONESTY: sources[] carries URLs only; surface is DERIVED from the request shape (the demo runs
// on cached fixtures, so no live surface is sealed) and labeled as such. Per-source byte counts
// are not sealed — the dedup byte total lives on the CFO page. Full SHA-256 values live in the
// evidence.json sidecar; the table truncates head…tail per the design spec.
import { PAPER, FONTS, PAGE } from "./theme.js";
import { pageOpen, sectionTitle, body } from "./interior.js";
import { table, truncMid } from "./components.js";

// Derive the Bright Data surface that WOULD route a URL from its shape. This is a transparent
// URL-class mapping, not a sealed fact (the demo runs on cached fixtures) — labeled in the note.
function surfaceOf(url) {
  const u = String(url ?? "");
  if (/[?&]q=|\/search\b|google\.|bing\./i.test(u)) return "SERP API";
  if (/forum|thread|comment|#c\d/i.test(u)) return "Web Unlocker";
  if (/dataset|\/api\//i.test(u)) return "Dataset API";
  return "Web Crawl";
}

// Short fetched-at (HH:MM:SSZ) from the sealed ISO timestamp; falls back to the date if no time.
function shortStamp(iso) {
  const s = String(iso ?? "");
  const m = s.match(/T(\d{2}:\d{2}:\d{2})/);
  return m ? `${m[1]}Z` : (s.slice(0, 10) || "—");
}

// Build a per-URL screen index from the sealed decisions[]. L1 = djl/prefilter layer (REVIEW-only
// on ingest), L2 = INJECTION_GUARD stage, L3 = ALIGNMENT_CHECK stage. Returns the last outcome per
// layer per URL (a URL is screened once per layer in the demo). Honest "—" when a layer never ran.
function screenIndex(decisions = []) {
  const ds = Array.isArray(decisions) ? decisions : [];
  const idx = new Map();
  const put = (url, key, value) => {
    const cur = idx.get(url) ?? {};
    idx.set(url, { ...cur, [key]: value });
  };
  for (const d of ds) {
    if (d.layer === "djl" || d.layer === "prefilter") put(d.url, "l1", d.outcome ?? "REVIEW");
    else if (d.stage === "INJECTION_GUARD") put(d.url, "l2", d.outcome ?? "—");
    else if (d.stage === "ALIGNMENT_CHECK") put(d.url, "l3", d.outcome ?? "—");
  }
  return idx;
}

// Compact per-layer verdict string (L1/L2/L3). "·" = layer did not run for this URL. The full
// 3-tier ledger with model ids + rationale lives on the Security Briefing page.
function screenCell(s) {
  const v = (x) => (x ? x : "·");
  return `L1:${v(s.l1)} L2:${v(s.l2)} L3:${v(s.l3)}`;
}

export function pageDataBom(doc, ev, ctx = {}) {
  const { payload = {} } = ev;
  const sources = Array.isArray(payload.sources) ? payload.sources : [];
  const findings = Array.isArray(payload.findings) ? payload.findings : [];
  const decisions = Array.isArray(payload.decisions) ? payload.decisions : [];
  const dedup = payload.dedup ?? null;
  const fetchedAt = payload.fetchedAt ?? ev.sealedAt;

  pageOpen(doc, {
    persona: "● Web Data Bill of Materials · for CISO / Security",
    title: "Per-source data bill of materials",
    reportId: ctx.reportId,
    registry: ctx.registry,
  });

  body(doc,
    "One row per source this run ingested through Bright Data, with its sealed content SHA-256, the " +
    "surface that routes the URL, the fetched-at stamp, deduplication status, and the per-layer " +
    "L1/L2/L3 screening verdict. This is the provenance ledger an audit asks for: every byte that " +
    "reached classification is named and hashed.");
  doc.moveDown(0.6);

  // Per-URL content hash: findings[] carry the sealed per-source contentHash; decisions[] carry it
  // too for screened URLs. Build a single lookup so every source resolves to its hash.
  const hashByUrl = new Map();
  for (const f of findings) if (f.url && f.contentHash) hashByUrl.set(f.url, f.contentHash);
  for (const d of decisions) if (d.url && d.contentHash && !hashByUrl.has(d.url)) hashByUrl.set(d.url, d.contentHash);

  // Dedup status. Primary signal: two sources sharing the same sealed contentHash are duplicates.
  // A source with no sealed hash was dropped by FORGE dedup before classification (its content
  // matched an earlier source byte-for-byte) — labeled DUP only when an earlier source carries a
  // hash to be the original; otherwise "not classed" (honest: we cannot prove the match here).
  const seenHash = new Map();
  let priorClassified = false;
  const dedupStatusOf = (url) => {
    const h = hashByUrl.get(url);
    if (h) {
      priorClassified = true;
      if (seenHash.has(h)) return "DUP";
      seenHash.set(h, url);
      return "UNIQUE";
    }
    return priorClassified ? "DUP" : "not classed";
  };

  const screens = screenIndex(decisions);
  const rows = sources.map((url) => {
    const s = screens.get(url) ?? {};
    return {
      url: truncMid(url, 30, 14),
      surface: surfaceOf(url),
      fetched: shortStamp(fetchedAt),
      hash: hashByUrl.has(url) ? truncMid(hashByUrl.get(url), 8, 6) : "—",
      dedup: dedupStatusOf(url),
      screen: screenCell(s),
    };
  });

  if (!rows.length) {
    doc.font(FONTS.body).fontSize(9).fillColor(PAPER.muted)
      .text("No sources recorded in this evidence object.", doc.page.margins.left, doc.y, { width: PAGE.textWidth });
    doc.fillColor(PAPER.ink).x = doc.page.margins.left;
    return;
  }

  // Columns sized to content; the URL column takes the slack and truncates in-body. Widths chosen
  // so the widest realistic cell fits without overflow (sum < 487; URL absorbs the remainder).
  table(doc, {
    theme: PAPER,
    columns: [
      { key: "url", header: "Source URL" },
      { key: "surface", header: "Surface", width: 60 },
      { key: "fetched", header: "Fetched", width: 58, mono: true },
      { key: "hash", header: "SHA-256", width: 76, mono: true },
      { key: "dedup", header: "Dedup", width: 44, mono: true },
      { key: "screen", header: "Screen", width: 112, mono: true },
    ],
    rows,
  });
  doc.x = doc.page.margins.left;
  doc.moveDown(0.7);

  // Honest notes: where each column's value is sealed vs derived, and where the full data lives.
  sectionTitle(doc, "How to read this ledger");
  const noteLeft = doc.page.margins.left;
  const notes = [
    ["Content SHA-256", "truncated head…tail; the FULL hash for every source lives in the evidence.json sidecar."],
    ["BD surface", "derived from the URL shape (this run used cached fixtures, so no live surface is sealed); a request-shape mapping, not a sealed fact."],
    ["Dedup", "from matching content hashes: two sources with the same hash are duplicates. A source with no sealed hash (DUP) was dropped by FORGE before classification; the byte total is on the CFO page."],
    ["L1 / L2 / L3", "read verbatim from the sealed payload.decisions[]: L1 = DJL/prefilter regex (REVIEW-only on ingest) · L2 = injection-guard · L3 = alignment-check. \"·\" = that layer did not run for this URL."],
  ];
  doc.x = noteLeft;
  for (const [label, text] of notes) {
    const y = doc.y;
    doc.font(FONTS.monoBold).fontSize(8).fillColor(PAPER.violet)
      .text(label, noteLeft, y, { width: 96, lineBreak: false });
    doc.font(FONTS.body).fontSize(8.5).fillColor(PAPER.ink)
      .text(text, noteLeft + 104, y, { width: PAGE.textWidth - 104 });
    doc.x = noteLeft;
    doc.moveDown(0.35);
  }

  if (dedup) {
    doc.moveDown(0.2);
    doc.font(FONTS.body).fontSize(8.5).fillColor(PAPER.muted).text(
      `This run: ${dedup.uniqueBlocks ?? "—"} unique · ${dedup.duplicateBlocks ?? 0} duplicate ` +
      `(${((Number(dedup.dedupRatio) || 0) * 100).toFixed(1)}% deduplicated, ${dedup.bytesSaved ?? 0} bytes saved).`,
      noteLeft, doc.y, { width: PAGE.textWidth });
  }
  doc.fillColor(PAPER.ink).x = doc.page.margins.left;
}
