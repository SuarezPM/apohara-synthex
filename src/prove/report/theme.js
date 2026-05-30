// PROVE/report/theme — single source of truth for the Evidence Report design system
// (Option C: dark cover · light interior). Tokens are EXTRACTED from the deployed
// synthex.apohara.dev (public/index.html) and locked in docs/internal/EVIDENCE_REPORT_DESIGN.md
// with WCAG-verified contrast ratios — NOT invented here. Cover pulls COVER (dark on void),
// interior pulls PAPER (dark ink on bone). Both vs/interior reference ONE palette object.
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const fontsDir = resolve(here, "../../../assets/fonts");

// ── Color tokens (PDFKit RGB hex) — design spec §1, contrast verified ──────────

// Cover (dark) — bg `--void #090a10`. AA+ on void per the spec.
export const COVER = {
  bg: "#090a10",     // page bg (void)
  ink: "#EDEFF0",    // body / headline — 17.1:1 AAA
  violet: "#9775fa", // seal / heading accent — 5.87:1 AA
  lime: "#25B13F",   // verdict-ok / QR / fold rule — 7.0:1 AAA
  amber: "#e8a13a",  // REVIEW accent — 9.0:1 AAA
  red: "#e5484d",    // BLOCK / critical — 5.05:1 AA
  muted: "#888fb0",  // meta / labels (large text only)
};

// Interior (light) — paper `#FAFAF8`. Brand violet/lime DARKENED to pass AA on light.
export const PAPER = {
  bg: "#FAFAF8",     // page bg (bone)
  ink: "#1a1d29",    // body — 16.0:1 AAA
  muted: "#5a6080",  // secondary / labels
  violet: "#5733b8", // persona tag / headings / seal — 7.82:1 AAA
  green: "#17772a",  // RAG green / verified / OK — 5.42:1 AA
  red: "#c0392b",    // RAG red / BLOCK / FAIL — 5.20:1 AA
  amber: "#8a5a08",  // RAG amber / REVIEW / partial — 5.67:1 AA
  rule: "#e3e3df",   // hairline table / section rules
  zebra: "#f3f3f0",  // zebra row tint
  codebg: "#f0f0ec", // hash / command box bg (light, printable)
};

// ── Font role names — registered once in buildPDFReport via doc.registerFont ───
// Inter → body + headings; Mono → hashes/commands/IDs/numerics/kickers; Pixel →
// cover wordmark accent only (falls back to Mono if the Press Start 2P TTF is absent).
export const FONTS = {
  body: "Inter",          // Inter-Regular
  medium: "Inter-Medium",
  semibold: "Inter-SemiBold",
  bold: "Inter-Bold",
  mono: "Mono",           // JetBrains Mono Regular
  monoBold: "Mono-Bold",  // JetBrains Mono Bold
  pixel: "Pixel",         // cover wordmark accent only (optional)
};

// Absolute paths to the embedded TTFs (resolved from this module, not cwd).
export const FONT_FILES = {
  [FONTS.body]: resolve(fontsDir, "Inter-Regular.ttf"),
  [FONTS.medium]: resolve(fontsDir, "Inter-Medium.ttf"),
  [FONTS.semibold]: resolve(fontsDir, "Inter-SemiBold.ttf"),
  [FONTS.bold]: resolve(fontsDir, "Inter-Bold.ttf"),
  [FONTS.mono]: resolve(fontsDir, "JetBrainsMono-Regular.ttf"),
  [FONTS.monoBold]: resolve(fontsDir, "JetBrainsMono-Bold.ttf"),
  [FONTS.pixel]: resolve(fontsDir, "PressStart2P-Regular.ttf"), // optional; absent → falls back to Mono
};

// PDFKit built-in fallbacks if a TTF fails to register (design spec §2).
export const FONT_FALLBACK = {
  sans: "Helvetica",
  sansBold: "Helvetica-Bold",
  mono: "Courier",
  monoBold: "Courier-Bold",
};

// ── Type scale (PDF points) — design spec §2 ───────────────────────────────────
// Each entry: { font role, size, leading, optional tracking, optional case }.
export const TYPE = {
  coverWordmark: { font: FONTS.pixel, size: 22, leading: 30, tracking: 1 },
  coverVerdict: { font: FONTS.bold, size: 30, leading: 34 },
  h1: { font: FONTS.semibold, size: 19, leading: 24 },
  sectionTitle: { font: FONTS.semibold, size: 12.5, leading: 16, tracking: 0.4 },
  kicker: { font: FONTS.mono, size: 8.5, leading: 12, tracking: 1.4, upper: true },
  body: { font: FONTS.body, size: 9.5, leading: 14 },
  tableHeader: { font: FONTS.mono, size: 8, leading: 11, tracking: 0.6, upper: true },
  tableCell: { font: FONTS.body, size: 8.5, leading: 12 },
  tableNum: { font: FONTS.mono, size: 8.5, leading: 12 }, // numerics → Mono, right-aligned
  code: { font: FONTS.mono, size: 8, leading: 12 },
  footer: { font: FONTS.body, size: 7.5, leading: 10 },
};

// ── Page geometry — design spec §3. A4 595×842; margins 54 L/R/top, 64 bottom. ──
export const PAGE = {
  size: "A4",
  width: 595,
  height: 842,
  margins: { top: 54, bottom: 64, left: 54, right: 54 },
  textWidth: 595 - 54 - 54, // 487 pt — the column tables sum to
  baseline: 14,             // body grid
  sectionGap: 22,
  intraSection: 12,
  footerBand: 64,           // reserved bottom band for the footer
};

// ── Voice — design spec §6 (exact strings; never paraphrased) ──────────────────
export const VOICE = {
  coverSignature: "APOHARA SYNTHEX · everything signed, nothing trusted.",
  coverCouplet: "Screen what your agents ingest. Seal what they found.",
  verifyKicker: "VERIFY IT YOURSELF · RUN IT",
  // Verbatim footer disclaimer printed on every interior page (design spec §7).
  disclaimer:
    "The seal proves when these bytes existed and that they are unchanged — not that the claims are " +
    "true. Identity is self-signed (not a public trust-list certificate). Evidence record + mapping " +
    "aid, not legal advice. Full verification: page « Verify It Yourself ».",
};

// Report ID format — design spec §3: SYNTHEX-EVR-<8 hex of contentHash>.
export function reportIdOf(contentHash) {
  const hex = String(contentHash ?? "").slice(0, 8) || "00000000";
  return `SYNTHEX-EVR-${hex.toUpperCase()}`;
}

// Bundle both palettes + tokens behind one theme object so a page picks its variant once.
export const THEME = { COVER, PAPER, FONTS, TYPE, PAGE, VOICE };
