#!/usr/bin/env node
// PROBE (gate-before-trust, item 2.7 / D8) — confirm the Bright Data Web Scraper API async
// surface (trigger → snapshot_id → progress) BEFORE relying on the dataset adapter. Tries the
// `discover_new` collector first; if the dataset does not support it, falls back to a plain
// async trigger to confirm trigger→poll works. BILLING: at most ONE input is triggered.
//
//   set -a; source ~/.config/apohara/secrets.env; set +a
//   node scripts/probe-bd-dataset.mjs
import { BrightDataDatasetClient } from "../src/fetch/dataset-client.js";

const datasetId = process.env.BRIGHT_DATA_DATASET_ID;
if (!process.env.BRIGHT_DATA_TOKEN || !datasetId) {
  console.log("FAIL — BRIGHT_DATA_TOKEN / BRIGHT_DATA_DATASET_ID not set.");
  process.exit(1);
}
const c = new BrightDataDatasetClient();

async function tryTrigger(label, fn) {
  try {
    const res = await fn();
    const snap = res?.snapshot_id ?? null;
    if (!snap) return { ok: false, reason: `${label}: no snapshot_id in response (${JSON.stringify(res).slice(0, 100)})` };
    return { ok: true, snap, label };
  } catch (e) {
    return { ok: false, reason: `${label}: ${e.message}` };
  }
}

// 1) discover_new collector (the watchlist→delta source). 2) plain async trigger (1 URL) fallback.
let r = await tryTrigger("discover_new", () => c.triggerDiscoverNew({ url: "https://example.com" }, { discoverBy: "url" }));
if (!r.ok) r = await tryTrigger("trigger", () => c.trigger({ url: "https://example.com" }));

if (!r.ok) {
  console.log(`FAIL ${r.reason}`);
  console.log("DECISION (gate-before-trust): the async/discover_new surface is not confirmed for this dataset.");
  console.log("The trigger→poll→collect adapter is built + offline-tested; the LIVE discover_new path is declared, not claimed. HONESTY §10.6.");
  process.exit(1);
}

// Poll progress ONCE (no full collect → no extra billing) to confirm the progress surface.
let status = "?";
try { status = (await c.pollProgress(r.snap))?.status ?? "?"; } catch (e) { status = `progress-err: ${e.message}`; }
console.log(`OK surface=datasets/v3/${r.label} dataset_id=${datasetId} snapshot_id=${r.snap} progress=${status}`);
process.exit(0);
