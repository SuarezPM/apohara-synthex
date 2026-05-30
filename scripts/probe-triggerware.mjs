#!/usr/bin/env node
// PROBE (gate-before-trust, item 2.4) — confirm TriggerWare is reachable before relying on the
// react loop's delta source. GET /triggers (the real surface: https://api.triggerware.com,
// header Api-Key). Prints `OK ... 200 ...` or `FAIL <reason>`. NEVER builds on a failed probe.
//
//   set -a; source ~/.config/apohara/secrets.env; set +a
//   node scripts/probe-triggerware.mjs
import { TriggerWareClient } from "../src/trigger/triggerware-client.js";

if (!process.env.TRIGGERWARE_API_KEY) {
  console.log("FAIL — TRIGGERWARE_API_KEY not set (source ~/.config/apohara/secrets.env)");
  process.exit(1);
}

try {
  const triggers = await new TriggerWareClient().listTriggers();
  const n = Array.isArray(triggers) ? triggers.length : "?";
  console.log(`OK GET /triggers → 200 (${n} trigger(s)) — TriggerWare reachable, react delta source live`);
  process.exit(0);
} catch (e) {
  console.log(`FAIL GET /triggers — ${e.message}`);
  console.log("react loop falls back to its current single-URL / TriggerWare-less state (declared).");
  process.exit(1);
}
