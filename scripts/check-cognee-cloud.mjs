#!/usr/bin/env node
// PROBE (gate-before-trust, item 2.3) — can Synthex wire a Cognee CLOUD memory backend with
// COGNEE_API_KEY? Default memory is local OSS (Apache-2.0, zero-lock-in). Cloud would be an
// EXPLICIT opt-in (COGNEE_CLOUD=1), DISTINCT from the COGNEE_REMOTE_URL guard (which stays a
// hard abort). This probe decides BUILD-vs-CUT: it only confirms a usable cloud surface if the
// endpoint answers with a programmatic JSON API — NOT if it merely serves the web dashboard.
//
//   set -a; source ~/.config/apohara/secrets.env; set +a
//   node scripts/check-cognee-cloud.mjs
const key = process.env.COGNEE_API_KEY;
if (!key) {
  console.log("FAIL — COGNEE_API_KEY not set. Cognee stays local OSS only (default).");
  process.exit(1);
}

const base = process.env.COGNEE_CLOUD_URL || "https://platform.cognee.ai/api";
try {
  const r = await fetch(`${base}/health`, {
    headers: { Authorization: `Bearer ${key}` },
    signal: AbortSignal.timeout(10000),
  });
  const ctype = r.headers.get("content-type") || "";
  const body = (await r.text()).trim();
  const isJsonApi = /application\/json/i.test(ctype) || body.startsWith("{") || body.startsWith("[");

  if (r.ok && isJsonApi) {
    console.log(`OK cloud reachable — ${base} returns a JSON API; tools: cognee cloud ingest/recall`);
    process.exit(0);
  }
  // Reachable but the response is the dashboard SPA (HTML), NOT a programmatic API with this key.
  console.log(`FAIL — ${base} is reachable (HTTP ${r.status}, content-type "${ctype || "?"}") but returns the`);
  console.log("       web DASHBOARD (HTML), not a programmatic JSON ingest API with this key.");
  console.log("DECISION (gate-before-trust): Cognee cloud backend NOT wired. Cognee stays LOCAL OSS only");
  console.log("(Apache-2.0, zero-lock-in, data-residency). The CaMeL gate (A1) covers the Cognee path");
  console.log("regardless of backend; the COGNEE_REMOTE_URL guard remains a hard abort. See HONESTY §10.5.");
  process.exit(1);
} catch (e) {
  console.log(`FAIL — ${base} unreachable: ${e.message}. Cognee stays local OSS only.`);
  process.exit(1);
}
