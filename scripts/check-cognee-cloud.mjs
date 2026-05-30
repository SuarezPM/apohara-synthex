#!/usr/bin/env node
// PROBE (gate-before-trust, item 2.3 / R6) — confirm the Cognee CLOUD tenant REST API is reachable
// + authenticated BEFORE relying on the cloud memory backend. Default memory is local OSS; cloud is
// an EXPLICIT opt-in (COGNEE_CLOUD=1). The TENANT endpoint (https://tenant-<id>.aws.cognee.ai) is a
// real JSON API authenticated with X-Api-Key + X-Tenant-Id — NOT the platform.cognee.ai dashboard
// (that earlier probe hit the SPA; the tenant API is the programmatic surface).
//
//   set -a; source ~/.config/apohara/secrets.env; set +a
//   COGNEE_API_URL=https://tenant-<id>.aws.cognee.ai COGNEE_TENANT_ID=<id> node scripts/check-cognee-cloud.mjs
const apiUrl = (process.env.COGNEE_API_URL ?? "").replace(/\/+$/, "");
const tenantId = process.env.COGNEE_TENANT_ID;
const apiKey = process.env.COGNEE_API_KEY;

if (!apiUrl || !tenantId || !apiKey) {
  console.log("FAIL — set COGNEE_API_URL (tenant base), COGNEE_TENANT_ID, COGNEE_API_KEY. Cognee stays local OSS only.");
  process.exit(1);
}

const H = { "X-Api-Key": apiKey, "X-Tenant-Id": tenantId };
try {
  const health = await fetch(`${apiUrl}/api/health`, { headers: H, signal: AbortSignal.timeout(10000) });
  const ctype = health.headers.get("content-type") || "";
  if (!health.ok || !/json/i.test(ctype)) {
    console.log(`FAIL — ${apiUrl}/api/health → HTTP ${health.status} (${ctype || "?"}); not a JSON API. Cognee stays local OSS only.`);
    process.exit(1);
  }
  // Authenticated read to prove the key/tenant work (datasets list is read-only).
  const ds = await fetch(`${apiUrl}/api/v1/datasets/`, { headers: H, signal: AbortSignal.timeout(10000) });
  if (!ds.ok) {
    console.log(`FAIL — auth check ${apiUrl}/api/v1/datasets/ → HTTP ${ds.status}. Check COGNEE_API_KEY / COGNEE_TENANT_ID.`);
    process.exit(1);
  }
  const list = await ds.json();
  const names = Array.isArray(list) ? list.map((d) => d.name).join(", ") : "?";
  console.log(`OK cloud reachable — ${apiUrl} JSON API authenticated (X-Api-Key + X-Tenant-Id); tools: add_text, cognify, search, datasets [${names}]`);
  process.exit(0);
} catch (e) {
  console.log(`FAIL — ${apiUrl} unreachable: ${e.message}. Cognee stays local OSS only.`);
  process.exit(1);
}
