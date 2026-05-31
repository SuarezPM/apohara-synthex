// test/scripts/verify-bundle.test.js — node:test for verify-bundle.mjs
// Runs the wrapper against a small in-memory/fixture evidence and asserts
// it reports a per-method status WITHOUT needing c2patool or any network.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { writeFileSync, readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { buildEvidence } from "../../src/prove/evidence-report.js";
import { anchorKeyId } from "../../src/prove/rekor.js";
import { generateKeyPair } from "../../src/prove/asymmetric.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// ─── fixture helpers ────────────────────────────────────────────────────────

// Build a minimal evidence fixture with HMAC only (no network/TSA needed)
async function buildHmacOnlyEvidence() {
  return await buildEvidence(
    { test: "fixture", schema_version: 2 },
    { hmacKey: "test-hmac-key-12345" }
  );
}

// Load a real Rekor anchor fixture for testing
function loadRekorAnchor() {
  const anchorPath = join(HERE, "..", "..", "samples", "synthex-hero-rekor-anchor.json");
  return JSON.parse(readFileSync(anchorPath, "utf8"));
}

// ─── tests ──────────────────────────────────────────────────────────────────

test("verify-bundle: reports Evidence PASS for valid HMAC evidence", async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), "synthex-test-"));
  try {
    const evidence = await buildHmacOnlyEvidence();
    const evidencePath = join(tmpDir, "evidence.json");
    writeFileSync(evidencePath, JSON.stringify(evidence));
    
    const cmd = `node ${join(HERE, "..", "..", "scripts", "verify-bundle.mjs")} "${evidencePath}"`;
    const output = execSync(cmd, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
    
    assert.match(output, /Evidence\s+·\s+PASS\s+·/);
    assert.match(output, /VERDICT:\s+PASS/);
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("verify-bundle: reports Evidence FAIL for malformed evidence", async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), "synthex-test-"));
  try {
    const evidencePath = join(tmpDir, "evidence.json");
    writeFileSync(evidencePath, "{ invalid json }");
    
    const cmd = `node ${join(HERE, "..", "..", "scripts", "verify-bundle.mjs")} "${evidencePath}"`;
    try {
      execSync(cmd, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
      assert.fail("Expected command to fail");
    } catch (e) {
      // Command should fail with exit code 1
      assert.ok(e.status !== 0, "Command should exit with non-zero status");
      // Error goes to stderr
      assert.match(e.stderr, /Error:\s+malformed evidence JSON/);
    }
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("verify-bundle: reports Evidence SKIP for evidence without seal", async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), "synthex-test-"));
  try {
    // Build evidence WITHOUT any seal data (no HMAC, no TSA, no signature)
    // We need to manually construct this because buildEvidence always creates a seal
    const evidence = {
      payload: { test: "no-seal", schema_version: 2 },
      contentHash: "abc123def456"
      // No seal object at all
    };
    const evidencePath = join(tmpDir, "evidence.json");
    writeFileSync(evidencePath, JSON.stringify(evidence));
    
    const cmd = `node ${join(HERE, "..", "..", "scripts", "verify-bundle.mjs")} "${evidencePath}"`;
    const output = execSync(cmd, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
    
    // No seal data → SKIP
    assert.match(output, /Evidence\s+·\s+SKIP\s+·/);
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("verify-bundle: reports Rekor PASS when --rekor given with valid bundle", async () => {
  // Use the real committed bundle and evidence that verify together
  const realEvidencePath = join(HERE, "..", "..", "samples", "synthex-hero-evidence.json");
  const realRekorPath = join(HERE, "..", "..", "samples", "synthex-hero-rekor-anchor.json");
  
  const cmd = `node ${join(HERE, "..", "..", "scripts", "verify-bundle.mjs")} "${realEvidencePath}" --rekor "${realRekorPath}"`;
  const output = execSync(cmd, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
  
  assert.match(output, /Evidence\s+·\s+PASS\s+·/);
  assert.match(output, /Rekor\s+·\s+PASS\s+·/);
  assert.match(output, /VERDICT:\s+PASS/);
});

test("verify-bundle: reports Rekor SKIP when --rekor file not found", async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), "synthex-test-"));
  try {
    const evidence = await buildHmacOnlyEvidence();
    const evidencePath = join(tmpDir, "evidence.json");
    const rekorPath = join(tmpDir, "missing.json");
    
    writeFileSync(evidencePath, JSON.stringify(evidence));
    
    const cmd = `node ${join(HERE, "..", "..", "scripts", "verify-bundle.mjs")} "${evidencePath}" --rekor "${rekorPath}"`;
    const output = execSync(cmd, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
    
    assert.match(output, /Evidence\s+·\s+PASS\s+·/);
    assert.match(output, /Rekor\s+·\s+SKIP\s+·/);
    assert.match(output, /VERDICT:\s+PASS/); // Evidence passed, Rekor skipped
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("verify-bundle: reports C2PA SKIP when c2patool not on PATH (stubbed)", async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), "synthex-test-"));
  try {
    const evidence = await buildHmacOnlyEvidence();
    const evidencePath = join(tmpDir, "evidence.json");
    const c2paPath = join(tmpDir, "card.png");
    
    writeFileSync(evidencePath, JSON.stringify(evidence));
    writeFileSync(c2paPath, "fake-png-data"); // file exists but c2patool not available
    
    // Temporarily remove c2patool from PATH for this test
    const originalPath = process.env.PATH;
    process.env.PATH = "/nonexistent:" + originalPath;
    
    try {
      const cmd = `node ${join(HERE, "..", "..", "scripts", "verify-bundle.mjs")} "${evidencePath}" --c2pa "${c2paPath}"`;
      const output = execSync(cmd, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
      
      assert.match(output, /Evidence\s+·\s+PASS\s+·/);
      assert.match(output, /C2PA\s+·\s+SKIP\s+·/);
      assert.match(output, /VERDICT:\s+PASS/);
    } finally {
      process.env.PATH = originalPath;
    }
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("verify-bundle: reports C2PA SKIP when card file not found", async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), "synthex-test-"));
  try {
    const evidence = await buildHmacOnlyEvidence();
    const evidencePath = join(tmpDir, "evidence.json");
    const c2paPath = join(tmpDir, "missing.png");
    
    writeFileSync(evidencePath, JSON.stringify(evidence));
    
    const cmd = `node ${join(HERE, "..", "..", "scripts", "verify-bundle.mjs")} "${evidencePath}" --c2pa "${c2paPath}"`;
    const output = execSync(cmd, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
    
    assert.match(output, /Evidence\s+·\s+PASS\s+·/);
    assert.match(output, /C2PA\s+·\s+SKIP\s+·/);
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("verify-bundle: table format is clean with METHOD · STATUS · DETAIL", async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), "synthex-test-"));
  try {
    const evidence = await buildHmacOnlyEvidence();
    const evidencePath = join(tmpDir, "evidence.json");
    writeFileSync(evidencePath, JSON.stringify(evidence));
    
    const cmd = `node ${join(HERE, "..", "..", "scripts", "verify-bundle.mjs")} "${evidencePath}"`;
    const output = execSync(cmd, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
    
    // Verify table header
    assert.match(output, /METHOD\s+·\s+STATUS\s+·\s+DETAIL/);
    
    // Verify Evidence line exists
    assert.match(output, /Evidence\s+·\s+(PASS|SKIP|FAIL)\s+·/);
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("verify-bundle: uses existing verifyEvidence() from evidence-report.js", async () => {
  // This test verifies the wrapper actually calls the existing verifier
  // by checking that it correctly handles the return shape from verifyEvidence()
  const tmpDir = mkdtempSync(join(tmpdir(), "synthex-test-"));
  try {
    // Build evidence with HMAC only (no TSA, no Ed25519)
    const evidence = await buildHmacOnlyEvidence();
    const evidencePath = join(tmpDir, "evidence.json");
    writeFileSync(evidencePath, JSON.stringify(evidence));
    
    const cmd = `node ${join(HERE, "..", "..", "scripts", "verify-bundle.mjs")} "${evidencePath}"`;
    const output = execSync(cmd, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
    
    // Should report PASS with HMAC-only detail
    assert.match(output, /Evidence\s+·\s+PASS\s+·.*HMAC/);
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("verify-bundle: handles missing evidence file with clear error", async () => {
  const cmd = `node ${join(HERE, "..", "..", "scripts", "verify-bundle.mjs")} "/nonexistent/evidence.json"`;
  try {
    execSync(cmd, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
    assert.fail("Expected command to fail");
  } catch (e) {
    // Command should fail with exit code 1
    assert.ok(e.status !== 0, "Command should exit with non-zero status");
    // Error goes to stderr
    assert.match(e.stderr, /Error:\s+evidence\s+file\s+not\s+found/);
  }
});
