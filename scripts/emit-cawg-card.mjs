// CAWG Organizational Identity on the C2PA Evidence Card — c2patool-NATIVE flow (P3.4).
//
// **What this proves (and what it does NOT):**
//   This emits a C2PA Evidence Card PNG whose manifest carries a `cawg.identity`
//   assertion produced by c2patool's NATIVE `[cawg_x509_signer]` flow (c2patool
//   0.26.60 / c2pa-rs 0.85, the CAWG X.509 identity-assertion path). c2patool then
//   VALIDATES that assertion as `cawg.identity.well-formed` ("CAWG X.509 identity
//   signature valid"). That is strictly MORE than our self-signed JSON sidecar
//   (`src/prove/c2pa.js`), which c2patool never reads — this is the real standard
//   tool validating the assertion SHAPE.
//
//   The signer is STILL self-signed (the same 10-year self-signed Ed25519 cert that
//   `synthex keygen` produces). So c2patool ALSO reports `signingCredential.untrusted`
//   ("signing certificate untrusted") for both the claim signer and the CAWG x509
//   signer. The overall `validation_state` is `Valid` (the manifest is structurally
//   sound) but the *credential* is NOT CA-rooted and NOT third-party-anchored.
//
//   So this proves: the CAWG identity-assertion SHAPE, c2patool-validated.
//   This does NOT prove: trusted / CA-rooted / DIF-anchored organizational identity.
//   The CAWG Organizational Identity Profile was DIF-ratified 05 Feb 2026 and requires
//   C2PA 2.2/2.3 trust anchoring — out of scope here (self-signed, UNTRUSTED). See
//   docs/HONESTY.md §1.6 and docs/cawg-identity.md.
//
// **Binding (non-negotiable):** the card's `com.apohara.synthex` assertion carries the
//   evidence `contentHash` + seal `keyId`, and the card + the CAWG identity assertion are
//   signed with the SAME Ed25519 key that sealed the evidence. The CAWG assertion
//   `referenced_assertions` points at `com.apohara.synthex`, so the org-identity claim is
//   bound to the exact evidence the seal certifies — not floating free.
//
// **Skip contract:** like scripts/c2pa-interop-test.sh, this SKIPs (exit 0) when c2patool
//   (Rust binary) or Playwright's Chromium is absent — CI never fails on a missing optional
//   tool. The honest skip message names the install command.
//
//   Run:  node scripts/emit-cawg-card.mjs [--out=<card.png>] [--keep]
//   Needs: cargo install c2patool   +   npx playwright install chromium
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFileSync, mkdtempSync, rmSync, mkdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { buildSelfSignedEd25519Cert } from "../src/prove/c2pa.js";
import { generateKeyPair } from "../src/prove/asymmetric.js";
import { renderCardPng } from "../src/prove/evidence-card.js";
import { runDemo } from "../demo/demo.js";

const execFileP = promisify(execFile);
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

const CAWG_BINDING_LABEL = "com.apohara.synthex";
const CARD_SPEC = "Apohara Synthex Evidence Card v1";

// ─── skip gate ──────────────────────────────────────────────────────────────

/** Exit 0 with a clear reason — a missing optional tool is a SKIP, not a failure. */
function skip(reason) {
  console.log(`SKIP — ${reason}`);
  console.log("== CAWG card (skipped, exit 0) ==");
  process.exit(0);
}

async function c2patoolPresent() {
  try {
    const { stdout } = await execFileP("c2patool", ["--version"]);
    return stdout.trim();
  } catch {
    return null;
  }
}

async function chromiumPresent() {
  try {
    const { chromium } = await import("playwright");
    const b = await chromium.launch({ headless: true });
    await b.close();
    return true;
  } catch {
    return false;
  }
}

// ─── manifest + settings builders (pure) ─────────────────────────────────────

/**
 * Base C2PA claim manifest. The claim signer reads its key + cert from file paths
 * (same as the existing `synthex evidence-card` flow). The `com.apohara.synthex`
 * assertion is the load-bearing binding: card ⇄ evidence share contentHash + keyId.
 */
function buildManifest(evidence, { keyPath, certPath }) {
  return {
    alg: "ed25519",
    private_key: keyPath,
    sign_cert: certPath,
    claim_generator_info: [{ name: "Apohara Synthex", version: "1.0.0" }],
    title: "Apohara Synthex Evidence Card (CAWG)",
    assertions: [
      {
        label: "c2pa.actions",
        data: {
          actions: [{
            action: "c2pa.created",
            softwareAgent: "Apohara Synthex 1.0.0",
            ...(evidence.sealedAt ? { when: evidence.sealedAt } : {}),
          }],
        },
      },
      {
        label: CAWG_BINDING_LABEL,
        data: {
          contentHash: evidence.contentHash,
          keyId: evidence.seal.signature.keyId,
          sealMethod: evidence.seal?.method ?? null,
          sealedAt: evidence.sealedAt ?? null,
          spec: CARD_SPEC,
        },
      },
    ],
  };
}

/**
 * c2patool settings TOML with the NATIVE `[cawg_x509_signer.local]` section. When this
 * is present alongside the manifest's claim signer, c2patool runs a DUAL signer: the
 * main claim is signed by the manifest signer, and a `cawg.identity` assertion is added
 * and signed by the CAWG x509 signer. `alg = "ed25519"` (default is es256; ours is the
 * same self-signed Ed25519 cert). `referenced_assertions` binds the org-identity claim to
 * our evidence-binding assertion so it does not float free of the evidence.
 *
 * Honest: this is the SAME self-signed cert/key → the credential stays UNTRUSTED. We do
 * NOT configure `[cawg_trust]` anchors (there is no CA to anchor to); c2patool reports
 * `signingCredential.untrusted`, which is the point we keep.
 */
function buildCawgSettingsToml({ certPem, keyPem }) {
  return [
    "version = 1",
    "",
    "[cawg_x509_signer.local]",
    'alg = "ed25519"',
    `referenced_assertions = ["${CAWG_BINDING_LABEL}"]`,
    "sign_cert = \"\"\"",
    certPem.trim(),
    "\"\"\"",
    "private_key = \"\"\"",
    keyPem.trim(),
    "\"\"\"",
    "",
  ].join("\n");
}

// ─── verify (dry) ─────────────────────────────────────────────────────────────

/**
 * Parse c2patool --detailed output and extract the honest verdict:
 *   - validation_state                (must be "Valid")
 *   - cawgWellFormed                  (cawg.identity.well-formed success → SHAPE validated)
 *   - untrusted                       (signingCredential.untrusted → kept caveat)
 *   - bindingHash                     (com.apohara.synthex.contentHash, must equal evidence hash)
 */
function summarizeVerify(detailedJson, expectedHash) {
  const v = JSON.parse(detailedJson);
  const am = v?.validation_results?.activeManifest ?? {};
  const codes = (arr) => (Array.isArray(arr) ? arr.map((s) => s?.code) : []);
  const cawgWellFormed = codes(am.success).includes("cawg.identity.well-formed");
  const untrusted = codes(am.failure).includes("signingCredential.untrusted");

  // The com.apohara.synthex binding hash must equal the evidence contentHash.
  const text = JSON.stringify(v);
  const bindingHashPresent = expectedHash && text.includes(expectedHash);

  return {
    validationState: v?.validation_state ?? null,
    cawgWellFormed,
    untrusted,
    bindingHashPresent: !!bindingHashPresent,
  };
}

// ─── main ─────────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  const outFlag = args.find((a) => a.startsWith("--out="));
  const keep = args.includes("--keep");
  const outPath = outFlag ? outFlag.slice("--out=".length) : join(repoRoot, "out", "cawg-evidence-card.png");

  console.log("== CAWG Organizational Identity on the C2PA card — c2patool NATIVE flow (P3.4) ==");
  console.log("   HONEST: signer is SELF-SIGNED → proves the CAWG identity-assertion SHAPE");
  console.log("   (c2patool-validated), NOT CA-rooted / third-party-anchored trust.");

  const version = await c2patoolPresent();
  if (!version) skip("c2patool not installed — cargo install c2patool");
  console.log(`   c2patool: ${version}`);

  if (!(await chromiumPresent())) {
    skip("Chromium not installed — npx playwright install chromium");
  }

  const tmp = mkdtempSync(join(tmpdir(), "synthex-cawg-"));
  try {
    // 1. Ephemeral self-signed Ed25519 keypair + cert (the SAME shape `synthex keygen` makes).
    const kp = generateKeyPair();
    const keyPath = join(tmp, "synthex-ed25519.key");
    const certPath = join(tmp, "synthex-c2pa.crt");
    writeFileSync(keyPath, kp.privateKeyPem);
    const certDer = await buildSelfSignedEd25519Cert({
      privateKeyPem: kp.privateKeyPem,
      publicKeyPem: kp.publicKeyPem,
      validityDays: 3650,
    });
    const certB64 = Buffer.from(certDer).toString("base64");
    const certPem = `-----BEGIN CERTIFICATE-----\n${certB64.match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
    writeFileSync(certPath, certPem);

    // 2. Seal a demo evidence with the SAME key, so the card binds to a real seal keyId.
    const evidence = await runDemo({ requestTsa: false, sign: true, signingKey: kp.privateKeyPem });
    if (!evidence?.contentHash || !evidence?.seal?.signature?.keyId) {
      console.error("FAIL — demo evidence is not Ed25519-sealed (no contentHash / keyId)");
      process.exit(1);
    }
    console.log(`   contentHash : ${evidence.contentHash}`);
    console.log(`   seal keyId  : ${evidence.seal.signature.keyId}`);

    // 3. Render the unsigned card PNG.
    const unsignedPath = join(tmp, "card.png");
    writeFileSync(unsignedPath, await renderCardPng(evidence));

    // 4. Manifest (base claim signer) + settings TOML (NATIVE CAWG x509 signer).
    const manifestPath = join(tmp, "manifest.json");
    writeFileSync(manifestPath, JSON.stringify(buildManifest(evidence, { keyPath, certPath }), null, 2));
    const settingsPath = join(tmp, "settings.toml");
    writeFileSync(settingsPath, buildCawgSettingsToml({ certPem, keyPem: kp.privateKeyPem }));

    // 5. Emit — c2patool dual-signs: claim signer + CAWG x509 identity signer.
    mkdirSync(dirname(outPath), { recursive: true });
    try {
      await execFileP("c2patool", ["--settings", settingsPath, unsignedPath, "-m", manifestPath, "-o", outPath, "-f"]);
    } catch (e) {
      console.error("FAIL — c2patool emit error:", String(e.stderr || e.message || "").split("\n").slice(0, 3).join(" | "));
      process.exit(1);
    }
    console.log(`   emitted     : ${outPath}`);

    // 6. Dry verify the card we just emitted.
    const { stdout: detailed } = await execFileP("c2patool", [outPath, "--detailed"]);
    const s = summarizeVerify(detailed, evidence.contentHash);

    console.log("── c2patool dry verify ──");
    console.log(`   validation_state          : ${s.validationState}`);
    console.log(`   cawg.identity.well-formed  : ${s.cawgWellFormed ? "YES (CAWG X.509 identity signature valid — SHAPE proven)" : "NO"}`);
    console.log(`   signingCredential.untrusted: ${s.untrusted ? "YES (self-signed — NOT CA-rooted, kept caveat)" : "NO"}`);
    console.log(`   com.apohara.synthex binding: ${s.bindingHashPresent ? "OK (card ⇄ evidence share contentHash)" : "MISSING"}`);

    // Honest success criteria: the manifest is Valid, the CAWG assertion is well-formed,
    // the credential is (expectedly) untrusted, and the evidence binding is present.
    const ok = s.validationState === "Valid" && s.cawgWellFormed && s.untrusted && s.bindingHashPresent;
    if (!ok) {
      console.error("FAIL — CAWG card did not meet the honest success criteria above");
      process.exit(1);
    }
    console.log("== PASS — CAWG identity-assertion SHAPE validated by c2patool; signer self-signed/UNTRUSTED (honest) ==");
    if (keep && tmp !== dirname(outPath)) console.log(`   (work dir kept: ${tmp})`);
    return 0;
  } finally {
    if (!keep) rmSync(tmp, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error("FAIL —", e?.message ?? String(e));
  process.exit(1);
});
