#!/usr/bin/env node
// CLI de Apohara Synthex — corre el pipeline (o el demo determinista) desde la terminal y emite un
// Evidence Report verificable. Sin dependencias externas: parser de argv mínimo.
//
//   node bin/synthex.mjs --demo                         # demo cacheado, SIN secrets, verificable
//   node bin/synthex.mjs --demo finance                 # demo con otra lente
//   node bin/synthex.mjs "Competitor X" gtm             # pipeline real (requiere secrets de Bright Data/AIML)
//   node bin/synthex.mjs https://example.com security --dedup=semantic   # dedup near-dup (opt-in)
//   node bin/synthex.mjs keygen [--out=<dir>] [--force]  # v0.8 — generate Ed25519 signing keypair
//   node bin/synthex.mjs publish-keyid [--domain=<your-domain>] # v0.8 — print publication formats
import { mkdirSync, writeFileSync, chmodSync, existsSync, readFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { homedir, tmpdir } from "node:os";
import { Buffer } from "node:buffer";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { runPipeline } from "../src/pipeline.js";
import { runDemo } from "../demo/demo.js";
import { verifyEvidence } from "../src/prove/evidence-report.js";
import { generateKeyPair, keyIdOf, resolveSigningKey } from "../src/prove/asymmetric.js";
import { buildSelfSignedEd25519Cert, buildC2paManifest, verifyC2paManifest } from "../src/prove/c2pa.js";
import { renderCardPng, buildCardManifestDefinition } from "../src/prove/evidence-card.js";

const execFileP = promisify(execFile);

/**
 * Parser argv mínimo. Soporta `--flag` (boolean), `--key=value`, y posicionales.
 * @param {string[]} argv  argumentos crudos (sin node ni el script).
 * @returns {{positional:string[], flags:Record<string,string|true>}}
 */
export function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (const a of argv) {
    if (a.startsWith("--")) {
      const [k, v] = a.slice(2).split("=");
      flags[k] = v === undefined ? true : v;
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

const USAGE = `apohara-synthex — Evidence layer over Bright Data

  node bin/synthex.mjs --demo [lens]                  demo cacheado (sin secrets), verificable
  node bin/synthex.mjs <target> [lens] [--dedup=semantic|exact]

  lens: gtm | finance | security | supply-chain | all   (default: security; demo: gtm)
  --dedup=semantic   near-duplicate clustering (lossy, opt-in; descarga modelo en 1er uso)
  --help             muestra esta ayuda

  v0.8 — asymmetric signing
  node bin/synthex.mjs keygen [--out=<dir>] [--force]
     Generates an Ed25519 keypair + self-signed X.509 cert (10y) at
     ~/.config/apohara/synthex/synthex-ed25519.{key,pub} + synthex-c2pa.crt.
     Refuses overwrite without --force. Prints the keyId.
  node bin/synthex.mjs publish-keyid [--domain=<your-domain>]
     Prints the DNS TXT record + .well-known JSON formats so the operator can
     publish the keyId out-of-band (identity ≠ embedded pubkey — see HONESTY §1.4).
  node bin/synthex.mjs c2pa-emit <evidence.json> [--out=<sidecar.c2pa.json>]
     Emits a C2PA sidecar (own format) binding evidence.contentHash via a
     c2pa.hash.data assertion, signed Ed25519+COSE_Sign1 with x5chain.
  node bin/synthex.mjs c2pa-verify <sidecar.c2pa.json> [--evidence=<evidence.json>]
     Verifies the C2PA sidecar with our own verifier (COSE math + hash binding).
  node bin/synthex.mjs evidence-card <evidence.json> [--out=<card.png>] [--key-dir=<dir>]
     Renders a PNG Evidence Card and embeds a REAL C2PA manifest (verifiable by
     c2patool / contentcredentials.org). A com.apohara.synthex assertion binds the
     card to the evidence's contentHash + seal keyId — card and PDF attest the same
     evidence. Requires c2patool + a keypair (run keygen first). Signer is
     self-signed → "untrusted source" in c2patool (HONESTY §1.6).

  Resolution order at sign time:
     1. SYNTHEX_SIGNING_KEY (inline pkcs8 PEM or base64)
     2. SYNTHEX_SIGNING_KEY_FILE (explicit path)
     3. ~/.config/apohara/synthex/synthex-ed25519.key (XDG default)
     4. none → unsigned (signatureValid:'symmetric-only')
`;

async function printVerification(ev, hmacKey) {
  const v = await verifyEvidence(ev, { hmacKey });
  console.error("\n── Verificación ──");
  console.error("  hash :", v.hashOk ? "OK" : "FALLO");
  console.error("  HMAC :", v.hmacOk ? "OK" : "FALLO");
  console.error(
    "  TSA  :",
    v.tsaOk === true ? "OK (RFC 3161 · DigiCert)" : v.tsaOk === null ? "sin TSA (fallback HMAC-only)" : "FALLO",
  );
  // v0.8 — asymmetric Ed25519 verification (new)
  const sigLabel = v.signatureValid === true
    ? `OK (Ed25519 · keyId ${ev.seal?.signature?.keyId?.slice(0, 12)}…)`
    : v.signatureValid === false
      ? `FALLO (${v.signatureValidReason})`
      : "sin firma asimétrica (HMAC + TSA solamente)";
  console.error("  sig  :", sigLabel);
  // v0.8 — TSA CMS chain verdict (was the old signatureValid)
  if (v.tsaSignatureValid !== null) {
    const tsLabel = v.tsaSignatureValid
      ? "OK (CMS chain a DigiCert anchors)"
      : `FALLO (${v.tsaSignatureValidReason})`;
    console.error("  tsa-sig:", tsLabel);
  }
  console.error(`  método de sello: ${ev.seal.method}\n`);
}

// ─── keygen verb (v0.8) ─────────────────────────────────────────────────

const DEFAULT_KEY_DIR = join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "apohara", "synthex");

async function runKeygen({ outDir, force }) {
  const dir = outDir || DEFAULT_KEY_DIR;
  const keyPath = join(dir, "synthex-ed25519.key");
  const pubPath = join(dir, "synthex-ed25519.pub");
  const certPath = join(dir, "synthex-c2pa.crt");
  if (existsSync(keyPath) && !force) {
    console.error(`refusing overwrite: ${keyPath} already exists. Pass --force to replace.`);
    console.error(`(replacing the private key orphans every report signed with the old key — be sure.)`);
    return 2;
  }
  mkdirSync(dir, { recursive: true });
  const kp = generateKeyPair();
  writeFileSync(keyPath, kp.privateKeyPem);
  chmodSync(keyPath, 0o600);
  writeFileSync(pubPath, kp.publicKeyPem);

  // v0.8 — also generate a self-signed X.509 cert wrapping the Ed25519 pubkey
  // for the C2PA x5chain header. The cert is self-attesting; the operator's
  // identity is still established out-of-band via DNS/.well-known (HONESTY §1.4).
  const certDer = await buildSelfSignedEd25519Cert({
    privateKeyPem: kp.privateKeyPem,
    publicKeyPem: kp.publicKeyPem,
    validityDays: 3650,
  });
  const certB64 = Buffer.from(certDer).toString("base64");
  const certPem = `-----BEGIN CERTIFICATE-----\n${certB64.match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
  writeFileSync(certPath, certPem);

  console.log(`Wrote private key → ${keyPath} (mode 0600)`);
  console.log(`Wrote public key  → ${pubPath}`);
  console.log(`Wrote X.509 cert  → ${certPath}  (10-year self-signed, Ed25519)`);
  console.log(`keyId: ${kp.keyId}`);
  console.log("");
  console.log("Next: publish the keyId out-of-band so verifiers can pin it.");
  console.log("  node bin/synthex.mjs publish-keyid --domain=<your-domain>");
  return 0;
}

// ─── publish-keyid verb (v0.8) ──────────────────────────────────────────

function loadPubKeyId(outDir) {
  const dir = outDir || DEFAULT_KEY_DIR;
  const pubPath = join(dir, "synthex-ed25519.pub");
  if (!existsSync(pubPath)) {
    throw new Error(`no public key found at ${pubPath} — run 'synthex keygen' first`);
  }
  const pem = readFileSync(pubPath, "utf8");
  const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, "");
  return keyIdOf(b64);
}

function runPublishKeyid({ outDir, domain }) {
  let keyId;
  try {
    keyId = loadPubKeyId(outDir);
  } catch (err) {
    console.error(err.message);
    return 2;
  }
  const host = domain || "<your-domain>";
  console.log(`keyId: ${keyId}`);
  console.log("");
  console.log("DNS TXT record (recommended — publish at your domain):");
  console.log(`  Name:  _synthex-keyid.${host}`);
  console.log("  Type:  TXT");
  console.log(`  Value: \"v=APOHARA_SYNTHEX1; keyid=${keyId}\"`);
  console.log("");
  console.log(".well-known JSON (alternative — host at your domain):");
  console.log(`  Path:  https://${host}/.well-known/synthex-keys.json`);
  console.log(`  Body:  {"keyIds": ["${keyId}"], "active": "${keyId}", "rotatedAt": null}`);
  console.log("");
  console.log("Verifiers then pin this keyId via:");
  console.log(`  node bin/decode-evidence.js <evidence.json> --expected-keyid=${keyId}`);
  console.log("");
  console.log("Why this matters: embedding the pubkey in the report is integrity, not identity —");
  console.log("the report attests its own key (circular). Identity requires out-of-band publication");
  console.log("via DNS / .well-known / transparency log. See docs/HONESTY.md §1.4.");
  return 0;
}

export async function main(argv) {
  const { positional, flags } = parseArgs(argv);
  if (flags.help || flags.h) {
    console.log(USAGE);
    return 0;
  }
  // v0.8 verbs (positional[0] = verb name).
  if (positional[0] === "keygen") {
    return runKeygen({ outDir: typeof flags.out === "string" ? flags.out : null, force: !!flags.force });
  }
  if (positional[0] === "publish-keyid") {
    return runPublishKeyid({
      outDir: typeof flags.out === "string" ? flags.out : null,
      domain: typeof flags.domain === "string" ? flags.domain : null,
    });
  }
  if (positional[0] === "c2pa-emit") {
    return runC2paEmit({
      evidencePath: positional[1],
      outPath: typeof flags.out === "string" ? flags.out : null,
      keyDir: typeof flags["key-dir"] === "string" ? flags["key-dir"] : null,
    });
  }
  if (positional[0] === "c2pa-verify") {
    return runC2paVerify({
      sidecarPath: positional[1],
      evidencePath: typeof flags.evidence === "string" ? flags.evidence : null,
    });
  }
  if (positional[0] === "evidence-card") {
    return runEvidenceCard({
      evidencePath: positional[1],
      outPath: typeof flags.out === "string" ? flags.out : null,
      keyDir: typeof flags["key-dir"] === "string" ? flags["key-dir"] : null,
    });
  }

  const hmacKey = process.env.SYNTHEX_HMAC_KEY || "synthex-demo";
  // v0.8.0 — resolve the Ed25519 signing key (env inline → file → XDG default).
  // Presence opt-in: a configured key activates the asymmetric seal; absence
  // keeps the honest symmetric-only fallback (signatureValid:'symmetric-only').
  const signingKey = resolveSigningKey();
  let ev;
  if (flags.demo) {
    const lens = positional[0] || "gtm";
    ev = await runDemo({ requestTsa: true, lens, signingKey });
  } else {
    const target = positional[0];
    if (!target) {
      console.error(USAGE);
      return 1;
    }
    const lens = positional[1] || "security";
    const dedupMode = flags.dedup === "semantic" ? "semantic" : "exact";
    ev = await runPipeline(target, { lens, dedupMode, hmacKey, requestTsa: true, signingKey });
  }
  // El reporte va a stdout (parseable); la verificación a stderr (no contamina el JSON).
  console.log(JSON.stringify(ev, null, 2));
  await printVerification(ev, hmacKey);
  return 0;
}

// ─── c2pa-emit verb (v0.8) ──────────────────────────────────────────────

function _pemToDer(pem) {
  const b64 = pem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s+/g, "");
  return new Uint8Array(Buffer.from(b64, "base64"));
}

async function runC2paEmit({ evidencePath, outPath, keyDir }) {
  if (!evidencePath) {
    console.error("usage: synthex c2pa-emit <evidence.json> [--out=<sidecar.c2pa.json>] [--key-dir=<dir>]");
    return 2;
  }
  const dir = keyDir || DEFAULT_KEY_DIR;
  const keyPath = join(dir, "synthex-ed25519.key");
  const certPath = join(dir, "synthex-c2pa.crt");
  if (!existsSync(keyPath) || !existsSync(certPath)) {
    console.error(`missing key or cert in ${dir} — run 'synthex keygen' first`);
    return 2;
  }
  const ev = JSON.parse(readFileSync(evidencePath, "utf8"));
  const keyPem = readFileSync(keyPath, "utf8");
  const certDer = _pemToDer(readFileSync(certPath, "utf8"));
  const { sidecar } = await buildC2paManifest(ev, {
    x509CertDer: certDer,
    signingKey: keyPem,
  });
  const out = outPath || evidencePath.replace(/\.json$/, ".c2pa.json");
  writeFileSync(out, JSON.stringify(sidecar, null, 2));
  console.log(`Wrote C2PA sidecar → ${out}`);
  console.log(`  evidence contentHash : ${ev.contentHash}`);
  console.log(`  spec                 : ${sidecar.spec}`);
  console.log(`  signed with Ed25519 wrapped in self-signed X.509 (HONESTY §1.6).`);
  return 0;
}

// ─── c2pa-verify verb (v0.8) ────────────────────────────────────────────

async function runC2paVerify({ sidecarPath, evidencePath }) {
  if (!sidecarPath) {
    console.error("usage: synthex c2pa-verify <sidecar.c2pa.json> [--evidence=<evidence.json>]");
    return 2;
  }
  const sidecar = JSON.parse(readFileSync(sidecarPath, "utf8"));
  let expectedHash = null;
  if (evidencePath) {
    expectedHash = JSON.parse(readFileSync(evidencePath, "utf8")).contentHash;
  }
  const v = await verifyC2paManifest(sidecar, { expectedContentHash: expectedHash });
  console.log(`── C2PA Sidecar ──`);
  console.log(`  format             : ${sidecar.format}`);
  console.log(`  spec               : ${sidecar.spec}`);
  console.log(`  generator          : ${sidecar.generator}`);
  console.log(`  evidence_content_hash: ${sidecar.evidence_content_hash}`);
  console.log("");
  console.log(`── Verification (synthex own verifier) ──`);
  console.log(`  COSE_Sign1 verify  : ${v.ok ? "OK" : `FAIL (${v.reason})`}`);
  if (v.contentHash) console.log(`  claim contentHash  : ${v.contentHash}`);
  if (expectedHash) {
    console.log(`  vs evidence hash   : ${v.contentHash === expectedHash ? "OK match" : "MISMATCH"}`);
  }
  return v.ok ? 0 : 1;
}

// ─── evidence-card verb (v0.9) ──────────────────────────────────────────
// Renders a PNG Evidence Card and embeds a REAL C2PA manifest via c2patool.
// The com.apohara.synthex assertion binds the card to evidence.contentHash +
// seal keyId, so the card and the PDF attest the same evidence (HONESTY §1.6).

async function runEvidenceCard({ evidencePath, outPath, keyDir }) {
  if (!evidencePath) {
    console.error("usage: synthex evidence-card <evidence.json> [--out=<card.png>] [--key-dir=<dir>]");
    return 2;
  }
  const dir = keyDir || DEFAULT_KEY_DIR;
  const keyPath = join(dir, "synthex-ed25519.key");
  const certPath = join(dir, "synthex-c2pa.crt");
  if (!existsSync(keyPath) || !existsSync(certPath)) {
    console.error(`missing key or cert in ${dir} — run 'synthex keygen' first`);
    return 2;
  }
  const ev = JSON.parse(readFileSync(evidencePath, "utf8"));
  if (!ev?.seal?.signature?.keyId) {
    console.error("evidence is symmetric-only (no Ed25519 seal) — re-run the pipeline with a signing key");
    console.error("configured (SYNTHEX_SIGNING_KEY / keygen) so the card can bind to the seal keyId.");
    return 2;
  }
  const out = outPath || evidencePath.replace(/\.json$/, "") + ".card.png";

  const tmp = mkdtempSync(join(tmpdir(), "synthex-card-"));
  try {
    const unsignedPath = join(tmp, "card.png");
    writeFileSync(unsignedPath, await renderCardPng(ev));

    const manifestDef = buildCardManifestDefinition(ev, { privateKeyPath: keyPath, signCertPath: certPath });
    const manifestPath = join(tmp, "manifest.json");
    writeFileSync(manifestPath, JSON.stringify(manifestDef, null, 2));

    try {
      await execFileP("c2patool", [unsignedPath, "-m", manifestPath, "-o", out, "-f"]);
    } catch (e) {
      if (e.code === "ENOENT") {
        console.error("c2patool not found — install with: cargo install c2patool");
        console.error("(the unsigned card was rendered but NOT C2PA-signed)");
        return 3;
      }
      console.error("c2patool failed:", String(e.stderr || e.message || "").split("\n")[0]);
      return 1;
    }

    console.log(`Wrote C2PA evidence card → ${out}`);
    console.log(`  contentHash : ${ev.contentHash}`);
    console.log(`  seal keyId  : ${ev.seal.signature.keyId}`);
    console.log(`  The com.apohara.synthex assertion binds this card to the sealed evidence.`);
    console.log(`  Verify: c2patool ${out}   (signer self-signed → 'untrusted source', expected — HONESTY §1.6)`);
    return 0;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then((code) => process.exit(code ?? 0));
}
