# F4 — DigiCert TSA Anchor Rotation Runbook

> **MANDATORY** for v0.7.1 per the v0.7.0 PRD §10. Created at v0.7.0 release because v0.7.0 ships with pinned DigiCert anchors (`src/prove/tsa-anchors.js`), and any future rotation by DigiCert will silently fail *new*-token verification until the pins are refreshed. This runbook is how an operator (or a CI alert) refreshes them safely.

---

## When this runbook applies

You should follow this runbook when **any** of the following happen:

1. A live demo or a production verify call returns `signatureValidReason: "untrusted-anchor"` on a token sealed **after** the last anchor refresh date recorded in this file (current: 2026-05-28, taken from `samples/synthex-evidence-report.json`).
2. The pre-demo smoke test (`test/prove/tsa-cms-verify.test.js` "M1 pre-demo smoke (PM-6-agudo)") starts failing the **positive** branch (the negative `trustedCerts:[]` branch should always fail with `"untrusted-anchor"` — that's the point).
3. DigiCert publishes a new TSA intermediate or rotates the cross-signing root. Watch <https://www.digicert.com/kb/digicert-root-certificates.htm> for the "Trusted G4 TimeStamping" family.
4. A scheduled health check (Sprint 3 follow-up F4 monitor, see §3 below) flags an anchor verifying *new* but not *old* tokens — DigiCert can issue from old + new chain in parallel for a transition window.

**Do NOT follow this runbook** if the failure is a `"forged"` reason (signature math) or a `"chain-incomplete"` reason on every single token (those are real verification failures, not anchor staleness).

---

## §1 · Reproducing the issue (5 minutes)

1. Get a freshly-sealed Synthex token:
   ```bash
   node bin/synthex.mjs --target https://example.com --lens security --requestTsa | tee /tmp/fresh-evidence.json
   ```
2. Run the verifier with the current pinned anchors:
   ```bash
   node bin/decode-evidence.js /tmp/fresh-evidence.json
   ```
3. Read the `sig` line. The four outcomes:
   - `OK (chain verifies against pinned DigiCert anchors)` → no rotation needed.
   - `FAIL (untrusted-anchor)` → **rotation needed**. Continue this runbook.
   - `FAIL (forged)` → NOT a rotation issue. Investigate token integrity.
   - `FAIL (chain-incomplete)` → NOT a rotation issue. Check `src/prove/tsa.js verifyCmsSigned` for shape mismatch.

---

## §2 · Refreshing the pinned anchors

The two PEMs in `src/prove/tsa-anchors.js` were originally extracted from the embedded CMS `certificates` set in `samples/synthex-evidence-report.json`. We extract from a **fresh** token the same way — no external `crl3.digicert.com` fetch required.

### 2.1 · Capture a fresh token

```bash
node bin/synthex.mjs --target https://example.com --lens security --requestTsa > /tmp/fresh.json
```

If the live pipeline isn't easy to drive, you can also seal an arbitrary 32-byte hash directly:

```bash
node -e '
import("./src/prove/tsa.js").then(async ({ requestTimestamp }) => {
  const hash = require("node:crypto").randomBytes(32);
  const token = await requestTimestamp(hash);
  require("node:fs").writeFileSync("/tmp/fresh-token.der", token);
  console.log("Token wrote, " + token.length + " bytes");
});
'
```

### 2.2 · Decode the embedded chain

```bash
node -e '
const fs = require("node:fs");
const asn1js = require("asn1js");
const pkijs = require("pkijs");

// If you sealed via the pipeline (Option A): pull the b64 token out of /tmp/fresh.json.
// If you sealed via the direct script (Option B): read /tmp/fresh-token.der.
const der = fs.existsSync("/tmp/fresh-token.der")
  ? new Uint8Array(fs.readFileSync("/tmp/fresh-token.der"))
  : new Uint8Array(Buffer.from(JSON.parse(fs.readFileSync("/tmp/fresh.json", "utf8")).seal.rfc3161Tsa.token, "base64"));

const asn1 = asn1js.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
const resp = new pkijs.TimeStampResp({ schema: asn1.result });
const signed = new pkijs.SignedData({ schema: resp.timeStampToken.content });

signed.certificates.forEach((c, i) => {
  const cn = c.subject.typesAndValues.find(t => t.type === "2.5.4.3")?.value.valueBlock?.value;
  const issuer = c.issuer.typesAndValues.find(t => t.type === "2.5.4.3")?.value.valueBlock?.value;
  const der = c.toSchema(true).toBER(false);
  const fp = require("node:crypto").createHash("sha256").update(Buffer.from(der)).digest("hex").toUpperCase().match(/.{2}/g).join(":");
  const pem = "-----BEGIN CERTIFICATE-----\n"
    + Buffer.from(der).toString("base64").match(/.{1,64}/g).join("\n")
    + "\n-----END CERTIFICATE-----";
  fs.writeFileSync(`/tmp/cert-${i}.pem`, pem);
  console.log(`[${i}] subject="${cn}" issuer="${issuer}"`);
  console.log(`    fingerprint=${fp}`);
  console.log(`    saved to /tmp/cert-${i}.pem`);
});
'
```

You'll see 3 certificates: responder (signer) + intermediate + cross-signed root.

### 2.3 · Identify the two anchors to pin

- **Intermediate** = the cert whose subject CN starts with `"DigiCert Trusted G4 TimeStamping"`. As of 2026-05-28 this is `"DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1"`. DigiCert will bump the year suffix on rotation (e.g. `2026 CA1`).
- **Root cross-cert** = the cert whose subject is `"DigiCert Trusted Root G4"` (issued by the older `"DigiCert Assured ID Root CA"`). This is the cross-sign that lets us anchor the chain to a publicly-trusted root without shipping a full Mozilla bundle.

### 2.4 · Update `src/prove/tsa-anchors.js`

```bash
# Inspect the new PEMs you want to pin.
cat /tmp/cert-1.pem    # intermediate
cat /tmp/cert-2.pem    # root cross-cert (verify by running `openssl x509 -in /tmp/cert-2.pem -noout -subject`)
```

Open `src/prove/tsa-anchors.js`:

1. Replace `INTERMEDIATE_PEM` template literal with the new `/tmp/cert-1.pem` contents (between the BEGIN/END lines).
2. Replace `ROOT_CROSS_PEM` template literal with the new `/tmp/cert-2.pem` contents.
3. Update `ANCHOR_FINGERPRINTS.intermediate` and `ANCHOR_FINGERPRINTS.rootCross` to the fingerprints printed in §2.2.
4. Update `ANCHOR_METADATA` subject / issuer / notBefore / notAfter for both entries (the new validity window matters for the operator).

The fingerprint guard in `loadAnchors()` will refuse to load the module if you forget to update a fingerprint — the test suite will surface this immediately:

```bash
npm test -- --test-name-pattern "tsa-anchors"
```

### 2.5 · Re-run the gate

```bash
npm test
```

You should see:
- 8/8 in `test/prove/tsa-cms-verify.test.js` (positive, untrusted-anchor, forged, HMAC-only, piloto-50, v1+TSA, anchor-guard, pre-demo smoke).
- The full suite still green (283+ tests; baseline drift is normal).

The positive AC1 test still uses `samples/synthex-evidence-report.json` (the original 2026-05-07 token). The new anchors must continue to verify that token — DigiCert's rotation generally chains through the old root for a transition window, so the old token still passes under the new pins. If it doesn't (i.e. AC1 starts failing), DigiCert ended the transition window; you need to **add** the new anchors *alongside* the old ones, not replace them. Edit `loadAnchors()` to return all 3-4 anchors for the transition.

---

## §3 · Adding a monitor (operational follow-up)

The PRD calls F4 "anchor-rotation runbook + monitor". The runbook is this file; the monitor is recommended but not yet wired:

- **Recommended**: a cron / GitHub Action that runs the §1 reproducer weekly and pages on `signatureValidReason: "untrusted-anchor"`. Reuses the existing `bin/decode-evidence.js` CLI.
- **Output**: structured JSON line so log aggregators can alert: `{"check":"tsa-anchor","status":"stale","reason":"untrusted-anchor","at":"<ISO>"}`.
- **Until the monitor lands** (v0.7.x or v0.8): the pre-demo smoke test in `test/prove/tsa-cms-verify.test.js` is the manual interim guard. Run `npm test` before any live demo.

---

## §4 · Commit + release the refresh

A pinned-anchor refresh is a patch release (`v0.7.x`). The commit message should be exact about which anchors moved:

```
fix(prove): refresh DigiCert TSA anchors — intermediate <old subject> → <new subject>

DigiCert rotated the <year> CA. Old fingerprint: <old>. New fingerprint: <new>.
Captured from a fresh sealed token at <date>; cross-checked against
https://www.digicert.com/kb/digicert-root-certificates.htm.

Tests: 8/8 acceptance, full suite green.

Co-Authored-By: ...
```

Tag and push: the existing `release-slsa.yml` workflow handles SLSA L3 + npm provenance + GitHub Release automatically.

---

## §5 · Things that are NOT in this runbook (on purpose)

- **No OCSP / CRL revocation check.** The CMS verifier trusts the pinned chain back to our anchors; it does not phone home to validate the responder cert isn't revoked. This is a documented limit (see [`docs/HONESTY.md §1.1`](HONESTY.md#11-rfc-3161-tsa--what-signaturevalidtrue-means-m1-v070)).
- **No full Mozilla CA bundle as fallback.** We pin specifically to keep the "we know exactly who signed" property. The PRD §3 "Must NOT Have" line.
- **No automated PR for anchor refresh.** Trust pins should land via a human-reviewed commit, not an unattended bot. The fingerprint guard would catch silent drift, but a refresh PR should still be reviewed.
