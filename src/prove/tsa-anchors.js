// DigiCert TSA trust anchors — pinned for RFC 3161 timestamp verification (M1, v0.7.0).
//
// Both PEMs were extracted from the CMS `certificates` set embedded in
// `samples/synthex-evidence-report.json` (the real DigiCert TimeStamp token Synthex
// shipped with v0.5.0). They are the actual intermediate + cross-signed root that
// chain-signed every TSA token Synthex has produced 2025-05-07 onward.
//
// Verification source (any future maintainer can reproduce):
//   $ node -e 'const a=require("asn1js"),p=require("pkijs"),b=Buffer.from(require("./samples/synthex-evidence-report.json").seal.rfc3161Tsa.token,"base64"); ...'
//   $ openssl x509 -in cert.pem -noout -subject -fingerprint -sha256 -dates
//
// Fingerprints are SHA-256 of the DER form of each cert, formatted with `:` separators
// (matches `openssl ... -fingerprint -sha256` output). Used for fail-fast load-time
// verification in `loadAnchors()`.
//
// Anchor rotation runbook (Follow-up F4, v0.7.1): when DigiCert rotates these
// anchors, the post-rotation tokens will fail with `signatureValidReason:
// "untrusted-anchor"` instead of `"forged"`. Operator must extract the new chain
// from a fresh sample token (same node script above), bump the PEMs + fingerprints
// below, and `npm test`. The fingerprint guard refuses to load if a PEM was edited
// without updating its fingerprint.

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

const INTERMEDIATE_PEM = `-----BEGIN CERTIFICATE-----
MIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBi
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3Qg
RzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJV
UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIIC
IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NG
aHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1
IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77j
YMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrY
hXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVC
iZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL
0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A1
9WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7
fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCr
O2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOm
xkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPx
ul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAw
HQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LS
cV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
BQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
Z2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYy
aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
CwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVM
Y2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ5
9Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB
9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J
05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HC
n2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8
xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam
4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6T
l4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovR
Diyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8
BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XA==
-----END CERTIFICATE-----`;

const ROOT_CROSS_PEM = `-----BEGIN CERTIFICATE-----
MIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQG
EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0G
CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7J
IT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxS
D1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb
7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1ef
VFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoY
OAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSa
M0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI
8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9L
BADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfm
Q6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDr
McXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15Gkv
mB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGL
p6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEF
BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRw
Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
Y3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
aWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0G
CSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6p
Grsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1W
z/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp
8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38dglo
hJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8S
uFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmU
-----END CERTIFICATE-----`;

// SHA-256 fingerprints (colon-separated, uppercase — matches `openssl ... -fingerprint -sha256`).
// Load-time guard refuses to load if PEM was edited without updating fingerprint.
export const ANCHOR_FINGERPRINTS = Object.freeze({
  intermediate: "CA:0B:15:54:EC:D9:01:EA:19:DC:AD:87:49:E9:F2:64:8C:8D:6D:FC:EA:1A:DD:9D:2C:21:09:41:5B:B8:2C:CD",
  rootCross: "33:84:6B:54:5A:49:C9:BE:49:03:C6:0E:01:71:3C:1B:D4:E4:EF:31:EA:65:CD:95:D6:9E:62:79:4F:30:B9:41",
});

export const ANCHOR_METADATA = Object.freeze({
  intermediate: {
    subject: "DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1",
    issuer: "DigiCert Trusted Root G4",
    notBefore: "2025-05-07T00:00:00Z",
    notAfter: "2038-01-14T23:59:59Z",
  },
  rootCross: {
    subject: "DigiCert Trusted Root G4",
    issuer: "DigiCert Assured ID Root CA",
    notBefore: "2022-08-01T00:00:00Z",
    notAfter: "2031-11-09T23:59:59Z",
  },
});

function pemToDer(pem) {
  const b64 = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/g, "");
  return Buffer.from(b64, "base64");
}

function sha256FpColon(derBuffer) {
  const hex = createHash("sha256").update(derBuffer).digest("hex").toUpperCase();
  return hex.match(/.{2}/g).join(":");
}

let _cached = null;

/**
 * Parse the pinned PEMs into pkijs.Certificate objects + verify each fingerprint
 * matches ANCHOR_FINGERPRINTS. Throws on mismatch (means a PEM was edited without
 * updating its fingerprint — guard against silent trust drift). Cached after first call.
 *
 * @returns {pkijs.Certificate[]} two certs in chain order: [intermediate, rootCross]
 */
export function loadAnchors() {
  if (_cached) return _cached;

  const intDer = pemToDer(INTERMEDIATE_PEM);
  const rootDer = pemToDer(ROOT_CROSS_PEM);
  const intFp = sha256FpColon(intDer);
  const rootFp = sha256FpColon(rootDer);

  if (intFp !== ANCHOR_FINGERPRINTS.intermediate) {
    throw new Error(`tsa-anchors: intermediate fingerprint mismatch (got ${intFp}, expected ${ANCHOR_FINGERPRINTS.intermediate}). PEM was edited without updating ANCHOR_FINGERPRINTS — refuse to load.`);
  }
  if (rootFp !== ANCHOR_FINGERPRINTS.rootCross) {
    throw new Error(`tsa-anchors: root cross-cert fingerprint mismatch (got ${rootFp}, expected ${ANCHOR_FINGERPRINTS.rootCross}). PEM was edited without updating ANCHOR_FINGERPRINTS — refuse to load.`);
  }

  const parse = (der) => {
    const arr = der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength);
    const a = asn1js.fromBER(arr);
    if (a.offset === -1) throw new Error("tsa-anchors: ASN.1 parse failed");
    return new pkijs.Certificate({ schema: a.result });
  };

  _cached = Object.freeze([parse(intDer), parse(rootDer)]);
  return _cached;
}
