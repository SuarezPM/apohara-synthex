// Tests del live-compare de Rekor (R3) — checkpointMatchesPinnedKey + el monitor con fetchImpl
// inyectado. Usa el checkpoint REAL del fixture (firmado por la key pinneada) — determinista, offline.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Buffer } from "node:buffer";
import { generateKeyPair } from "../../src/prove/asymmetric.js";
import { checkpointMatchesPinnedKey, ed25519CheckpointKeyId } from "../../src/prove/rekor.js";
import { REKOR_V2_LOGS } from "../../src/prove/rekor-anchors.js";
import { main } from "../../scripts/monitor-rekor-anchors.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const bundle = JSON.parse(readFileSync(join(HERE, "..", "fixtures", "rekor", "keyid-anchor-bundle.json"), "utf8"));
const ENVELOPE = bundle.tlogEntry.inclusionProof.checkpoint.envelope;
const LOG = REKOR_V2_LOGS[0];

// Flip a byte in the checkpoint signature (index >=4 to leave the keyhint intact → "signature").
function tamperSig(envelope) {
  const lines = envelope.split("\n");
  const i = lines.findIndex((l) => l.trim().startsWith("—"));
  const parts = lines[i].trim().split(" ");
  const blob = Buffer.from(parts.at(-1), "base64");
  blob[10] ^= 0xff; // a signature byte (after the 4-byte keyhint)
  parts[parts.length - 1] = blob.toString("base64");
  lines[i] = parts.join(" ");
  return lines.join("\n");
}

test("checkpointMatchesPinnedKey: checkpoint real del fixture + key pinneada → match:true", () => {
  const r = checkpointMatchesPinnedKey(ENVELOPE, LOG);
  assert.equal(r.match, true);
  assert.equal(r.reason, null);
  assert.equal(r.liveKeyHintHex, r.pinnedKeyHintHex);
});

test("checkpointMatchesPinnedKey: key DISTINTA (rotación) → keyhint-rotated", () => {
  const kp = generateKeyPair(); // un Ed25519 cualquiera, distinto a la log key
  const fakeLog = { origin: LOG.origin, publicKeySpkiB64: kp.publicKeySpkiB64 };
  const r = checkpointMatchesPinnedKey(ENVELOPE, fakeLog);
  assert.equal(r.match, false);
  assert.equal(r.reason, "keyhint-rotated");
  assert.notEqual(r.liveKeyHintHex, r.pinnedKeyHintHex);
});

test("checkpointMatchesPinnedKey: firma corrupta (keyhint intacto) → signature", () => {
  const r = checkpointMatchesPinnedKey(tamperSig(ENVELOPE), LOG);
  assert.equal(r.match, false);
  assert.equal(r.reason, "signature");
});

test("checkpointMatchesPinnedKey: envelope basura → parse-error, sin throw", () => {
  const r = checkpointMatchesPinnedKey("not a checkpoint", LOG);
  assert.equal(r.match, false);
  assert.equal(r.reason, "parse-error");
});

test("ed25519CheckpointKeyId: origin pinneado + SPKI → keyhint conocido cf119915", () => {
  const kid = ed25519CheckpointKeyId(LOG.origin, Buffer.from(LOG.publicKeySpkiB64, "base64"));
  assert.equal(kid.toString("hex"), "cf119915");
});

// Inyecta `emit` para capturar los records SIN hijackear stdout global (que rompe el TAP de node:test).
const resp = (text) => ({ ok: true, status: 200, text: async () => text });
async function run(fetchImpl) {
  const records = [];
  const code = await main({ fetchImpl, emit: (r) => records.push(r) });
  return { code, records };
}

test("monitor: checkpoint live verifica bajo la key pinneada → exit 0, liveCompare verified", async () => {
  const { code, records } = await run(async () => resp(ENVELOPE));
  assert.equal(code, 0);
  const ok = records.find((r) => r.status === "ok");
  assert.ok(ok, "debe emitir una línea status:ok");
  assert.equal(ok.liveCompare, "verified");
});

test("monitor: checkpoint live NO verifica (rotación) → exit 2, status rotated + suggestedRefresh", async () => {
  const { code, records } = await run(async () => resp(tamperSig(ENVELOPE)));
  assert.equal(code, 2);
  const rot = records.find((r) => r.status === "rotated");
  assert.ok(rot, "debe emitir status:rotated");
  assert.match(rot.suggestedRefresh, /TUF trusted_root\.json/);
});

test("monitor: checkpoint inalcanzable (fetch lanza) → exit 0, NO falla por flake de red", async () => {
  const { code, records } = await run(async () => { throw new Error("network down"); });
  assert.equal(code, 0);
  const ok = records.find((r) => r.status === "ok");
  assert.match(ok.liveCompare, /unreachable/);
});
