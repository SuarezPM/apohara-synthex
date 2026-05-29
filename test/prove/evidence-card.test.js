// Tests del manifest-definition de la Evidence Card C2PA (función pura, sin c2patool).
// El binding contentHash + keyId es el requisito NO NEGOCIABLE del diseño v0.9.0:
// la card PNG y el PDF sellado deben atestiguar el MISMO contentHash.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../../src/prove/asymmetric.js";
import { buildEvidence } from "../../src/prove/evidence-report.js";
import { buildCardManifestDefinition, renderCardHtml, SYNTHEX_ASSERTION_LABEL, CARD_SPEC } from "../../src/prove/evidence-card.js";

async function sealedEvidence() {
  const kp = generateKeyPair();
  const ev = await buildEvidence({ test: true, schema_version: 3 }, {
    hmacKey: "k", requestTsa: false, signingKey: kp.privateKeyPem,
  });
  return { kp, ev };
}

test("buildCardManifestDefinition: assertion com.apohara.synthex ata contentHash + keyId del sello", async () => {
  const { kp, ev } = await sealedEvidence();
  const def = buildCardManifestDefinition(ev, { privateKeyPath: "/k.pem", signCertPath: "/c.pem" });
  assert.equal(def.alg, "ed25519");
  const a = def.assertions.find((x) => x.label === SYNTHEX_ASSERTION_LABEL);
  assert.ok(a, "debe incluir la assertion com.apohara.synthex");
  assert.equal(a.data.contentHash, ev.contentHash, "contentHash debe igualar el del evidence");
  assert.equal(a.data.keyId, kp.keyId, "keyId debe igualar el del sello Ed25519");
  assert.equal(a.data.keyId, ev.seal.signature.keyId, "keyId debe ser el del sello del evidence");
  assert.equal(a.data.spec, CARD_SPEC);
});

test("buildCardManifestDefinition: incluye c2pa.actions created", async () => {
  const { ev } = await sealedEvidence();
  const def = buildCardManifestDefinition(ev, {});
  const actions = def.assertions.find((x) => x.label === "c2pa.actions");
  assert.ok(actions);
  assert.equal(actions.data.actions[0].action, "c2pa.created");
  assert.equal(actions.data.actions[0].when, ev.sealedAt);
});

test("buildCardManifestDefinition: rechaza evidence sin sello Ed25519 (symmetric-only)", async () => {
  const ev = await buildEvidence({ test: true }, { hmacKey: "k", requestTsa: false }); // sin signingKey
  assert.equal(ev.seal.signature, null);
  assert.throws(() => buildCardManifestDefinition(ev, {}), TypeError);
});

test("buildCardManifestDefinition: rechaza evidence sin contentHash", () => {
  assert.throws(() => buildCardManifestDefinition({ seal: { signature: { keyId: "x" } } }, {}), TypeError);
});

test("buildCardManifestDefinition: setea private_key/sign_cert/ta_url cuando se pasan", async () => {
  const { ev } = await sealedEvidence();
  const def = buildCardManifestDefinition(ev, { privateKeyPath: "/k.pem", signCertPath: "/c.pem", taUrl: "http://ts" });
  assert.equal(def.private_key, "/k.pem");
  assert.equal(def.sign_cert, "/c.pem");
  assert.equal(def.ta_url, "http://ts");
});

test("buildCardManifestDefinition: sin paths → no setea private_key/sign_cert (manifest portable)", async () => {
  const { ev } = await sealedEvidence();
  const def = buildCardManifestDefinition(ev, {});
  assert.equal(def.private_key, undefined);
  assert.equal(def.sign_cert, undefined);
});

test("renderCardHtml: incluye contentHash, keyId, target y branding (pura, sin browser)", async () => {
  const { kp, ev } = await sealedEvidence();
  ev.payload.target = "acme.com";
  ev.payload.lens = "security";
  const html = renderCardHtml(ev, { score: 72, band: "HIGH" });
  assert.match(html, /APOHARA SYNTHEX/);
  assert.match(html, /Content Credentials/);
  assert.ok(html.includes(ev.contentHash), "el HTML debe mostrar el contentHash");
  assert.ok(html.includes(kp.keyId), "el HTML debe mostrar el keyId del sello");
  assert.match(html, /acme\.com/);
  assert.match(html, /72/);
  assert.match(html, /HIGH/);
});

test("renderCardHtml: escapa caracteres peligrosos del target (anti-inyección HTML)", async () => {
  const { ev } = await sealedEvidence();
  ev.payload.target = '<script>alert(1)</script>';
  const html = renderCardHtml(ev, { score: 10, band: "LOW" });
  assert.ok(!html.includes("<script>alert(1)</script>"), "no debe inyectar el script crudo");
  assert.match(html, /&lt;script&gt;/);
});
