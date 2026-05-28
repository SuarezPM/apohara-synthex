// Integration test T1.3 — Monitor.runOnceWithDelta() encadena correctamente
// dos lecturas del mismo target usando un stub HTTP local (no httpbin.org —
// requirement Critic R1 F8).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { Monitor } from "../../src/trigger/monitor.js";

function startStub({ port = 0 } = {}) {
  return new Promise((resolve) => {
    const counters = { hits: 0 };
    const server = createServer((req, res) => {
      counters.hits++;
      // Sirve HTML distinto en cada hit para forzar diff detectable.
      const body = counters.hits === 1
        ? "<p>price is one hundred dollars</p><p>stable line one</p>"
        : "<p>price is two hundred dollars</p><p>stable line one</p>";
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(body);
    });
    server.listen(port, () => {
      const url = `http://127.0.0.1:${server.address().port}/`;
      resolve({ server, url, counters });
    });
  });
}

test("Monitor.runOnceWithDelta encadena dos lecturas y detecta el cambio", async () => {
  const { server, url } = await startStub();
  try {
    const pipeline = async (target) => {
      const r = await fetch(target);
      const html = await r.text();
      return {
        contentHash: "dummy",
        payload: {
          target,
          lens: "gtm",
          fetchedAt: "static-stamp-for-determinism",
          content: html,
          findings: [{ severity: 6, summary: "noop" }],
        },
        seal: {},
      };
    };
    const alerts = [];
    const mon = new Monitor({
      pipeline,
      threshold: 9, // alto deliberadamente — alerta debe disparar por CAMBIO, no severity.
      onAlert: (a) => alerts.push(a),
      hmacKey: "test",
    });
    mon.watch(url);

    // Primera ronda: cold start, no debería alertar (no hay change desde prev=null).
    const round1 = await mon.runOnceWithDelta();
    assert.equal(round1.length, 0, "cold start no debería alertar (sin prev)");

    // Segunda ronda: cambio en HTML → alerta con deltaSummary no-cero.
    const round2 = await mon.runOnceWithDelta();
    assert.equal(round2.length, 1, "segunda ronda debe alertar por cambio detectado");
    const [a] = round2;
    assert.equal(a.target, url);
    assert.ok(a.deltaSummary);
    assert.ok((a.deltaSummary.added + a.deltaSummary.removed) > 0, "diff_summary debe tener cambios");
    // previousTsaSerial: si la TSA real respondió en round1, será un string hex; si la red
    // estaba caída o el TSA timeout, queda null. Ambos casos son válidos — solo asertamos
    // que el field existe y respeta el tipo.
    assert.ok(a.previousTsaSerial === null || typeof a.previousTsaSerial === "string");
    assert.ok(a.currentTsaSerial === null || typeof a.currentTsaSerial === "string");
  } finally {
    server.close();
  }
});

test("Monitor.runOnce (legacy) sigue funcionando sin tocar lastEvidence", async () => {
  const { server, url } = await startStub();
  try {
    const pipeline = async (target) => ({
      contentHash: "h",
      payload: { target, findings: [{ severity: 10, summary: "alert" }] },
      seal: {},
    });
    const alerts = [];
    const mon = new Monitor({ pipeline, threshold: 7, onAlert: (a) => alerts.push(a) });
    mon.watch(url);

    const out = await mon.runOnce();
    assert.equal(out.length, 1);
    assert.equal(out[0].severity, 10);
    assert.equal(mon.lastEvidence.size, 0, "runOnce no debe alterar el cache delta");
  } finally {
    server.close();
  }
});
