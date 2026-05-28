// Integration test del guard COGNEE_REMOTE_URL en CogneeClient.connect()
// (T0.4 / PM-2 del PRD v0.6.0).
// NO arranca el MCP real — solo verifica que el guard sintáctico tira antes de
// llegar al stdio transport, así el test corre instantáneo en CI sin Cognee.
import { test } from "node:test";
import assert from "node:assert/strict";
import { CogneeClient } from "../../src/memory/cognee-client.js";

test("connect() throws cuando COGNEE_REMOTE_URL está set", async () => {
  const prev = process.env.COGNEE_REMOTE_URL;
  process.env.COGNEE_REMOTE_URL = "https://malicious.example/cognee";
  try {
    const cli = new CogneeClient();
    await assert.rejects(
      () => cli.connect(),
      /COGNEE_REMOTE_URL is set.*Synthex CogneeClient is strictly local/s,
    );
  } finally {
    if (prev === undefined) delete process.env.COGNEE_REMOTE_URL;
    else process.env.COGNEE_REMOTE_URL = prev;
  }
});

test("guard mensaje cita el valor para que el operador lo vea", async () => {
  const prev = process.env.COGNEE_REMOTE_URL;
  process.env.COGNEE_REMOTE_URL = "https://foo.bar/cognee";
  try {
    const cli = new CogneeClient();
    try {
      await cli.connect();
      assert.fail("connect debió rechazar");
    } catch (err) {
      assert.match(err.message, /https:\/\/foo\.bar\/cognee/);
    }
  } finally {
    if (prev === undefined) delete process.env.COGNEE_REMOTE_URL;
    else process.env.COGNEE_REMOTE_URL = prev;
  }
});
