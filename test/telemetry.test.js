// Tests de telemetría OTel. Sin SDK registrado los spans son no-op (no deben romper nada).
import { test } from "node:test";
import assert from "node:assert/strict";
import { withSpan, recordTokens, recordBlocked, recordSealed, startTelemetry } from "../src/telemetry/otel.js";

test("withSpan: devuelve el valor de la fn y expone record()", async () => {
  const r = await withSpan("TEST", async ({ record }) => {
    record("docs", 3);
    return 42;
  });
  assert.equal(r, 42);
});

test("withSpan: propaga el error de la fn (y cierra el span sin tragarlo)", async () => {
  await assert.rejects(
    () => withSpan("TEST", async () => { throw new Error("boom"); }),
    /boom/
  );
});

test("record helpers no rompen sin SDK (no-op seguro)", () => {
  assert.doesNotThrow(() => {
    recordTokens({ prompt_tokens: 100, completion_tokens: 20 });
    recordTokens(null);
    recordBlocked(2);
    recordBlocked(0);
    recordSealed();
  });
});

test("startTelemetry: sin OTEL_EXPORTER_OTLP_ENDPOINT devuelve false (no arranca exporter)", async () => {
  const prev = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  try {
    const started = await startTelemetry();
    assert.equal(started, false);
  } finally {
    if (prev !== undefined) process.env.OTEL_EXPORTER_OTLP_ENDPOINT = prev;
  }
});
