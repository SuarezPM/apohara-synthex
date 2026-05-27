// Tests del módulo FETCH. El test de red real se SKIPEA sin token (honesto: no finge).
import { test } from "node:test";
import assert from "node:assert/strict";
import { BrightDataClient } from "../src/fetch/bright-data-client.js";

const hasToken = !!(process.env.BRIGHT_DATA_TOKEN || process.env.API_TOKEN);

test("fetch: connect() lanza error claro si falta el token", async () => {
  const c = new BrightDataClient({ apiToken: null });
  await assert.rejects(() => c.connect(), /token de Bright Data/);
});

test("fetch: el cliente expone los helpers de las tools de BD", () => {
  const c = new BrightDataClient({ apiToken: "dummy" });
  for (const fn of ["searchEngine", "scrapeMarkdown", "scrapeBatch", "extract"]) {
    assert.equal(typeof c[fn], "function");
  }
});

test("fetch: connect + listTools incluye search_engine (requiere token + red)", { skip: !hasToken }, async () => {
  const c = new BrightDataClient();
  await c.connect();
  const tools = await c.listTools();
  assert.ok(tools.some((t) => t.name === "search_engine"), "debe exponer search_engine");
  assert.ok(tools.some((t) => t.name === "scrape_as_markdown"), "debe exponer scrape_as_markdown");
  await c.close();
});
