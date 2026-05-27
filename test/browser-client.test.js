// Tests del fetcher browser (Bright Data Scraping Browser vía Playwright connectOverCDP).
// Unit: el guard sin endpoint (no toca red). Live: opt-in con BROWSER_LIVE=1 + secrets.
import { test } from "node:test";
import assert from "node:assert/strict";
import { browserFetch } from "../src/fetch/browser-client.js";

test("browser-client: sin WSS lanza error claro", async () => {
  const saved = process.env.BRIGHT_DATA_BROWSER_WSS;
  delete process.env.BRIGHT_DATA_BROWSER_WSS;
  try {
    await assert.rejects(
      () => browserFetch("https://example.com", { wssEndpoint: undefined }),
      /Falta BRIGHT_DATA_BROWSER_WSS/,
    );
  } finally {
    if (saved !== undefined) process.env.BRIGHT_DATA_BROWSER_WSS = saved;
  }
});

test("browser-client LIVE: scrape real vía CDP (opt-in)", { skip: process.env.BROWSER_LIVE !== "1" }, async () => {
  const { url, content } = await browserFetch("https://example.com");
  assert.match(url, /example\.com/i);
  assert.match(content, /Example Domain/i);
});
