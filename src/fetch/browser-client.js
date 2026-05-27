// FETCH (browser) — scrape de sitios JS-heavy / SPAs vía Bright Data Scraping Browser.
// Misma simbiosis ("sin Bright Data, no hay datos") pero conectándonos por CDP a un Chromium
// remoto que Bright Data ejecuta y desbloquea: el render de JS lo hace ELLOS, nosotros solo
// pedimos el innerText ya pintado. Para páginas que la API REST (Web Unlocker) no resuelve
// porque el contenido se monta en cliente.
import { chromium } from "playwright";

/**
 * Scrapea una URL conectándose por CDP al Scraping Browser de Bright Data.
 * El endpoint vive en process.env.BRIGHT_DATA_BROWSER_WSS
 * (formato: wss://brd-customer-...-zone-...:PASS@brd.superproxy.io:9222).
 *
 * @param {string} url
 * @param {{ wssEndpoint?: string, waitUntil?: "load"|"domcontentloaded"|"networkidle"|"commit", timeoutMs?: number }} [opts]
 * @returns {Promise<{ url: string, content: string }>} url final + innerText del body
 */
export async function browserFetch(url, opts = {}) {
  const wss = opts.wssEndpoint ?? process.env.BRIGHT_DATA_BROWSER_WSS ?? null;
  if (!wss) {
    throw new Error("Falta BRIGHT_DATA_BROWSER_WSS para el Scraping Browser de Bright Data.");
  }
  const waitUntil = opts.waitUntil ?? "domcontentloaded";
  const timeoutMs = opts.timeoutMs ?? 60000;

  let browser = null;
  try {
    // connectOverCDP no descarga Chromium: usa el navegador remoto que Bright Data ya corre.
    browser = await chromium.connectOverCDP(wss, { timeout: timeoutMs });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil, timeout: timeoutMs });
    // innerText del body = texto ya renderizado (post-JS), sin markup. Markdown-friendly.
    const content = await page.evaluate(() => document.body?.innerText ?? "");
    const finalUrl = page.url();
    return { url: finalUrl, content };
  } finally {
    // Cerrar SIEMPRE: una sesión abierta del Scraping Browser sigue facturando.
    await browser?.close?.();
  }
}
