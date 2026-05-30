// GUARD — protección del endpoint público live: rate-limit por IP + bloqueo SSRF + allowlist.
// Honestidad: el rate-limit es IN-MEMORY (best-effort, por instancia warm de la función). Para
// un límite duro multi-instancia se usaría Vercel KV / Upstash; acá frena el abuso rápido sin
// agregar infra. El bloqueo SSRF y la allowlist SÍ son deterministas por request.
//
// Límite conocido del bloqueo SSRF: filtra por el HOSTNAME textual (literal + IP ofuscada +
// IPv6 privado), NO resuelve DNS → un dominio público que apunte a una IP privada (DNS
// rebinding) pasaría el filtro. El riesgo real es bajo en este diseño: el scrape lo ejecuta el
// proxy REMOTO de Bright Data, no la red de la función serverless → no hay metadata endpoint
// propio alcanzable. El filtro es defensa en profundidad + ahorro de créditos, no la única capa.

// Rangos privados/internos y metadata de cloud — nunca scrapeables desde un endpoint público.
const PRIVATE_HOSTS = [
  /^localhost$/i, /\.local$/i, /^0\./, /^127\./, /^10\./, /^192\.168\./,
  /^169\.254\./, /^172\.(1[6-9]|2\d|3[01])\./, /^\[?::1\]?$/, /169\.254\.169\.254/, /metadata\.(google|goog)/i,
  /^\[?::\]?$/, /^\[?(0:0:0:0:0:ffff:|::ffff:)/i,
];

export function isUrlTarget(t) { return /^https?:\/\//i.test(String(t ?? "")); }

/**
 * Valida que un target-URL sea público y (si hay allowlist) permitido. Los términos de búsqueda
 * (no-URL) pasan: el fetcher arma la SERP de Google, no hay SSRF.
 * @throws Error con motivo si el destino no es seguro/permitido.
 */
export function assertSafeTarget(target) {
  if (Array.isArray(target)) {
    for (const t of target) assertSafeTarget(t);
    return;
  }
  const s = String(target ?? "").trim();
  if (!s) throw new Error("target vacío");
  // Cualquier scheme://  que NO sea http/https se rechaza (no se degrada a término de búsqueda).
  const scheme = /^([a-z][a-z0-9+.\-]*):\/\//i.exec(s);
  if (scheme && !/^https?$/i.test(scheme[1])) throw new Error("solo se permite http/https");
  if (!isUrlTarget(s)) return; // término de búsqueda
  let u;
  try { u = new URL(s); } catch { throw new Error("URL inválida"); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("solo se permite http/https");
  // IPs ofuscadas (decimal/octal/hex) que evaden el match textual de rangos privados.
  if (/^\d+$/.test(u.hostname) || /^0x[0-9a-f]+$/i.test(u.hostname)) throw new Error("IP ofuscada bloqueada (SSRF)");
  // IPv6 link-local (fe80::/10) y ULA (fc00::/7) llegan como "[fe80::1]".
  if (/^\[?(fe80|fc|fd)[0-9a-f:]*\]?$/i.test(u.hostname)) throw new Error("IPv6 privado bloqueado (SSRF)");
  if (PRIVATE_HOSTS.some((re) => re.test(u.hostname))) throw new Error("destino privado/interno bloqueado (SSRF)");
  const allow = (process.env.SYNTHEX_ALLOWED_DOMAINS || "").split(",").map((s) => s.trim()).filter(Boolean);
  if (allow.length && !allow.some((d) => u.hostname === d || u.hostname.endsWith("." + d))) {
    throw new Error(`dominio fuera de la allowlist: ${u.hostname}`);
  }
}

const _hits = new Map(); // ip -> timestamps[] (best-effort, por instancia)

/** Rate-limit de ventana deslizante en memoria. Default: 8 req / 10 min por IP. */
export function rateLimit(ip, { max = 8, windowMs = 600_000 } = {}) {
  const now = Date.now();
  const arr = (_hits.get(ip || "unknown") || []).filter((t) => now - t < windowMs);
  arr.push(now);
  _hits.set(ip || "unknown", arr);
  return { ok: arr.length <= max, count: arr.length, max, remaining: Math.max(0, max - arr.length) };
}

/** Extrae la IP del cliente desde los headers de Vercel/proxy. */
export function clientIp(req) {
  const xff = req.headers?.["x-forwarded-for"] || req.headers?.["x-real-ip"] || "";
  return String(xff).split(",")[0].trim() || "unknown";
}

/** Resetea el estado del limiter (para tests). */
export function _resetRateLimit() { _hits.clear(); }
