// URL allowlist para stress-test-judges.mjs (T2.1 del PRD v0.6.0).
// 60 URLs reales mixed-sectorial (no Wikipedia). Distribuidas:
//   15 pricing/SaaS, 15 docs/dev, 15 news/regulatory, 15 misc real-world.
// Sólo dominios públicos sin login (Critic R1 mitigación M2.4 / PII allowlist).
//
// Para escalar el stress hasta 500+, multiplicar este array o pasar --urls-file
// con un .txt externo. Mantenemos 60 inline para no inflar el repo.

export const STRESS_URLS = [
  // ── Pricing / SaaS landing pages ────────────────────────────────────────
  "https://stripe.com/pricing",
  "https://vercel.com/pricing",
  "https://supabase.com/pricing",
  "https://www.notion.com/pricing",
  "https://www.linear.app/pricing",
  "https://www.figma.com/pricing",
  "https://www.openai.com/pricing/",
  "https://www.anthropic.com/pricing",
  "https://brightdata.com/pricing",
  "https://www.cloudflare.com/plans/",
  "https://hetzner.com/cloud/",
  "https://aws.amazon.com/ec2/pricing/on-demand/",
  "https://cloud.google.com/pricing",
  "https://render.com/pricing",
  "https://fly.io/docs/about/pricing/",

  // ── Docs / API references / dev pages ───────────────────────────────────
  "https://docs.anthropic.com/en/release-notes/api",
  "https://platform.openai.com/docs/models",
  "https://developers.cloudflare.com/workers/platform/limits/",
  "https://nodejs.org/en/about/previous-releases",
  "https://docs.python.org/3/whatsnew/changelog.html",
  "https://kubernetes.io/releases/",
  "https://nextjs.org/blog",
  "https://react.dev/blog",
  "https://docs.aws.amazon.com/whats-new/",
  "https://cloud.google.com/blog/products/identity-security",
  "https://stripe.com/blog",
  "https://vercel.com/changelog",
  "https://supabase.com/changelog",
  "https://nodejs.org/api/crypto.html",
  "https://nodejs.org/api/fetch.html",

  // ── News / regulatory / market ──────────────────────────────────────────
  "https://www.federalreserve.gov/newsevents/pressreleases.htm",
  "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&type=8-K&dateb=&owner=include&count=10",
  "https://www.bls.gov/news.release/cpi.nr0.htm",
  "https://www.cisa.gov/news-events/news",
  "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  "https://nvd.nist.gov/vuln/full-listing",
  "https://www.justice.gov/news",
  "https://www.ftc.gov/news-events/news/press-releases",
  "https://www.consumerfinance.gov/about-us/newsroom/",
  "https://www.cnbc.com/markets/",
  "https://www.reuters.com/markets/",
  "https://www.bloomberg.com/markets",
  "https://news.ycombinator.com/",
  "https://techcrunch.com/",
  "https://www.theverge.com/",

  // ── Misc real-world (GitHub, journals, sport, weather) ──────────────────
  "https://github.com/anthropics/claude-code/releases",
  "https://github.com/SuarezPM/apohara-synthex",
  "https://github.com/topoteretes/cognee",
  "https://github.com/sigstore/cosign",
  "https://github.com/slsa-framework/slsa-github-generator/releases",
  "https://arxiv.org/list/cs.AI/recent",
  "https://arxiv.org/list/cs.CR/recent",
  "https://www.iana.org/protocols",
  "https://www.rfc-editor.org/rfc/rfc8785.html",
  "https://www.rfc-editor.org/rfc/rfc3161.html",
  "https://www.first.org/cvss/specification-document",
  "https://owasp.org/Top10/",
  "https://www.nist.gov/cyberframework",
  "https://www.weather.gov/forecastmaps",
  "https://www.usatoday.com/sports/",
];

if (STRESS_URLS.length < 60) {
  throw new Error(`STRESS_URLS expected >=60, got ${STRESS_URLS.length}`);
}
