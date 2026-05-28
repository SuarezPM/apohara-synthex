// 20 fixtures representativas para calibrar nvidia/nemotron-3-nano-omni vs
// deepseek/deepseek-non-thinking-v3.2-exp en T0.6 del PRD v0.6.0.
// Cubren las 4 lentes (gtm, finance, security, supply-chain) con texto realista
// del tipo que Synthex procesa en producción: pricing pages, vendor risk
// disclosures, security advisories, supply-chain news, regulatory filings.
//
// Cada fixture trae el lens esperado para forzar al modelo a operar en ese
// dominio (no dejamos que infiera la lente — calibramos calidad dentro de cada).
//
// MIT — Pablo M. Suárez (@SuarezPM).

export const CALIBRATION_FIXTURES = [
  // ─── GTM (5) ─────────────────────────────────────────────────────────────
  {
    id: "gtm-01-competitor-pricing-launch",
    lens: "gtm",
    text:
      "Stripe today announced a new Atlas pricing tier at $499/year, replacing the previous $500 one-time fee. The new bundle includes Delaware C-Corp formation, EIN registration, and 1 year of Stripe Tax compliance. This puts them ahead of Mercury Bank's $399 bundle which only covers formation. Hiring page lists 47 new Atlas team openings, 12 in pricing strategy.",
    expected_severity_band: [6, 9],
  },
  {
    id: "gtm-02-hiring-signal-aggressive",
    lens: "gtm",
    text:
      "Cursor (Anysphere) posted 22 new senior eng openings in the past 7 days across infra, evals, and a new 'agent reliability' team. Compensation in the listings starts at $350k base + equity. Two of the postings explicitly mention 'replatform from VS Code Server to in-house IDE shell'.",
    expected_severity_band: [7, 9],
  },
  {
    id: "gtm-03-product-launch-incremental",
    lens: "gtm",
    text:
      "Notion released a minor update to its formula engine on November 14, adding support for date range arithmetic. The release notes mention 3 new functions: dateRangeBetween(), excludeWeekends(), and timezoneAware(). No pricing change. Roadmap page mentions a 'larger AI workspace overhaul' for Q1 2026.",
    expected_severity_band: [2, 5],
  },
  {
    id: "gtm-04-market-move-quiet",
    lens: "gtm",
    text:
      "Slack updated its enterprise SKU page to remove the 'Plus' tier silently. The Wayback Machine confirms the tier existed on 2026-04-12 and was gone by 2026-05-10. No announcement. Customers on Plus appear migrated to Business+.",
    expected_severity_band: [5, 8],
  },
  {
    id: "gtm-05-noise-blog-post",
    lens: "gtm",
    text:
      "Our quarterly engineering culture report celebrates remote-first values, async standups, and the use of Markdown for everything. Featured employees: Sarah from Customer Success and Marcus from Platform.",
    expected_severity_band: [0, 3],
  },

  // ─── FINANCE (5) ─────────────────────────────────────────────────────────
  {
    id: "fin-01-vendor-bankruptcy",
    lens: "finance",
    text:
      "Cloud infrastructure provider FibreCore Inc filed Chapter 11 bankruptcy on November 18 after Q3 revenue dropped 67% YoY. They are the second-largest reseller of regional Tier-3 data centers in the Midwest US. Approximately 340 mid-market SaaS customers are listed in the bankruptcy filing as creditors. Expected emergency runoff: 90 days.",
    expected_severity_band: [8, 10],
  },
  {
    id: "fin-02-regulatory-filing-mild",
    lens: "finance",
    text:
      "SEC 8-K filing on November 15: Acme Corp disclosed that the previously announced acquisition of TargetCo will close two weeks later than the projected November 30 date, citing additional antitrust review by the DOJ. The deal value remains $4.2B and termination fees have not changed.",
    expected_severity_band: [4, 7],
  },
  {
    id: "fin-03-earnings-beat",
    lens: "finance",
    text:
      "NVIDIA reported Q3 FY26 earnings: revenue $35.1B vs consensus $33.2B, EPS $0.81 vs $0.75 expected. Data center revenue grew 112% YoY. Guidance for Q4: $37.5B revenue, $0.84 EPS — both above consensus. Stock up 6% AH.",
    expected_severity_band: [2, 5],
  },
  {
    id: "fin-04-credit-downgrade",
    lens: "finance",
    text:
      "Moody's downgraded Boeing's senior unsecured debt from Baa2 to Baa3, the last notch above junk. Cited: elongated commercial aircraft production restart timeline + ongoing strike-related cash burn. Outlook 'negative'. Total debt outstanding affected: $48B.",
    expected_severity_band: [7, 9],
  },
  {
    id: "fin-05-noise-press-release",
    lens: "finance",
    text:
      "Local credit union announces grand opening of new branch in downtown Wichita. Ribbon cutting ceremony scheduled for December 1 with mayor in attendance. Branch will offer standard checking, savings, and ATM services. Hours: M-F 9 to 5.",
    expected_severity_band: [0, 2],
  },

  // ─── SECURITY (5) ────────────────────────────────────────────────────────
  {
    id: "sec-01-active-exploit-cve",
    lens: "security",
    text:
      "CISA added CVE-2025-68143 to the Known Exploited Vulnerabilities catalog on November 16. CVSS 8.8 HIGH, path traversal in the official MCP server-git component. Active exploitation observed in the wild against developer workstations running Claude Code, Cursor, and Cline with mcp-server-git enabled. Patch released same day in version 0.6.5 of @modelcontextprotocol/server-git. Workaround: remove git from MCP config.",
    expected_severity_band: [8, 10],
  },
  {
    id: "sec-02-leaked-credentials",
    lens: "security",
    text:
      "A pastebin dump posted November 12 contains 14,200 plaintext credentials with .gov email addresses. Sample verification confirms ~30% are valid against major SaaS providers. Origin appears to be a phished MFA-disabled identity provider tenant.",
    expected_severity_band: [8, 10],
  },
  {
    id: "sec-03-supply-chain-typosquat",
    lens: "security",
    text:
      "npm packages 'reqeusts', 'requests-py', and 'requrests' published this week each contain identical post-install scripts that exfiltrate the contents of ~/.aws/credentials and ~/.ssh/id_rsa to a Cloudflare Worker endpoint. All three packages combined have ~1,200 downloads since publication. Maintainer accounts created same week.",
    expected_severity_band: [8, 10],
  },
  {
    id: "sec-04-low-severity-disclosure",
    lens: "security",
    text:
      "Coordinated disclosure: a non-exploitable timing oracle was identified in version 4.x of an obscure XML parser used in <50 commercial products. Vendor confirmed fix in 4.7.1 released same day as disclosure. No PoC, no in-the-wild observations.",
    expected_severity_band: [2, 5],
  },
  {
    id: "sec-05-noise-marketing",
    lens: "security",
    text:
      "Acme Cybersecurity unveils new AI-powered SIEM platform at Black Hat USA, featuring 'next-generation correlation engine' and 'patented machine learning detection'. Free trial available for enterprise prospects. Customer logos include Fortune 500 names.",
    expected_severity_band: [0, 2],
  },

  // ─── SUPPLY-CHAIN (5) ────────────────────────────────────────────────────
  {
    id: "sc-01-supplier-fire",
    lens: "supply-chain",
    text:
      "Major fire at the only US fab plant producing automotive-grade silicon carbide modules; full production halt expected at least 8 weeks. Plant supplies 22% of US-market EV powertrain modules. Three OEMs already disclosed projected Q1 build-rate impact: 12-18% reduction in their EV truck lines.",
    expected_severity_band: [9, 10],
  },
  {
    id: "sc-02-port-strike",
    lens: "supply-chain",
    text:
      "International Longshoremen's Association announced 72-hour East Coast strike beginning December 1 unless contract terms met. Average daily TEU throughput at affected ports: 95,000. Estimated CPI impact if strike extends >2 weeks: +0.4 pp on consumer goods inflation.",
    expected_severity_band: [7, 9],
  },
  {
    id: "sc-03-rare-earth-export-control",
    lens: "supply-chain",
    text:
      "Country X announced new export licensing requirement for refined neodymium and dysprosium effective January 1, 2026. The country supplies 65% of global refined output. Licenses subject to 90-day review. Several non-defense end-use applications listed as 'restricted' pending case-by-case review.",
    expected_severity_band: [7, 10],
  },
  {
    id: "sc-04-weather-disruption-mild",
    lens: "supply-chain",
    text:
      "Heavy snowfall on Interstate 80 corridor caused 6-hour delays for trucking traffic between Sacramento and Reno on November 16. Normal operations expected resumption next day. No reported cargo damage.",
    expected_severity_band: [1, 4],
  },
  {
    id: "sc-05-noise-vendor-newsletter",
    lens: "supply-chain",
    text:
      "Our annual customer appreciation newsletter highlights warehouse safety achievements, employee of the quarter recognition, and a new partnership with a local recycling facility for shipping pallets. Free coffee mugs available at the front desk.",
    expected_severity_band: [0, 2],
  },
];

if (CALIBRATION_FIXTURES.length !== 20) {
  throw new Error(`Expected 20 fixtures, got ${CALIBRATION_FIXTURES.length}`);
}
