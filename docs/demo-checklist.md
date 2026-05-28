# Synthex v0.6.0 — Demo Pre-Show Checklist

**Purpose:** make the live demo of `synthex.apohara.dev/playground.html`
boring (in a good way). No surprises, no first-time Cognee cold start in
front of judges, no stale Vercel cache, no missing TSA reachability.

> Marked NON-BLOCKING in the PRD (SC-17), but every minute spent here saves
> minutes of awkward "loading…" during the demo.

---

## T-60 min — Environment

- [ ] `source ~/.config/apohara/secrets.env` in the demo shell (AIML_API_KEY,
      BRIGHT_DATA_TOKEN, NPM_TOKEN, VERCEL_TOKEN present).
- [ ] `node --version` reports v24.x (Krypton LTS).
- [ ] `npm test` passes locally (262 / 252 / 0 fail expected).
- [ ] `npm run lint:slides` exits 0.
- [ ] `git status -sb` shows working tree clean on `main` (or release tag).

## T-30 min — Warm services

- [ ] `node scripts/bench-tsa-rtt.mjs --samples=5` — DigiCert reachable,
      p95 < 1500 ms. If it fails, write to backup TSA list (`docs/PERFORMANCE.md`).
- [ ] `node scripts/warmup-cognee.mjs` if you plan to demo with
      `COGNEE_LIVE=1`. Cold start is 12-25 s and YOU DO NOT WANT THAT IN
      FRONT OF JUDGES.
- [ ] `curl -I https://synthex.apohara.dev` returns 200. If 503/404, redeploy
      from Vercel dashboard (Production Branch should be `main`).
- [ ] `curl -I https://synthex.apohara.dev/playground.html` returns 200.
- [ ] `curl -I https://synthex.apohara.dev/dashboard.html` returns 200.

## T-15 min — Pre-loaded artifacts

- [ ] Open `out/stress-500-2026-05-28/report.json` in a tab. **If the live
      stress fails on stage, this is your fallback** ("here are 500 URLs
      we ran offline — same pipeline, same evidence shape").
- [ ] Have `samples/synthex-evidence-report.pdf` open in a PDF reader.
- [ ] Have `docs/v060-stress-report.md` open as a reading reference.

## T-5 min — Browser tabs in order

| Tab | URL | Why |
|---|---|---|
| 1 | `synthex.apohara.dev/` | Landing — context + market framing |
| 2 | `synthex.apohara.dev/playground.html` | Live demo target |
| 3 | `synthex.apohara.dev/dashboard.html` | If you trigger the stress live |
| 4 | local `out/stress-500-2026-05-28/report.json` | Honest numbers backup |
| 5 | `github.com/SuarezPM/apohara-synthex` | Repo for "show the code" |
| 6 | `npmjs.com/package/@apohara/synthex` | Provenance badge live |

## T-2 min — Microphone/screen

- [ ] Mic test, screen-share resolution at least 1920×1080.
- [ ] Close Slack/Discord/email notifications.
- [ ] Increase terminal font size (28 px) and dark theme.

---

## During the demo

### Script (90 seconds)

1. **Hook (10 s)**: "Your agent scraped this URL yesterday. Did the price
   change today? With proof?"
2. **Playground demo (30 s)**: paste `stripe.com/pricing`, hit Analyze.
   Show JSON evidence with `contentHash`, `seal.rfc3161Tsa.serial`. Download
   the PDF.
3. **Watch demo (20 s)**: hit Watch (60 s loop). First reading = cold start
   (previous_tsa_serial: null). Wait one tick. Second reading = chain
   (previous → current serial). "Both readings provably exist."
4. **Show the chain (15 s)**: in another tab `node bin/decode-evidence.js
   downloaded-evidence.json` — show the Delta Chain block.
5. **Close (15 s)**: "500 URLs in 9 min for 75 cents. Repo public, MIT,
   SLSA L3 + npm provenance. Try it yourself: `npx @apohara/synthex --demo`."

### If something fails on stage

| Symptom | Recovery |
|---|---|
| Playground hangs > 30 s | Cancel, switch to pre-loaded `out/stress-500-2026-05-28/evidence-NNNN.json` and `node bin/decode-evidence.js` it. |
| TSA returns 503 | Show the bench output `logs/digicert-rtt-baseline.json` — "yesterday at 16:15 UTC, p95 385 ms; DigiCert is having a bad afternoon, the architecture handles this with `--no-kg` fallback." |
| Vercel cold start > 5 s | Pre-warm by hitting the playground once T-1 min before going on stage. |
| Cognee MCP not ready | Don't activate COGNEE_LIVE during the demo. Mention it as "the opt-in cold path" without invoking it. |

---

## Rehearsal log

Re-run this checklist at least 3 times before the actual demo. Record the
results so you know which step is brittle on your network:

```
[ ] Run 1: date / time / outcome / notes
[ ] Run 2: date / time / outcome / notes
[ ] Run 3: date / time / outcome / notes
```
