# Kiro IDE agent hooks — `@apohara/synthex`

These are **Kiro IDE hooks**: individual `*.kiro.hook` JSON files that the Kiro
editor runs automatically on an editor event (file save, agent stop, …). They
are the IDE-side QA net. The complementary **headless CLI path** is the
read-only QA team-buddy in `.kiro/agents/synthex-qa.json` (run on a separate
model; it never edits code, only verifies).

Each hook follows the confirmed Kiro schema:

```jsonc
{
  "enabled": true,
  "name": "…",
  "description": "…",
  "version": 1,
  "when": { "type": "<event>", "patterns": ["…"] },
  "then": { "type": "shellCommand", "command": "…" }   // or "askAgent" + "prompt"
}
```

Confirmed `when.type` enum (10): `fileCreate | fileEdited | fileDelete |
promptSubmit | agentStop | preToolUse | postToolUse | preTaskExecution |
postTaskExecution | userTriggered`. The canonical file-save value is
**`fileEdited`** (NOT `fileEdit`). `then.type` is exactly two: `shellCommand`
(free + deterministic — preferred here) or `askAgent` (consumes credits).

**There is NO native `on-commit` / `gitCommit` event.** "Pre-commit" is mapped
to `agentStop` — the honest approximation. We do not invent `onCommit`.

All four hooks use `then.type: shellCommand` (R8.5) and every command they call
already exists in this repo today (R8.6 — a hook calling a missing command is
dead).

## The hooks

| File | `when.type` | Patterns | Command | What it catches |
|---|---|---|---|---|
| `qa-on-save.kiro.hook` | `fileEdited` | `["src/**/*.js","!**/*.test.js"]` | `node --test && npm audit` | A regression (failing test) or a new dependency advisory the moment you save a non-test source file. |
| `report-integrity.kiro.hook` | `fileEdited` | `["src/prove/report/**/*.js"]` | `node scripts/gen-hero-report.mjs` | A report-source edit that silently drops a seal row. The script exits non-zero if the Ed25519 signature is absent, or if the Rekor logIndex / C2PA sidecar row would render DARK. |
| `seal-verify-smoke.kiro.hook` | `fileEdited` | `["src/prove/**/*.js","samples/*-evidence*.json"]` | `node bin/decode-evidence.js samples/synthex-evidence-report.json` | A broken seal: re-verifies hash + HMAC + RFC 3161 TSA (CMS chain vs pinned DigiCert) + the Ed25519 layer when present, on a committed sample. |
| `pre-commit-qa.kiro.hook` | `agentStop` | `[]` | `npm test` | A regression slipping into a commit — re-runs the full suite when the agent stops (the honest "pre-commit", since Kiro has no git event). |

## Honesty notes (the moat)

- **`qa-on-save`** — the FP-gate step (`measure-guard-fp` / `measure-guard-recall`)
  is intentionally *not* chained here yet: those scripts exist but their gate
  thresholds land with P1.2 (per R8.1 `<!-- the FP-gate step is added once P1.2
  ships its script -->`). Adding them now would assert a gate that isn't wired.

- **`report-integrity`** — `gen-hero-report.mjs` is a *reproducible* caller of
  `buildPDFReport()` with the committed C2PA sidecar + Rekor anchor, so the seal
  rows are load-bearing. It asserts on `sealRows()` in-process (PDFKit subset-CID
  fonts make grepping the emitted PDF useless), then fails if `rekorLogIndex` is
  null or the C2PA sidecar is absent.

- **`seal-verify-smoke`** — design R8.3 names an external **3-way** verify
  (`openssl ts` / `c2patool` / `rekor`). Those are external binaries **not wired
  into this repo's command set**, so this hook honestly runs the **in-repo
  offline verifier** (`bin/decode-evidence.js`) instead — a real verification
  that exists today (HMAC + TSA CMS-chain + Ed25519-when-present). The external
  3-way remains a roadmap item; this hook does not claim to run it.

- **`pre-commit-qa`** — `agentStop` is NOT a git commit hook. It cannot block a
  `git commit` issued outside Kiro. For a true commit gate, install an external
  `.git/hooks/pre-commit` (outside Kiro). The hook's `description` states this so
  no reader infers a `gitCommit` trigger that does not exist (R8.4).

## Verifying the commands by hand

```bash
node --test                                              # qa-on-save (tests)
npm audit                                                # qa-on-save (deps)
node scripts/gen-hero-report.mjs                         # report-integrity
node bin/decode-evidence.js samples/synthex-evidence-report.json  # seal-verify-smoke
npm test                                                 # pre-commit-qa
```
