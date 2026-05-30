// Tests del Speechmatics batch client. Integration: stub http.createServer fakes the /v2/jobs flow
// (submit→poll→transcript) — NUNCA toca el endpoint real de Speechmatics en la suite. baseUrl se
// inyecta apuntando al stub. Live: opt-in con SPEECHMATICS_LIVE=1 (skipped por defecto).
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { SpeechmaticsClient, buildEnvelope } from "../../src/fetch/speechmatics-client.js";

/**
 * Spin up a stub Speechmatics server. `behaviour` controls the job lifecycle so each test can drive
 * happy path / rejected / timeout. Returns { baseUrl, close, requests } for assertions + teardown.
 */
function startStub(behaviour = {}) {
  const {
    finalStatus = "done", // status returned after `pollsUntilFinal` checks
    pollsUntilFinal = 1, // number of status checks before the final status shows up
    jobId = "job_stub_1",
    transcript = {
      results: [
        { type: "word", start_time: 0.0, end_time: 0.5, alternatives: [{ content: "Revenue", speaker: "S1" }] },
        { type: "word", start_time: 0.5, end_time: 0.9, alternatives: [{ content: "grew", speaker: "S1" }] },
        { type: "punctuation", start_time: 0.9, end_time: 0.9, alternatives: [{ content: ".", speaker: "S1" }] },
      ],
      metadata: { transcription_config: { language: "en" } },
    },
  } = behaviour;

  const requests = [];
  let pollCount = 0;

  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    requests.push({ method: req.method, url: req.url, auth: req.headers.authorization, length: body.length });

    const send = (code, obj) => {
      res.writeHead(code, { "Content-Type": "application/json" });
      res.end(JSON.stringify(obj));
    };

    // Submit: POST /v2/jobs/
    if (req.method === "POST" && req.url === "/jobs/") {
      return send(201, { id: jobId });
    }
    // Transcript: GET /v2/jobs/:id/transcript?format=json
    if (req.method === "GET" && req.url.startsWith(`/jobs/${jobId}/transcript`)) {
      return send(200, transcript);
    }
    // Poll: GET /v2/jobs/:id
    if (req.method === "GET" && req.url === `/jobs/${jobId}`) {
      pollCount++;
      const status = pollCount >= pollsUntilFinal ? finalStatus : "running";
      return send(200, { job: { id: jobId, status } });
    }
    return send(404, { error: "not found" });
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        requests,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

const AUDIO = new Uint8Array([0x52, 0x49, 0x46, 0x46]); // 4 dummy bytes ("RIFF")

test("speechmatics: falta API key lanza error claro (config error, no fail-safe)", () => {
  assert.throws(
    () => new SpeechmaticsClient({ apiKey: null }),
    /Falta SPEECHMATICS_API_KEY/,
  );
});

test("speechmatics: happy path submit→done→transcript → envelope SEAL-READY", async () => {
  const stub = await startStub({ pollsUntilFinal: 2 }); // running once, then done
  try {
    const c = new SpeechmaticsClient({ apiKey: "tok", baseUrl: stub.baseUrl });
    const env = await c.transcribe(AUDIO, {
      language: "en",
      domain: "finance",
      diarization: "speaker",
      enableEntities: true,
      operatingPoint: "enhanced",
      intervalMs: 0,
      sleep: async () => {},
    });

    assert.equal(env.ok, true);
    assert.equal(env.jobId, "job_stub_1");
    assert.equal(env.surface, "speechmatics");
    assert.equal(env.language, "en");
    assert.equal(typeof env.fetchedAt, "string");
    assert.equal(env.transcript_text, "Revenue grew.");
    assert.equal(env.words.length, 3);
    assert.deepEqual(env.words[0], { content: "Revenue", start: 0.0, end: 0.5, speaker: "S1" });
    assert.ok(env.raw && Array.isArray(env.raw.results));

    // Submit carried Bearer auth + a non-empty multipart body; we polled at least twice (running→done).
    const submit = stub.requests.find((r) => r.method === "POST");
    assert.equal(submit.auth, "Bearer tok");
    assert.ok(submit.length > 0, "multipart body should be non-empty");
    const polls = stub.requests.filter((r) => r.method === "GET" && r.url === "/jobs/job_stub_1");
    assert.ok(polls.length >= 2, "should have polled running→done");
  } finally {
    await stub.close();
  }
});

test("speechmatics: job rejected → structured error (no throw)", async () => {
  const stub = await startStub({ finalStatus: "rejected", pollsUntilFinal: 1 });
  try {
    const c = new SpeechmaticsClient({ apiKey: "tok", baseUrl: stub.baseUrl });
    const out = await c.transcribe(AUDIO, { intervalMs: 0, sleep: async () => {} });
    assert.equal(out.ok, false);
    assert.equal(out.status, "rejected");
    assert.match(out.error, /rejected/);
    assert.equal(out.stage, "poll");
  } finally {
    await stub.close();
  }
});

test("speechmatics: poll timeout (never done) → bounded structured error (no infinite loop)", async () => {
  const stub = await startStub({ finalStatus: "running", pollsUntilFinal: 999 }); // never reaches done
  try {
    const c = new SpeechmaticsClient({ apiKey: "tok", baseUrl: stub.baseUrl });
    const out = await c.transcribe(AUDIO, { maxAttempts: 3, intervalMs: 0, sleep: async () => {} });
    assert.equal(out.ok, false);
    assert.equal(out.stage, "poll");
    assert.match(out.error, /not done after 3 polls/);
    const polls = stub.requests.filter((r) => r.method === "GET" && r.url === "/jobs/job_stub_1");
    assert.equal(polls.length, 3, "bounded to exactly maxAttempts polls");
  } finally {
    await stub.close();
  }
});

test("speechmatics: non-2xx on submit → structured error (no throw)", async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(402, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "payment required" }));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  try {
    const c = new SpeechmaticsClient({ apiKey: "tok", baseUrl: `http://127.0.0.1:${port}` });
    const out = await c.submitJob(AUDIO);
    assert.equal(out.ok, false);
    assert.equal(out.stage, "submit");
    assert.equal(out.status, 402);
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test("speechmatics: finance knobs land in transcription_config (no input mutation)", async () => {
  let capturedConfig;
  const fetchImpl = async (url, init) => {
    if (init?.method === "POST") {
      capturedConfig = JSON.parse(init.body.get("config"));
    }
    return { ok: true, json: async () => ({ id: "j1" }) };
  };
  const c = new SpeechmaticsClient({ apiKey: "tok", baseUrl: "http://stub", fetchImpl });
  const opts = Object.freeze({ language: "es", domain: "finance", diarization: "speaker", enableEntities: true, operatingPoint: "enhanced" });
  const res = await c.submitJob(AUDIO, opts); // frozen opts → would throw if we mutated it
  assert.equal(res.ok, true);
  assert.deepEqual(capturedConfig, {
    type: "transcription",
    transcription_config: {
      language: "es",
      domain: "finance",
      diarization: "speaker",
      enable_entities: true,
      operating_point: "enhanced",
    },
  });
});

test("speechmatics: buildEnvelope flattens results and joins text", () => {
  const env = buildEnvelope("jX", {
    results: [
      { type: "word", start_time: 1, end_time: 2, alternatives: [{ content: "Hello" }] },
      { type: "word", start_time: 2, end_time: 3, alternatives: [{ content: "world" }] },
      { type: "punctuation", start_time: 3, end_time: 3, alternatives: [{ content: "!" }] },
    ],
  }, { language: "en" });
  assert.equal(env.transcript_text, "Hello world!");
  assert.equal(env.words.length, 3);
  assert.equal(env.words[0].speaker, undefined);
  assert.equal(env.language, "en");
});

// ─── LIVE smoke test (opt-in) ────────────────────────────────────────────────
// Requires SPEECHMATICS_LIVE=1 + SPEECHMATICS_API_KEY + a real audio file path in SPEECHMATICS_AUDIO.
// Skipped by default — never hits the real endpoint in CI.
test("speechmatics LIVE: real submit→transcribe — opt-in", { skip: process.env.SPEECHMATICS_LIVE !== "1" }, async () => {
  const { readFile } = await import("node:fs/promises");
  const audioPath = process.env.SPEECHMATICS_AUDIO;
  assert.ok(audioPath, "SPEECHMATICS_AUDIO must point at a real audio file for the live smoke test");
  const audio = await readFile(audioPath);
  const c = new SpeechmaticsClient(); // reads SPEECHMATICS_API_KEY from env
  const env = await c.transcribe(audio, { language: "en", domain: "finance", maxAttempts: 60, intervalMs: 5000, filename: audioPath.split("/").pop() });
  assert.equal(env.ok, true, `live transcribe failed: ${env.error ?? ""}`);
  assert.equal(typeof env.transcript_text, "string");
});
