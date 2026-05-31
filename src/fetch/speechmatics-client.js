// SPEECHMATICS (batch ASR) — submits an audio file to the Speechmatics Batch v2 API, polls the job
// until done (BOUNDED — never infinite), fetches the transcript and returns a SEAL-READY envelope.
//
// Why this exists: agents increasingly scrape AUDIO (earnings calls, interviews, podcasts). Synthex
// classifies + seals what agents scrape; this client makes spoken evidence first-class so the pipeline
// can seal a transcript the same way it seals text. Speechmatics keeps job artifacts ~7 days upstream,
// so the caller MUST seal the returned envelope immediately (the envelope carries everything to seal).
//
// HONESTY: confirmed live (gate-probed 2026-05-30, key valid) against the EU endpoint below. Finance
// tuning knobs (domain:"finance", diarization, entities, enhanced) are passed straight into
// transcription_config — Speechmatics ignores ones it does not support rather than rejecting the job.
//
// FAIL-SAFE: a missing API key throws (a configuration error the caller must fix). Every recoverable
// external failure (non-2xx, network error, timeout, rejected job, poll exhaustion) returns a
// structured { ok:false, ... } result instead of throwing, so the pipeline never crashes on a bad fetch.
const DEFAULT_BASE_URL = "https://eu1.asr.api.speechmatics.com/v2";

/** Structured fail-safe result. Never thrown — returned so callers branch on `ok`. */
function errorResult(stage, message, extra = {}) {
  return { ok: false, surface: "speechmatics", stage, error: String(message), ...extra };
}

/** Reads a Response body as text without ever throwing (used only for error context). */
async function safeText(res) {
  try {
    return (await res.text()).slice(0, 200);
  } catch {
    return "";
  }
}

export class SpeechmaticsClient {
  /**
   * @param {{apiKey?:string, baseUrl?:string, fetchImpl?:Function}} [opts]
   *   apiKey   — defaults to process.env.SPEECHMATICS_API_KEY (throws if absent).
   *   baseUrl  — override the API base (used by tests to point at a stub http server).
   *   fetchImpl — injectable fetch (defaults to the built-in global fetch).
   */
  constructor({ apiKey, baseUrl, fetchImpl } = {}) {
    this.apiKey = apiKey ?? process.env.SPEECHMATICS_API_KEY ?? null;
    if (!this.apiKey) {
      throw new Error("Falta SPEECHMATICS_API_KEY para la Speechmatics Batch API.");
    }
    // Trim a trailing slash so `${baseUrl}/jobs/` never doubles up.
    this.baseUrl = String(baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.fetchImpl = fetchImpl ?? fetch;
  }

  #authHeaders() {
    return { Authorization: `Bearer ${this.apiKey}` };
  }

  /**
   * Build the transcription_config from finance-tuning opts WITHOUT mutating the caller's object.
   * Only keys the caller opted into are added (Speechmatics ignores unsupported keys anyway).
   * @returns {object} a fresh transcription_config
   */
  #buildTranscriptionConfig({
    language = "en",
    domain,
    diarization,
    enableEntities,
    operatingPoint,
    transcriptionConfig = {},
  }) {
    const cfg = { ...transcriptionConfig, language };
    if (domain !== undefined) cfg.domain = domain;
    if (diarization !== undefined) cfg.diarization = diarization;
    if (enableEntities !== undefined) cfg.enable_entities = enableEntities;
    if (operatingPoint !== undefined) cfg.operating_point = operatingPoint;
    return cfg;
  }

  /**
   * Submit an audio file for batch transcription. POST multipart to /jobs/ with a `config` JSON part
   * and a `data_file` part. Returns { ok:true, id } on success, or a structured error result.
   * @param {Uint8Array|ArrayBuffer|Blob|Buffer} audio  the audio bytes.
   * @param {{filename?:string, contentType?:string, timeoutMs?:number} & object} [opts]  finance knobs + io.
   */
  async submitJob(audio, opts = {}) {
    const { filename = "audio.wav", contentType = "application/octet-stream", timeoutMs = 60000 } = opts;
    const transcriptionConfig = this.#buildTranscriptionConfig(opts);
    const config = { type: "transcription", transcription_config: transcriptionConfig };

    let form;
    try {
      form = new FormData();
      form.append("config", JSON.stringify(config));
      const blob = audio instanceof Blob ? audio : new Blob([audio], { type: contentType });
      form.append("data_file", blob, filename);
    } catch (err) {
      return errorResult("submit", err?.message ?? err, { stageDetail: "form-build" });
    }

    try {
      const res = await this.fetchImpl(`${this.baseUrl}/jobs/`, {
        method: "POST",
        headers: this.#authHeaders(), // do NOT set Content-Type: FormData sets the multipart boundary.
        body: form,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) {
        return errorResult("submit", `HTTP ${res.status}: ${await safeText(res)}`, { status: res.status });
      }
      const json = await res.json();
      const id = json?.id ?? json?.job?.id ?? null;
      if (!id) return errorResult("submit", "respuesta sin job id", { raw: json });
      return { ok: true, surface: "speechmatics", id, language: transcriptionConfig.language };
    } catch (err) {
      return errorResult("submit", err?.message ?? err);
    }
  }

  /**
   * Single status check for a job → { ok:true, status } where status is running|done|rejected (etc.),
   * or a structured error result. No waiting here — `pollUntilDone` orchestrates the bounded loop.
   */
  async getJobStatus(jobId, { timeoutMs = 20000 } = {}) {
    try {
      const res = await this.fetchImpl(`${this.baseUrl}/jobs/${encodeURIComponent(jobId)}`, {
        headers: this.#authHeaders(),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) {
        return errorResult("poll", `HTTP ${res.status}: ${await safeText(res)}`, { status: res.status });
      }
      const json = await res.json();
      const status = String(json?.job?.status ?? json?.status ?? "").toLowerCase();
      return { ok: true, surface: "speechmatics", status, raw: json };
    } catch (err) {
      return errorResult("poll", err?.message ?? err);
    }
  }

  /**
   * Poll a job until it is done (BOUNDED — never infinite; capped by maxAttempts + delay).
   * Returns { ok:true, status:"done" } when finished, or a structured error result for a rejected
   * job, a failed status check, or exhausted attempts. `sleep` is injectable for fast tests.
   * @param {string} jobId
   * @param {{maxAttempts?:number, intervalMs?:number, sleep?:Function, timeoutMs?:number}} [opts]
   */
  async pollUntilDone(jobId, { maxAttempts = 30, intervalMs = 5000, sleep, timeoutMs = 20000 } = {}) {
    const wait = sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    let last = "";
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const s = await this.getJobStatus(jobId, { timeoutMs });
      if (!s.ok) return s; // propagate the structured error (e.g. network/HTTP failure)
      last = s.status;
      if (last === "done") return { ok: true, surface: "speechmatics", status: "done" };
      if (last === "rejected") {
        return errorResult("poll", `job ${jobId} rejected`, { jobId, status: "rejected", raw: s.raw });
      }
      if (attempt < maxAttempts - 1) await wait(intervalMs);
    }
    return errorResult("poll", `job ${jobId} not done after ${maxAttempts} polls (status="${last}"). Bounded by cost cap.`, {
      jobId,
      status: last,
    });
  }

  /**
   * Fetch the JSON transcript of a finished job → { ok:true, raw } (the raw Speechmatics payload),
   * or a structured error result.
   */
  async getTranscript(jobId, { timeoutMs = 30000 } = {}) {
    try {
      const res = await this.fetchImpl(
        `${this.baseUrl}/jobs/${encodeURIComponent(jobId)}/transcript?format=json`,
        { headers: this.#authHeaders(), signal: AbortSignal.timeout(timeoutMs) },
      );
      if (!res.ok) {
        return errorResult("transcript", `HTTP ${res.status}: ${await safeText(res)}`, { status: res.status });
      }
      const raw = await res.json();
      return { ok: true, surface: "speechmatics", raw };
    } catch (err) {
      return errorResult("transcript", err?.message ?? err);
    }
  }

  /**
   * Full happy-path: submit → poll until done → fetch transcript → build the SEAL-READY envelope.
   * Returns the envelope on success, or the first structured error result encountered (fail-safe).
   * The caller MUST seal the envelope immediately (Speechmatics retains artifacts ~7 days upstream).
   * @param {Uint8Array|ArrayBuffer|Blob|Buffer} audio
   * @param {object} [opts]  finance knobs + io + poll knobs (see submit/pollUntilDone).
   * @returns {Promise<object>} seal-ready envelope or { ok:false, ... }
   */
  async transcribe(audio, opts = {}) {
    const submitted = await this.submitJob(audio, opts);
    if (!submitted.ok) return submitted;

    const polled = await this.pollUntilDone(submitted.id, opts);
    if (!polled.ok) return polled;

    const fetched = await this.getTranscript(submitted.id, opts);
    if (!fetched.ok) return fetched;

    return buildEnvelope(submitted.id, fetched.raw, { language: submitted.language });
  }
}

/**
 * Build the SEAL-READY envelope from a raw Speechmatics transcript payload. Pure + deterministic
 * (no I/O), so it is unit-testable in isolation and used by `transcribe()`.
 *
 * Speechmatics returns { results:[ {type, start_time, end_time, alternatives:[{content, speaker?}]} ] };
 * we flatten the highest-confidence alternative per result into words[] and join into transcript_text.
 * @param {string} jobId
 * @param {object} raw  raw transcript payload from /jobs/:id/transcript
 * @param {{language?:string}} [meta]
 * @returns {object} { ok, jobId, surface, fetchedAt, language, transcript_text, words, raw }
 */
export function buildEnvelope(jobId, raw, { language } = {}) {
  const results = Array.isArray(raw?.results) ? raw.results : [];
  const words = [];
  let text = "";
  for (const r of results) {
    const alt = Array.isArray(r?.alternatives) ? r.alternatives[0] : undefined;
    const content = alt?.content;
    if (content === undefined || content === null) continue;
    // Build a fresh word record; never mutate the source result.
    const word = { content, start: r.start_time, end: r.end_time };
    if (alt.speaker !== undefined) word.speaker = alt.speaker;
    words.push(word);
    // Speechmatics emits punctuation as its own result (type:"punctuation") — attach it to the
    // preceding word without a leading space; everything else gets a separating space, but only
    // once `text` already holds a word. Skip empty content so an empty result never leaves a double
    // space; skip leading punctuation (no preceding word) so it never starts the text — both cases
    // would otherwise force a stray leading/double space into transcript_text.
    if (content === "") continue;
    if (r.type === "punctuation") {
      if (text) text += content;
    } else {
      text += (text ? " " : "") + content;
    }
  }
  // Detected language can live at the payload root; fall back to the requested language.
  const detectedLanguage =
    raw?.metadata?.transcription_config?.language ?? raw?.metadata?.language ?? language;
  return {
    ok: true,
    jobId,
    surface: "speechmatics",
    fetchedAt: new Date().toISOString(),
    language: detectedLanguage,
    transcript_text: text,
    words,
    raw,
  };
}
