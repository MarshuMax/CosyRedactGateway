// R3.3 -- one size point, one process, so peak RSS means something.
// In-process measurement over many sizes would keep old corpora alive and report the high-water
// mark of the whole run rather than of the point.
import { handleRequest, RedactionContext, redactJson } from "../worker.js";

const spec = JSON.parse(process.argv[2]);
const { kind, bytes } = spec;

// ---------------------------------------------------------------- corpus builders ---
function corpus(targetBytes) {
  if (kind === "clean") {
    // Pad by content, never by slicing -- a truncated body is invalid JSON -- and land AT OR BELOW
    // the target. The previous version rounded the repeat count UP and produced a body 18 bytes
    // OVER the 16 MiB default cap, which handleRequest correctly answered with 413; the harness then
    // reported 38ms for a whole 16 MiB request because the body was refused, not processed.
    const PAD = "lorem ipsum dolor sit amet ";
    const head = { model: "g", messages: [{ role: "user", content: "" }] };
    const overhead = JSON.stringify(head).length;
    const needed = Math.max(0, targetBytes - overhead);
    head.messages[0].content = PAD.repeat(Math.floor(needed / PAD.length));
    let body = JSON.stringify(head);
    // Top up with single characters while staying inside the target.
    while (body.length + 1 <= targetBytes) {
      head.messages[0].content += "x";
      body = JSON.stringify(head);
    }
    return body;
  }
  if (kind === "parser") {
    // Parser-heavy: many short config lines, which is what the structured-context parsers chew on.
    const lines = [];
    let n = 0;
    while (n < targetBytes) {
      const line = `service_${lines.length}: { host: svc-${lines.length}.internal, port: ${1000 + lines.length}, password: "\${VAULT_${lines.length}}" }`;
      lines.push(line);
      n += line.length + 1;
    }
    // Build to at least the target by LINE, then keep the JSON valid -- slicing the stringified
    // body would produce invalid JSON and measure the parse failure instead of the parser.
    const body = JSON.stringify({ model: "g", messages: [{ role: "user", content: lines.join("\n") }] });
    return body;
  }
  if (kind === "redaction") {
    // Redaction-heavy: every line carries a claimable secret.
    const lines = [];
    let n = 0;
    while (n < targetBytes) {
      const line = `DB_PASSWORD_${lines.length}=wJalrXUtnFEMI${String(lines.length).padStart(8, "0")}`;
      lines.push(line);
      n += line.length + 1;
    }
    const body = JSON.stringify({ model: "g", messages: [{ role: "user", content: lines.join("\n") }] });
    return body;
  }
  if (kind === "text") return "plain text body ".repeat(Math.ceil(targetBytes / 17)).slice(0, targetBytes);
  if (kind === "binary") return "BINARY".repeat(Math.ceil(targetBytes / 6)).slice(0, targetBytes);
  throw new Error("unknown kind " + kind);
}

const body = corpus(bytes);
const encoded = new TextEncoder().encode(body);

// ------------------------------------------------------------------- phases ---------
const phases = {};
const heap = () => process.memoryUsage().heapUsed;
let mark = heap();
const stage = (name, fn) => {
  const t0 = process.hrtime.bigint();
  const v = fn();
  phases[name] = Number(process.hrtime.bigint() - t0) / 1e6;
  mark = heap();
  void mark;
  return v;
};
const stageAsync = async (name, fn) => {
  const t0 = process.hrtime.bigint();
  const v = await fn();
  phases[name] = Number(process.hrtime.bigint() - t0) / 1e6;
  mark = heap();
  void mark;
  return v;
};

const baselineRss = process.memoryUsage().rss;
const baselineHeap = process.memoryUsage().heapUsed;
let peakRss = baselineRss;
let peakHeap = baselineHeap;
const sampler = setInterval(() => {
  const m = process.memoryUsage();
  if (m.rss > peakRss) peakRss = m.rss;
  if (m.heapUsed > peakHeap) peakHeap = m.heapUsed;
}, 2);

let result;
if (spec.side === "request" && spec.mode === "phases") {
  // PHASES MODE ONLY. Separate process from the E2E run so the memory sampler never spans both --
  // the earlier single-process version ran handleRequest and then the instrumented pipeline, and
  // reported the high-water mark of the TWO together, which overstates a single request.
  const text = await stageAsync("decode", async () => new TextDecoder().decode(encoded));
  const parsed = stage("jsonParse", () => JSON.parse(text));
  const ctx = new RedactionContext({ salt: "perf", maxRedactions: 1e9 });
  const redacted = await stageAsync("redactJson", () => redactJson(parsed, ctx, { gitleaks: true, highEntropy: true, email: true }));
  const out = stage("stringify", () => JSON.stringify(redacted));
  result = { outBytes: out.length, tokens: ctx.rawToToken.size };
} else if (spec.side === "request") {
  // E2E MODE ONLY. The instrumented pipeline runs in a SEPARATE process (mode=phases), because a
  // memory sampler that spans both reports the high-water mark of two executions rather than of one
  // request.
  //
  // Two tracks, because one cannot serve both purposes honestly.
  //
  // E2E: the real request path through handleRequest, with a fake fetchImpl that answers
  // immediately, so the measured cost IS the forward path. This is the authoritative baseline for
  // total time, peak heap, peak RSS and output size. It deliberately does NOT re-implement
  // handleRequest: an earlier version copied the pipeline by hand, used request.arrayBuffer()
  // instead of readBodyCapped(), and dropped redactJson's return value -- and redactJson BUILDS A
  // NEW TREE rather than mutating in place, so that version stringified the ORIGINAL object and
  // reported the wrong heap, stringify time and output size.
  //
  // PHASES: a separate instrumented run over the same corpus, kept only for phase attribution.
  // It parses the body itself, so its read/decode numbers are indicative rather than production
  // (the production read is a counted streaming read with a cap).
  // A FRESH Request per measurement. `request.body` is a one-shot stream, so reusing one object
  // meant the second read saw an exhausted body and returned early -- the 16 MiB run reported 6.8ms
  // for the whole E2E path because the stream had already been consumed.
  const makeRequest = () => {
    const stream = new ReadableStream({
      start(c) {
        const CH = 1 << 16;
        for (let at = 0; at < encoded.length; at += CH) c.enqueue(encoded.subarray(at, at + CH));
        c.close();
      },
    });
    return new Request("https://p/H$https://api.example/v1/chat/completions", {
      method: "POST", headers: { "content-type": "application/json" }, body: stream, duplex: "half",
    });
  };
  const e2eOut = await stageAsync("handleRequestE2E", async () => {
    const res = await handleRequest(makeRequest(), {}, {
      // A tiny response, so the measured body is the REQUEST forward path.
      fetchImpl: async () => new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: "ok" } }] }), { headers: { "content-type": "application/json" } }),
      salt: "perf",
    });
    return (await res.text()).length;
  });

  result = { outBytes: e2eOut };
} else if (spec.sse) {
  // SSE: build a stream of delta events whose deltas total the target size, then drive it through
  // handleRequest so restoreSseStream, streamFields and the per-event policy all run for real.
  const CHUNK = 8192;
  const payload = "streamed assistant text ".repeat(Math.ceil(bytes / 24)).slice(0, bytes);
  const events = [];
  for (let at = 0; at < payload.length; at += CHUNK) {
    events.push(`event: response.output_text.delta\ndata: ${JSON.stringify({ type: "response.output_text.delta", delta: payload.slice(at, at + CHUNK) })}\n\n`);
  }
  events.push("data: [DONE]\n\n");
  const streamBody = events.join("");
  const request = new Request("https://p/H$https://api.example/v1/chat/completions", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "g", messages: [{ role: "user", content: "PASSWORD=wJalrXUtnFEMIK7MDENGbPxRfiCY" }] }),
  });
  const out = await stageAsync("handleRequest", async () => {
    const res = await handleRequest(request, {}, {
      fetchImpl: async () => new Response(streamBody, { headers: { "content-type": "text/event-stream" } }),
      salt: "perf",
    });
    return (await res.text()).length;
  });
  result = { outBytes: out, events: events.length - 1 };
} else {
  // RESPONSE SIDE, non-stream. Driven through handleRequest so the measured cost is the REAL path
  // -- an earlier version built the response object inline and skipped restoreNonStreamResponse
  // entirely, which reported 0.2ms of policy work and hid the whole pipeline.
  const contentType = kind === "binary" ? "application/octet-stream" : kind === "text" ? "text/plain" : "application/json";
  const request = new Request("https://p/H$https://api.example/v1/chat/completions", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "g", messages: [{ role: "user", content: "PASSWORD=wJalrXUtnFEMIK7MDENGbPxRfiCY" }] }),
  });
  const out = await stageAsync("handleRequest", async () => {
    const res = await handleRequest(request, {}, {
      fetchImpl: async () => new Response(body, { headers: { "content-type": contentType } }),
      salt: "perf",
    });
    return (await res.text()).length;
  });
  result = { outBytes: out };
}
clearInterval(sampler);
const m = process.memoryUsage();
if (m.rss > peakRss) peakRss = m.rss;
if (m.heapUsed > peakHeap) peakHeap = m.heapUsed;

// `total` must be the AUTHORITATIVE path cost, not the sum of every measurement taken.
// On the request side the E2E run and the instrumented phase run are SEPARATE executions of the
// same corpus, so summing them double-counts and made the 16 MiB row look like 3803ms when the
// real request path was 6.7ms + its own work. phases is attribution only.
const total = phases.handleRequestE2E !== undefined
  ? phases.handleRequestE2E
  : Object.values(phases).reduce((a, b) => a + b, 0);
process.stdout.write(JSON.stringify({
  kind, side: spec.side, requested: bytes, bodyBytes: body.length,
  phases, total,
  peakRssMiB: peakRss / 1048576, peakHeapMiB: peakHeap / 1048576,
  baselineRssMiB: baselineRss / 1048576, baselineHeapMiB: baselineHeap / 1048576,
  result,
}));
