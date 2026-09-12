// R3.3 -- one size point, one process, so peak RSS means something.
// In-process measurement over many sizes would keep old corpora alive and report the high-water
// mark of the whole run rather than of the point.
import { handleRequest, RedactionContext, redactJson } from "../worker.js";

const spec = JSON.parse(process.argv[2]);
const { kind, bytes } = spec;

// ---------------------------------------------------------------- corpus builders ---
function corpus(targetBytes) {
  if (kind === "clean") {
    // Pad a simple message so the JSON envelope is most of the body.
    const head = { model: "g", messages: [{ role: "user", content: "" }] };
    const base = JSON.stringify(head).length;
    head.messages[0].content = "lorem ipsum dolor sit amet ".repeat(Math.ceil((targetBytes - base) / 27));
    // Pad by content, never by slicing: a truncated body is invalid JSON.
    return JSON.stringify(head);
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
    return JSON.stringify({ model: "g", messages: [{ role: "user", content: lines.join("\n") }] });
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
    return JSON.stringify({ model: "g", messages: [{ role: "user", content: lines.join("\n") }] });
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
if (spec.side === "request") {
  // capped read, then decode, parse, redact, stringify -- mirroring handleRequest's own order.
  const stream = new ReadableStream({
    start(c) {
      const CH = 1 << 16;
      for (let at = 0; at < encoded.length; at += CH) c.enqueue(encoded.subarray(at, at + CH));
      c.close();
    },
  });
  const request = new Request("https://p/H$https://api.example/v1/chat/completions", {
    method: "POST", headers: { "content-type": "application/json" }, body: stream, duplex: "half",
  });
  const bytesRead = await stageAsync("read", async () => new Uint8Array(await request.arrayBuffer()).length);
  const text = await stageAsync("decode", async () => new TextDecoder().decode(encoded));
  const data = stage("jsonParse", () => JSON.parse(text));
  const ctx = new RedactionContext({ salt: "perf", maxRedactions: 1e9 });
  await stageAsync("redactJson", () => redactJson(data, ctx, { gitleaks: true, highEntropy: true, email: true }));
  const out = stage("stringify", () => JSON.stringify(data));
  result = { bytesRead, outBytes: out.length, tokens: ctx.rawToToken.size };
} else {
  // Response side: the upstream body is already a string, then parse, policy, stringify.
  const { applyResponsePolicy } = await import("../worker.js");
  const ctx = new RedactionContext({ salt: "perf", maxRedactions: 1e9 });
  if (kind === "binary" || kind === "text") {
    const out = await stageAsync("passthroughText", async () => body);
    result = { outBytes: out.length };
  } else if (spec.sse) {
    // SSE is streamed, so there is no whole-body parse.
    const { restoreSseStream } = await import("../worker.js");
    const event = `event: response.output_text.delta\ndata: ${JSON.stringify({ type: "response.output_text.delta", delta: body.slice(0, 4096) })}\n\ndata: [DONE]\n\n`;
    const out = await stageAsync("sse", async () => new Response(restoreSseStream(new Response(event).body, ctx)).text());
    result = { outBytes: out.length };
  } else {
    const text = await stageAsync("readText", async () => body);
    const data = stage("jsonParse", () => JSON.parse(text));
    await stageAsync("applyResponsePolicy", async () => applyResponsePolicy(data, ctx, null, null));
    const out = stage("stringify", () => JSON.stringify(data));
    result = { outBytes: out.length };
  }
}

clearInterval(sampler);
const m = process.memoryUsage();
if (m.rss > peakRss) peakRss = m.rss;
if (m.heapUsed > peakHeap) peakHeap = m.heapUsed;

process.stdout.write(JSON.stringify({
  kind, side: spec.side, requested: bytes, bodyBytes: body.length,
  phases, total: Object.values(phases).reduce((a, b) => a + b, 0),
  peakRssMiB: peakRss / 1048576, peakHeapMiB: peakHeap / 1048576,
  baselineRssMiB: baselineRss / 1048576, baselineHeapMiB: baselineHeap / 1048576,
  result,
}));
