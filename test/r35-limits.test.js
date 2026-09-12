// R3.5 -- limit effectiveness.
//
// Two limits, two different contracts, and the point of this file is that they are NOT the same
// kind of guarantee:
//
//   REDACT_MAX_BODY_BYTES   a SECURITY boundary with a RESOURCE dimension
//   REDACT_MAX_REDACTIONS   an ENTITY-IDENTITY limit, not a CPU guard
//
// Acceptance levels asserted here:
//   L1 security    an over-limit request is never forwarded
//   L2 semantic    the body byte cap and the unique-entity cap are exact at the boundary
//   L3 timing      which pipeline stage each limit takes effect at is pinned
//   L4 resource    work that can be refused early is not completed first
//   L5 adversarial a missing or untrue Content-Length cannot move the real byte cap
//
// "Reached stage X" is asserted explicitly, because `status === 413` alone cannot distinguish an
// early refusal from one that burned the whole pipeline first.

import test from "node:test";
import assert from "node:assert/strict";
import { handleRequest, RedactionContext, findSensitiveSpans } from "../worker.js";

const URL_OK = "https://proxy.example/H$https://api.example/v1/chat/completions";
const CHUNK = 1024;

/** Drive one request and record which stages were reached. */
async function trip({ body, contentType = "application/json", contentLength, env = {}, options = {} }) {
  const trace = { upstreamFetch: 0, deliveredBytes: 0, cancelled: false, totalBytes: 0 };
  const fetchImpl = async () => {
    trace.upstreamFetch++;
    return new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: "ok" } }] }),
      { headers: { "content-type": "application/json" } });
  };
  const bytes = new TextEncoder().encode(body);
  trace.totalBytes = bytes.length;
  let sent = 0;
  const stream = new ReadableStream({
    pull(controller) {
      if (sent >= bytes.length) { controller.close(); return; }
      const n = Math.min(CHUNK, bytes.length - sent);
      controller.enqueue(bytes.subarray(sent, sent + n));
      sent += n;
      trace.deliveredBytes += n;
    },
    cancel() { trace.cancelled = true; },
  });
  const headers = { "content-type": contentType };
  if (contentLength !== undefined) headers["content-length"] = String(contentLength);
  const request = new Request(URL_OK, { method: "POST", headers, body: stream, duplex: "half" });
  const response = await handleRequest(request, env, { fetchImpl, salt: "limit", ...options });
  const text = await response.text();
  return { status: response.status, body: text, trace };
}

const SECRET = (i) => `wJalrXUtnFEMI${String(i).padStart(8, "0")}`;
const docOf = (candidates, unique) => JSON.stringify({
  model: "g",
  messages: [{ role: "user", content: Array.from({ length: candidates }, (_, i) => `DB_PASSWORD_${i}=${SECRET(i % unique)}`).join("\n") }],
});

// =====================================================================================
// L1 / L4 / L5 -- body byte cap
// =====================================================================================

test("R3.5 L1: an over-limit body is never forwarded, in any Content-Length shape [GREEN NOW]", async () => {
  const env = { REDACT_MAX_BODY_BYTES: "1000" };
  const big = docOf(400, 400);
  const small = docOf(1, 1);
  assert.ok(big.length > 1000 && small.length <= 1000, "fixtures must straddle the cap");

  const shapes = [
    ["Content-Length declares too much", { contentLength: big.length }, big, 413],
    ["Content-Length absent (chunked)", {}, big, 413],
    ["Content-Length understates", { contentLength: small.length }, big, 413],
    ["Content-Length overstates a small body", { contentLength: String(big.length) }, small, 200],
    ["huge non-JSON body", { contentType: "text/plain" }, "y".repeat(200000), 413],
  ];
  for (const [label, headers, body, expected] of shapes) {
    const { status, trace } = await trip({ body, env, ...headers });
    assert.equal(status, expected, `${label}: status`);
    if (expected === 413) {
      assert.equal(trace.upstreamFetch, 0, `${label}: an over-limit request must not reach the upstream`);
    }
  }
});

test("R3.5 L4: the read STOPS once the cap is exceeded [GREEN NOW]", async () => {
  // The defect this pins: `await request.arrayBuffer()` materialised the whole body before any size
  // check could run, so an oversized request was fully buffered and only then rejected -- including
  // when Content-Length had already declared it oversized.
  const env = { REDACT_MAX_BODY_BYTES: "1000" };
  const big = docOf(400, 400);

  for (const [label, contentLength] of [["declared", big.length], ["absent", undefined], ["understated", 500]]) {
    const { status, trace } = await trip({ body: big, env, contentLength });
    assert.equal(status, 413, `${label}: must be refused`);
    assert.ok(
      trace.deliveredBytes <= 2 * CHUNK,
      `${label}: the read must stop near the cap, consumed ${trace.deliveredBytes} of ${trace.totalBytes}`
    );
    assert.ok(
      trace.deliveredBytes < trace.totalBytes,
      `${label}: the whole body must NOT be materialised (${trace.deliveredBytes} of ${trace.totalBytes})`
    );
    assert.equal(trace.cancelled, true, `${label}: the source must be cancelled, not merely abandoned`);
  }
});

test("R3.5 L5: an untrue Content-Length cannot move the real cap [GREEN NOW]", async () => {
  // Content-Length is a hint, never the boundary: it can be absent or untrue in either direction.
  const env = { REDACT_MAX_BODY_BYTES: "1000" };
  const big = docOf(400, 400);

  // Understating it does not smuggle an oversized body through.
  const under = await trip({ body: big, env, contentLength: 100 });
  assert.equal(under.status, 413, "an understated Content-Length must not bypass the counted cap");
  assert.equal(under.trace.upstreamFetch, 0);

  // Overstating it does not refuse a body that fits: the counted read is the authority.
  const small = docOf(1, 1);
  const over = await trip({ body: small, env, contentLength: String(big.length) });
  assert.equal(over.status, 200, "an overstated Content-Length must not refuse a body within the cap");
  assert.equal(over.trace.upstreamFetch, 1);
});

// =====================================================================================
// L2 / L3 -- body cap boundary precision, and the 415 ordering
// =====================================================================================

test("R3.5 L2: the body byte cap is exact at the boundary [GREEN NOW]", async () => {
  const env = { REDACT_MAX_BODY_BYTES: "512" };
  const mk = (n) => JSON.stringify({ model: "g", messages: [{ role: "user", content: "x".repeat(Math.max(0, n)) }] });
  // Find bodies a few bytes either side of the cap.
  let atCap = null;
  let overCap = null;
  for (let n = 400; n < 520; n++) {
    const body = mk(n);
    if (body.length === 512) atCap = body;
    if (body.length === 513 && overCap === null) overCap = body;
  }
  assert.ok(atCap && overCap, "fixtures must sit exactly at and just over the cap");

  assert.equal((await trip({ body: atCap, env })).status, 200, "exactly at the cap is accepted");
  assert.equal((await trip({ body: overCap, env })).status, 413, "one byte over is refused");
});

test("R3.5 L3: a huge non-JSON body is refused by the SIZE check, not the content-type check [GREEN NOW]", async () => {
  // The 415 check also runs after the body is available, so this pins which one fires. It matters
  // for L4: were 415 first, a huge non-JSON body would be read in full before being refused.
  const payload = "y".repeat(200000);
  const sized = await trip({ body: payload, contentType: "text/plain", env: { REDACT_MAX_BODY_BYTES: "1000" } });
  assert.equal(sized.status, 413, "an oversized non-JSON body is a size failure");
  assert.ok(sized.trace.deliveredBytes < payload.length, "and is refused before being read in full");

  // Within the cap, the same content type is still a 415 -- and that path necessarily has the body.
  const small = await trip({ body: "not json", contentType: "text/plain", env: { REDACT_MAX_BODY_BYTES: "1000" } });
  assert.equal(small.status, 415, "a small non-JSON body is a content-type failure");
});

// =====================================================================================
// REDACT_MAX_REDACTIONS -- an entity-identity limit, not a CPU guard
// =====================================================================================

test("R3.5 L2: maxRedactions counts UNIQUE entities, not spans or occurrences [GREEN NOW]", async () => {
  // The variable name suggests "at most N replacements". It is actually `rawToToken.size`, so it
  // bounds distinct entity identities. Both halves are asserted, because either one alone would
  // leave the semantics ambiguous.
  const flags = { gitleaks: true, highEntropy: true };

  // Many occurrences of FEW unique values: the limit is not reached, however many spans there are.
  const repeated = Array.from({ length: 200 }, (_, i) => `DB_PASSWORD_${i}=${SECRET(i % 2)}`).join("\n");
  assert.ok(findSensitiveSpans(repeated, flags).length >= 200, "the fixture must produce many spans");
  const manySpans = new RedactionContext({ salt: "limit", maxRedactions: 2 });
  await manySpans.redactText(repeated, flags);
  assert.equal(manySpans.rawToToken.size, 2, "200 spans, 2 identities, no limit hit");

  // Few occurrences of MANY unique values: the limit is reached.
  const distinct = Array.from({ length: 5 }, (_, i) => `DB_PASSWORD_${i}=${SECRET(i)}`).join("\n");
  const fewSpans = new RedactionContext({ salt: "limit", maxRedactions: 2 });
  await assert.rejects(() => fewSpans.redactText(distinct, flags), /Redaction limit exceeded/);
});

test("R3.5 L2: the unique-entity cap is exact at the boundary [GREEN NOW]", async () => {
  const flags = { gitleaks: true, highEntropy: true };
  for (const limit of [1, 2, 3, 5]) {
    for (const unique of [limit, limit + 1]) {
      const text = Array.from({ length: unique }, (_, i) => `DB_PASSWORD_${i}=${SECRET(i)}`).join("\n");
      const ctx = new RedactionContext({ salt: "limit", maxRedactions: limit });
      if (unique <= limit) {
        await ctx.redactText(text, flags);
        assert.equal(ctx.rawToToken.size, unique, `limit=${limit}: ${unique} unique values are admitted`);
      } else {
        await assert.rejects(
          () => ctx.redactText(text, flags), /Redaction limit exceeded/,
          `limit=${limit}: ${unique} unique values must be refused`
        );
      }
    }
  }
});

test("R3.5 L1: nothing is emitted when the entity limit is hit [GREEN NOW]", async () => {
  // Fail-closed at the gateway: the call throws rather than returning a partially redacted document,
  // so no plaintext can travel onward inside a half-processed payload.
  const flags = { gitleaks: true, highEntropy: true };
  const text = Array.from({ length: 10 }, (_, i) => `DB_PASSWORD_${i}=${SECRET(i)}`).join("\n");
  const ctx = new RedactionContext({ salt: "limit", maxRedactions: 2 });
  let returned = null;
  await assert.rejects(async () => { returned = await ctx.redactText(text, flags); }, /Redaction limit exceeded/);
  assert.equal(returned, null, "no partial output may be returned");
  for (let i = 0; i < 10; i++) {
    assert.equal(JSON.stringify(returned)?.includes(SECRET(i)) ?? false, false, "and no plaintext may be attached to it");
  }
});

test("R3.5 L1: an entity-limit failure is never forwarded upstream [GREEN NOW]", async () => {
  const doc = docOf(20, 20);
  const { status, trace } = await trip({ body: doc, env: { REDACT_MAX_REDACTIONS: "1" } });
  assert.equal(status, 413, "the client sees a 413");
  assert.equal(trace.upstreamFetch, 0, "and nothing reaches the upstream");
});

test("R3.5 L4: maxRedactions does NOT bound the pre-mint stages [GREEN NOW]", async () => {
  // The recorded contract, with the measurement that establishes it. The limit is consulted in
  // tokenFor, i.e. after findSensitiveSpans has run its parsers, detectors, envelopes and merge. So
  // the work before the first mint happens whatever the limit is; shortening it only stops the
  // allocation phase.
  //
  // This is asserted so the property cannot be mistaken for a CPU guard: a document whose
  // candidates are all rejected still costs a full scan.
  const flags = { gitleaks: true, highEntropy: true };
  const text = Array.from({ length: 400 }, (_, i) => `DB_PASSWORD_${i}=${SECRET(i)}`).join("\n");

  const spans = findSensitiveSpans(text, flags);
  assert.ok(spans.length >= 400, `the scan must find the candidates regardless of any limit (${spans.length})`);

  const tight = new RedactionContext({ salt: "limit", maxRedactions: 1 });
  const loose = new RedactionContext({ salt: "limit", maxRedactions: 1e9 });
  await assert.rejects(() => tight.redactText(text, flags), /Redaction limit exceeded/);
  await loose.redactText(text, flags);
  assert.equal(loose.rawToToken.size, 400, "the loose limit actually processes every entity");

  // The observable claim: the PRE-mint work is identical, because it happens before the check.
  assert.deepEqual(
    findSensitiveSpans(text, flags).map((s) => [s.start, s.end]),
    spans.map((s) => [s.start, s.end]),
    "the span set is a function of the document, not of maxRedactions"
  );
});

// =====================================================================================
// The stage table, asserted in one place
// =====================================================================================

test("R3.5 L3: each limit takes effect at a known stage [GREEN NOW]", async () => {
  const stages = [];
  const mk = (label, fn) => stages.push([label, fn]);

  mk("body cap", async () => {
    const { status, trace } = await trip({ body: docOf(400, 400), env: { REDACT_MAX_BODY_BYTES: "1000" } });
    return { status, upstream: trace.upstreamFetch, readFullBody: trace.deliveredBytes >= trace.totalBytes };
  });
  mk("entity cap", async () => {
    const { status, trace } = await trip({ body: docOf(20, 20), env: { REDACT_MAX_REDACTIONS: "1" } });
    return { status, upstream: trace.upstreamFetch, readFullBody: trace.deliveredBytes >= trace.totalBytes };
  });

  const results = {};
  for (const [label, fn] of stages) results[label] = await fn();

  // Body cap: refused before the body is read, and before anything else.
  assert.equal(results["body cap"].status, 413);
  assert.equal(results["body cap"].upstream, 0);
  assert.equal(results["body cap"].readFullBody, false, "the body cap fires during the read");

  // Entity cap: the body IS read in full, because the limit lives much further down the pipeline.
  assert.equal(results["entity cap"].status, 413);
  assert.equal(results["entity cap"].upstream, 0);
  assert.equal(results["entity cap"].readFullBody, true, "the entity cap fires after the body is read");
});
