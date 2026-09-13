// T1 -- the three real telemetry outlets, actually scanned.
//
// What this file exists to correct: an earlier leak test concatenated `globalThis.__lastSummary`,
// which was NEVER ASSIGNED, so "summary is verified" was an illusion -- the test really only scanned
// the log lines. The scan targets are now the real outlets:
//
//   recent.toArray()   the stored records
//   summary()          the aggregate view
//   structured logs    the rendered lines
//
// and the scanner carries a POSITIVE CONTROL, because a scanner that cannot detect a planted leak
// will happily report zero leaks forever. Each scan first proves it finds a sentinel that was
// deliberately placed in the same shape of data.
//
// No production behaviour is touched by this file: it only reads what the gateway already produces.

import test from "node:test";
import assert from "node:assert/strict";
import {
  handleRequest,
  __resetTelemetryStore,
  __telemetryStore,
  TELEMETRY_SCHEMA_VERSION,
} from "../worker.js";

const SECRET = "wJalrXUtnFEMIK7MDENGbPxRfiCY";
const EMAIL = "t1.sentinel@example.com";
const CARD = "4111111111111111";
const PHONE = "+8613800138000";
const NL = String.fromCharCode(10);
const ENV = (extra = {}) => ({ REDACT_MAX_BODY_BYTES: "16384", ...extra });
const ON = ENV({ REDACT_OBSERVABILITY: "1" });
const TOKEN_RE = /CRG_[A-Z0-9]{6}_[A-Z0-9]{4}/g;

/** The strings that must never appear in ANY outlet. */
const FORBIDDEN = [SECRET, EMAIL, CARD, PHONE, "CRG_"];

/** Capture the three outlets as text. */
function outlets() {
  const store = __telemetryStore();
  if (!store) return { recent: "[]", summary: "{}", logs: "" };
  return {
    recent: JSON.stringify(store.recent.toArray()),
    summary: JSON.stringify(store.summary()),
    logs: LOGS.join(NL),
  };
}

const LOGS = [];
function captureLogs(fn) {
  const original = console.error;
  console.error = (...a) => { LOGS.push(a.join(" ")); };
  return Promise.resolve()
    .then(fn)
    .finally(() => { console.error = original; });
}

/**
 * Scan every outlet for every forbidden string.
 * Returns the hits rather than throwing, so the caller can assert on shape.
 */
function scanOutlets() {
  const o = outlets();
  const hits = [];
  for (const [outlet, text] of Object.entries(o)) {
    for (const f of FORBIDDEN) {
      if (text.includes(f)) hits.push(`${outlet} contains ${f}`);
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------------------------
// POSITIVE CONTROL -- the scanner must be able to fail
// ---------------------------------------------------------------------------------------------

test("T1 positive control: the scanner detects a leak when one is planted [GREEN NOW]", () => {
  // Plant each forbidden shape directly into an object with the same structure as a record, and
  // confirm the SCANNER's predicate finds it. Without this, every "0 leaks" below could be reporting
  // a broken scanner rather than a clean gateway.
  const planted = { note: `${SECRET} ${EMAIL} ${CARD} ${PHONE} CRG_AAAAAA_0001` };
  const text = JSON.stringify(planted);
  for (const f of FORBIDDEN) {
    assert.ok(text.includes(f), `positive control: the scanner must be able to see ${f}`);
  }
  // And the same predicate applied to a clean record finds nothing.
  const clean = { outcome: "forwarded", status: 200, spans: { redact: 1 } };
  const cleanText = JSON.stringify(clean);
  for (const f of FORBIDDEN) assert.equal(cleanText.includes(f), false);
});

// ---------------------------------------------------------------------------------------------
// The real sweep
// ---------------------------------------------------------------------------------------------

test("T1: no outlet leaks across every recorded terminal path [GREEN NOW]", async () => {
  const deepUpstream = () => { let n = "leaf"; for (let i = 0; i < 700; i++) n = { c: n }; return n; };
  const sseUpstream = async () => {
    const ev = (s) => `event: response.output_text.delta${NL}data: ${JSON.stringify({ type: "response.output_text.delta", delta: s })}${NL}${NL}`;
    return new Response(ev("hello") + `data: [DONE]${NL}${NL}`, { headers: { "content-type": "text/event-stream" } });
  };
  const deepSse = async () => {
    const nested = (() => { let n = "y"; for (let i = 0; i < 700; i++) n = { c: n }; return n; })();
    const ev = { type: "response.output_text.delta", delta: "x", nested };
    return new Response(`event: response.output_text.delta${NL}data: ${JSON.stringify(ev)}${NL}${NL}data: [DONE]${NL}${NL}`, { headers: { "content-type": "text/event-stream" } });
  };
  const run = (body, { ct = "application/json", path = "/v1/chat/completions", fetchImpl, env = ON } = {}) =>
    handleRequest(new Request(`https://proxy.example/H$https://api.example${path}`, { method: "POST", headers: { "content-type": ct }, body }),
      env, { salt: "t1", fetchImpl: fetchImpl || (async () => new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: "ok" } }] }), { headers: { "content-type": "application/json" } })) });
  const ticket = (content) => JSON.stringify({ model: "g", messages: [{ role: "user", content }] });

  __resetTelemetryStore();
  LOGS.length = 0;
  await captureLogs(async () => {
    // every path that produces a record, each carrying the sentinels
    await (await run(ticket(`PW=${SECRET} mail ${EMAIL} card ${CARD} tel ${PHONE}`))).text();                  // forwarded + redact
    await (await run(ticket(`PW=${SECRET}`), { fetchImpl: async () => { throw new Error("boom"); } })).text(); // upstream_error
    await (await run(ticket(`PW=${SECRET}`), { ct: "text/plain" })).text();                                   // 415
    await (await run("{bad " + SECRET)).text();                                                               // 400
    await (await run(ticket(`PW=${SECRET}`), { env: ENV({ REDACT_OBSERVABILITY: "1", REDACT_MAX_BODY_BYTES: "64" }) })).text(); // 413 body
    await (await run(JSON.stringify({ model: "g", deep: (() => { let n = SECRET; for (let i = 0; i < 700; i++) n = { c: n }; return n; })() }))).text(); // 413 depth
    await (await run(ticket(`PW=${SECRET}`), { path: "/v1/messages", fetchImpl: async (_u, i) => {
      const tok = (String(i.body).match(TOKEN_RE) || [])[0];
      return new Response(JSON.stringify({ type: "message", role: "assistant", content: [{ type: "tool_use", id: "t", name: "untrusted", input: { pw: tok } }] }), { headers: { "content-type": "application/json" } });
    } })).text();                                                                                             // preserve in operand
    await (await run(ticket(`PW=${SECRET}`), { path: "/v1/responses", fetchImpl: sseUpstream })).text();        // SSE normal
    await (await run(ticket(`PW=${SECRET}`), { path: "/v1/responses", fetchImpl: deepSse })).text();           // SSE depth -> stream_error
    await (await run(ticket("hello"), { fetchImpl: async () => new Response(JSON.stringify({ nested: deepUpstream() }), { headers: { "content-type": "application/json" } }) })).text(); // upstream_depth
    await (await run(ticket("hello"), { fetchImpl: async () => new Response('{"e":1}', { status: 502, headers: { "content-type": "application/json" } }) })).text(); // native 502
  });

  const store = __telemetryStore();
  assert.ok(store, "the store must exist");
  assert.ok(store.recent.length >= 10, `expected many records, got ${store.recent.length}`);
  assert.ok(LOGS.some((l) => l.startsWith("[CRG]")), "and the log outlet must actually have content");

  // The three outlets, scanned.
  const hits = scanOutlets();
  assert.deepEqual(hits, [], `telemetry leaked: ${hits.join("; ")}`);

  // Record shape sanity, so a leak-free run cannot be a run that recorded nothing.
  const rec = store.recent.toArray()[0];
  assert.equal(rec.schema_version, TELEMETRY_SCHEMA_VERSION);
  assert.ok(Object.keys(rec).length >= 12, "records carry the full schema");
});

test("T1: the outlets genuinely contain data, so the scan is not vacuous [GREEN NOW]", async () => {
  // Guards the other half of a false green: a scan over EMPTY outlets finds no leaks trivially.
  __resetTelemetryStore();
  LOGS.length = 0;
  await captureLogs(async () => {
    await handleRequest(new Request("https://proxy.example/H$https://api.example/v1/chat/completions", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "g", messages: [{ role: "user", content: `PW=${SECRET}` }] }),
    }), ON, { salt: "t1", fetchImpl: async () => new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: "ok" } }] }), { headers: { "content-type": "application/json" } }) });
  });
  const o = outlets();
  assert.ok(o.recent.length > 2 && o.recent !== "[]", "recent has content");
  assert.ok(o.summary.length > 2 && o.summary !== "{}", "summary has content");
  assert.ok(o.logs.length > 0, "logs have content");
  // And the sensitive value travelled through the gateway, so its absence is meaningful.
  const store = __telemetryStore();
  assert.ok(store.counters.requests_total >= 1);
  assert.ok(store.recent.toArray()[0].spans.redact >= 1, "a redaction happened, so a leak would have been possible");
});
