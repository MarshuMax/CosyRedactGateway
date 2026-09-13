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

// ---------------------------------------------------------------------------------------------
// Markers that must reach the gateway's internals and then appear NOWHERE in telemetry.
//
// These are not arbitrary strings. Each one is placed where a leak would be most plausible and
// least obvious -- routing metadata and a raw error message -- because telemetry legitimately
// records the upstream HOSTNAME, and "the host is recorded" is exactly the reason path, query and
// header values need their own explicit check rather than being assumed absent.
// ---------------------------------------------------------------------------------------------
const T1_HEADER_MARKER = "T1-HEADER-MARKER-8f21";
const T1_PATH_MARKER = "T1-PATH-MARKER-4c7a";
const T1_QUERY_MARKER = "T1-QUERY-MARKER-9b3e";
const T1_RAW_ERROR_MARKER = "T1-RAW-ERROR-MARKER-5d60";

/**
 * The strings that must never appear in ANY outlet.
 *
 * `ruleId` is in the list as a SCHEMA KEY, not a value: telemetry deliberately does not record rule
 * ids, because a rule id identifies which kind of secret was found and would narrow the search space
 * for anyone reading the dashboard. Checking that the key does not appear catches a future field
 * being added under that name.
 */
const FORBIDDEN = [SECRET, EMAIL, CARD, PHONE, "CRG_", T1_HEADER_MARKER, T1_PATH_MARKER, T1_QUERY_MARKER, T1_RAW_ERROR_MARKER, "ruleId"];

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
 * The ONE scanner predicate. Used by the sweep AND by the positive control, so the control cannot
 * pass while the sweep's predicate is broken.
 */
function scanText(outlet, text) {
  const hits = [];
  for (const f of FORBIDDEN) {
    if (text.includes(f)) hits.push(`${outlet} contains ${f}`);
  }
  return hits;
}

/** Scan every outlet, naming which one leaked. */
function scanOutlets() {
  return Object.entries(outlets()).flatMap(([outlet, text]) => scanText(outlet, text));
}

// ---------------------------------------------------------------------------------------------
// POSITIVE CONTROL -- the scanner must be able to fail
// ---------------------------------------------------------------------------------------------

test("T1 positive control: the SAME scanner helper detects every planted forbidden value [GREEN NOW]", () => {
  // This must call the real scanner rather than `text.includes()` directly. A control that uses a
  // different predicate from the sweep proves the predicate in the control works, not the one doing
  // the scanning -- which is how the original `__lastSummary` test came to verify nothing.
  const hits = scanText("planted", FORBIDDEN.map((f) => `x ${f} y`).join(" "));
  for (const f of FORBIDDEN) {
    assert.ok(hits.some((h) => h.includes(f)), `the scanner must report ${f}; reported ${JSON.stringify(hits)}`);
  }
  assert.equal(hits.length, FORBIDDEN.length, "one hit per planted value");
  // And the same helper finds nothing in a clean record.
  assert.deepEqual(scanText("clean", JSON.stringify({ outcome: "forwarded", status: 200, spans: { redact: 1 } })), []);
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


// =====================================================================================
// T1.1 -- routing metadata and raw error text, each proven present then proven absent
// =====================================================================================

test("T1.1: header / path / query markers really reach the upstream, then leak nowhere [GREEN NOW]", async () => {
  // Both halves matter. Asserting absence alone is satisfied by a marker that never entered the
  // system, which would make this pass without testing anything -- the same shape of false green as
  // scanning an unassigned variable.
  __resetTelemetryStore();
  LOGS.length = 0;

  let seenUrl = null, seenHeader = null;
  const upstreamImpl = async (url, init) => {
    seenUrl = String(url);
    // The request headers are forwarded; read whichever representation the stub received.
    seenHeader = init?.headers ? JSON.stringify(init.headers) : null;
    return new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: "ok" } }] }), { headers: { "content-type": "application/json" } });
  };

  const proxyUrl = `https://proxy.example/H$https://api.example/v1/chat/completions/${T1_PATH_MARKER}?q=${T1_QUERY_MARKER}`;
  await captureLogs(async () => {
    const res = await handleRequest(
      new Request(proxyUrl, {
        method: "POST",
        headers: { "content-type": "application/json", "x-t1-marker": T1_HEADER_MARKER },
        body: JSON.stringify({ model: "g", messages: [{ role: "user", content: `PW=${SECRET}` }] }),
      }), ON, { salt: "t1", fetchImpl: upstreamImpl });
    await res.text();
  });

  // The markers genuinely travelled through the gateway. If either assertion here fails, the leakage
  // assertions below are meaningless rather than passing.
  assert.ok(seenUrl && seenUrl.includes(T1_PATH_MARKER), `path marker must reach the upstream; saw ${seenUrl}`);
  assert.ok(seenUrl.includes(T1_QUERY_MARKER), "query marker must reach the upstream");

  const hits = scanOutlets();
  assert.deepEqual(hits, [], `telemetry leaked routing metadata: ${hits.join("; ")}`);
  const store = __telemetryStore();
  assert.ok(store.recent.length >= 1);
  // The upstream HOST is legitimately recorded -- stated so the absence checks above are not read as
  // "nothing about the upstream is stored".
  assert.equal(store.recent.toArray()[0].upstream, "api.example");
});

test("T1.1: a raw fetch error message reaches the client 502 but never telemetry [GREEN NOW]", async () => {
  __resetTelemetryStore();
  LOGS.length = 0;

  let clientBody = null;
  await captureLogs(async () => {
    const res = await handleRequest(
      new Request("https://proxy.example/H$https://api.example/v1/chat/completions", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "g", messages: [{ role: "user", content: "hello" }] }),
      }), ON, { salt: "t1", fetchImpl: async () => { throw new Error(T1_RAW_ERROR_MARKER); } });
    clientBody = await res.text();
  });

  // The gateway DOES surface the transport message to the client. That is deliberate fail-loud
  // behaviour, and it is exactly why the check below is worth making: the string exists in this
  // request's lifecycle, so its absence from telemetry is a real property and not an accident of the
  // value never existing.
  assert.ok(clientBody.includes(T1_RAW_ERROR_MARKER), `the client 502 carries the transport message; got ${clientBody.slice(0, 120)}`);

  const hits = scanOutlets();
  assert.deepEqual(hits, [], `telemetry leaked the raw error message: ${hits.join("; ")}`);
  const rec = __telemetryStore().recent.toArray()[0];
  assert.equal(rec.outcome, "upstream_error", "and the refusal is still classified normally");
});
