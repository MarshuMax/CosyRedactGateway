// PR2.2 -- read-only JSON view at /admin/api.
//
// The payload is the STORE'S OWN output, not a recomputation: `summary()` plus the already-sanitized
// `recent.toArray()`. These tests therefore check the boundary and the wiring, not the statistics --
// the statistics themselves are PR1's, and re-asserting them here would create a second definition
// that could drift.

import test from "node:test";
import assert from "node:assert/strict";
import { handleRequest, __resetTelemetryStore } from "../worker.js";

const SECRET = "wJalrXUtnFEMIK7MDENGbPxRfiCY";
const EMAIL = "pr22.sentinel@example.com";
const HEADER_MARKER = "PR22-HEADER-MARKER-7a1";
const PATH_MARKER = "PR22-PATH-MARKER-2b9";
const QUERY_MARKER = "PR22-QUERY-MARKER-4c3";
const RAW_ERROR_MARKER = "PR22-RAW-ERROR-MARKER-6d8";
const TOKEN = "pr22-admin-token";
const OBS = { REDACT_OBSERVABILITY: "1" };
const WITH_TOKEN = { ...OBS, REDACT_ADMIN_TOKEN: TOKEN };
const node = (bindHost) => ({ runtime: { kind: "node", bindHost } });
const loopback = node("127.0.0.1");
const publicBind = node("0.0.0.0");

/** Perform a real proxy request so the store holds something. */
async function proxyRequest(env, { content = `PW=${SECRET} mail ${EMAIL}`, fetchImpl } = {}) {
  return handleRequest(new Request("https://proxy.example/H$https://api.example/v1/chat/completions", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "g", messages: [{ role: "user", content }] }),
  }), env, {
    salt: "pr22",
    fetchImpl: fetchImpl || (async () => new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: "ok" } }] }), { headers: { "content-type": "application/json" } })),
  });
}

/**
 * Admin API request with an EXPLICIT local Host. See the note in admin-envelope.test.js: since PR2.4
 * the exemption also requires the request to be ADDRESSED locally, and Node's Request does not derive
 * a Host header from the URL.
 */
const apiGet = (env, options, headers = {}, url = "http://127.0.0.1:8787/admin/api") =>
  handleRequest(new Request(url, { method: "GET", headers: { host: "127.0.0.1:8787", ...headers } }), env, options);

test("PR2.2: an empty store returns a zero summary and an empty recent, not an error [GREEN NOW]", async () => {
  __resetTelemetryStore();
  const res = await apiGet(OBS, loopback);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual(body.recent, []);
  assert.equal(body.counters.requests_total, 0);
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.equal(res.headers.get("access-control-allow-origin"), null, "no CORS on an admin route");
});

test("PR2.2: authentication runs BEFORE the store is read [GREEN NOW]", async () => {
  __resetTelemetryStore();
  await (await proxyRequest(OBS)).text();
  // Wrong token: refused, and the response must carry nothing from the store.
  const denied = await apiGet(WITH_TOKEN, publicBind, { authorization: "Bearer wrong" });
  assert.equal(denied.status, 401);
  const text = await denied.text();
  assert.equal(text.includes("requests_total"), false, "an unauthorised response must not leak the shape of the data");
  assert.equal(text.includes("by_detector"), false);
  // Hidden route: same, with observability off.
  const hidden = await apiGet({}, loopback);
  assert.equal(hidden.status, 404);
});

test("PR2.2: the API reports what a real proxy request actually produced [GREEN NOW]", async () => {
  __resetTelemetryStore();
  await (await proxyRequest(OBS)).text();
  const res = await apiGet(OBS, loopback);
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.ok(body.counters.requests_total >= 1, "the proxy request was counted");
  assert.ok(body.counters.requests_redacted >= 1, "and it was a redacting request");
  assert.ok(body.counters.spans_redacted_total >= 1);
  assert.ok(Object.keys(body.by_detector).length >= 1, "a detector bucket exists");
  assert.ok(body.recent.length >= 1, "and the recent ring holds the record");
  // The record is the store's own sanitized object, so it carries the frozen schema.
  const rec = body.recent[0];
  assert.equal(rec.schema_version, 1);
  assert.equal(rec.outcome, "forwarded");
  assert.equal(rec.status, 200);
  assert.ok(Array.isArray(body.recent), "recent is an array");
});

test("PR2.2: /admin/api performs no proxy telemetry of its own [GREEN NOW]", async () => {
  // It is a routing request inside the admin envelope, so it must not appear in the counters it
  // serves -- otherwise reading the dashboard would change the dashboard.
  __resetTelemetryStore();
  await (await proxyRequest(OBS)).text();
  const before = (await (await apiGet(OBS, loopback)).json()).counters.requests_total;
  for (let i = 0; i < 5; i++) await apiGet(OBS, loopback);
  const after = (await (await apiGet(OBS, loopback)).json()).counters.requests_total;
  assert.equal(after, before, "admin reads must not increment the proxy counters");
});

test("PR2.2: /admin/api leaks no sentinel from a real request lifecycle [GREEN NOW]", async () => {
  const FORBIDDEN = [SECRET, EMAIL, HEADER_MARKER, PATH_MARKER, QUERY_MARKER, RAW_ERROR_MARKER, "CRG_", TOKEN, "ruleId"];
  const scan = (outlet, text) => FORBIDDEN.filter((f) => text.includes(f)).map((f) => `${outlet} contains ${f}`);

  __resetTelemetryStore();
  // A request carrying routing, header and query markers, plus a redaction.
  await (await handleRequest(new Request(
    `https://proxy.example/H$https://api.example/v1/chat/completions/${PATH_MARKER}?q=${QUERY_MARKER}`,
    { method: "POST", headers: { "content-type": "application/json", "x-pr22-marker": HEADER_MARKER },
      body: JSON.stringify({ model: "g", messages: [{ role: "user", content: `PW=${SECRET} mail ${EMAIL}` }] }) }),
    OBS, { salt: "pr22", fetchImpl: async () => new Response('{"ok":true}', { headers: { "content-type": "application/json" } }) })).text();
  // And a request whose transport failed with a distinctive message.
  await (await proxyRequest(OBS, { fetchImpl: async () => { throw new Error(RAW_ERROR_MARKER); } })).text();

  const body = await (await apiGet(WITH_TOKEN, publicBind, { authorization: `Bearer ${TOKEN}` })).text();
  const hits = scan("/admin/api body", body);
  assert.deepEqual(hits, [], `the API leaked: ${hits.join("; ")}`);

  // Non-vacuity: the payload really does carry the data whose absence is being asserted.
  const parsed = JSON.parse(body);
  assert.ok(parsed.recent.length >= 2, "the API returned the records");
  assert.ok(JSON.stringify(parsed.counters).includes("requests_total"), "and the counters");
  assert.ok(parsed.recent.some((r) => r.outcome === "upstream_error"), "including the failed-fetch record");
});

test("PR2.2: the API is GET-only and takes no parameters [GREEN NOW]", async () => {
  __resetTelemetryStore();
  for (const method of ["POST", "PUT", "DELETE", "PATCH"]) {
    const res = await handleRequest(new Request("http://127.0.0.1:8787/admin/api", { method, headers: { host: "127.0.0.1:8787" } }), OBS, loopback);
    assert.equal(res.status, 405, `${method} must be refused`);
    assert.equal(res.headers.get("allow"), "GET");
  }
  // Query parameters are ignored rather than interpreted: no filtering, no selectors.
  const withParams = await apiGet(OBS, loopback, {}, "http://127.0.0.1:8787/admin/api?limit=1&filter=x&clear=1");
  assert.equal(withParams.status, 200);
  const body = await withParams.json();
  assert.equal(body.counters.requests_total, 0);
  assert.deepEqual(body.recent, []);
});

test("PR2.2: the admin API route requires admission on every runtime [GREEN NOW]", async () => {
  __resetTelemetryStore();
  // Same matrix as the envelope, asserted for the API path specifically.
  assert.equal((await apiGet({}, loopback)).status, 404, "observability off");
  assert.equal((await apiGet(OBS, publicBind)).status, 404, "public bind, no token configured");
  assert.equal((await apiGet(WITH_TOKEN, publicBind)).status, 401, "public bind, no credential");
  assert.equal((await apiGet(WITH_TOKEN, { runtime: { kind: "cloudflare" } }, { authorization: `Bearer ${TOKEN}` })).status, 200, "worker with a valid token");
  assert.equal((await apiGet(WITH_TOKEN, { runtime: { kind: "deno" } })).status, 401, "deno without a credential");
});

// =====================================================================================
// PR2.2 revision -- the admin envelope is entered BEFORE the global CORS preflight
// =====================================================================================

/** No admin status may carry any CORS header, and all of them must be no-store. */
function assertNoCorsAndNoStore(res, label) {
  for (const h of ["access-control-allow-origin", "access-control-allow-methods", "access-control-allow-headers", "access-control-allow-credentials", "access-control-max-age"]) {
    assert.equal(res.headers.get(h), null, `${label}: ${h} must be absent`);
  }
  assert.equal(res.headers.get("cache-control"), "no-store", `${label}: must be no-store`);
}

test("PR2.2: OPTIONS /admin/api with observability off is a no-store 404 with no CORS [GREEN NOW]", async () => {
  __resetTelemetryStore();
  const res = await handleRequest(new Request("http://127.0.0.1:8787/admin/api", { method: "OPTIONS", headers: { host: "127.0.0.1:8787" } }), {}, loopback);
  assert.equal(res.status, 404, "a preflight must not bypass admission");
  assertNoCorsAndNoStore(res, "OPTIONS obs off");
});

test("PR2.2: OPTIONS /admin/api on a public bind without a credential is a 401, not a 204 [GREEN NOW]", async () => {
  // The specific defect: the global corsPreflight() used to answer 204 with CORS headers BEFORE
  // adminAdmission() ran, which both bypassed authorisation and advertised a cross-origin surface
  // the route does not have.
  __resetTelemetryStore();
  const res = await handleRequest(new Request("http://127.0.0.1:8787/admin/api", { method: "OPTIONS", headers: { host: "127.0.0.1:8787" } }), WITH_TOKEN, publicBind);
  assert.equal(res.status, 401, "admission runs before any preflight handling");
  assertNoCorsAndNoStore(res, "OPTIONS unauthenticated");
});

test("PR2.2: an authorised OPTIONS /admin/api is a 405 with Allow: GET and no CORS [GREEN NOW]", async () => {
  __resetTelemetryStore();
  const authed = await handleRequest(
    new Request("http://127.0.0.1:8787/admin/api", { method: "OPTIONS", headers: { host: "127.0.0.1:8787", authorization: `Bearer ${TOKEN}` } }),
    WITH_TOKEN, publicBind);
  assert.equal(authed.status, 405, "admitted, so the method is what fails");
  assert.equal(authed.headers.get("allow"), "GET");
  assertNoCorsAndNoStore(authed, "OPTIONS authorised");
});

test("PR2.2: every hidden GET /admin/api status is no-store with no CORS [GREEN NOW]", async () => {
  __resetTelemetryStore();
  const off = await handleRequest(new Request("http://127.0.0.1:8787/admin/api", { method: "GET", headers: { host: "127.0.0.1:8787" } }), {}, loopback);
  assert.equal(off.status, 404);
  assertNoCorsAndNoStore(off, "GET obs off");

  const publicNoToken = await handleRequest(new Request("http://127.0.0.1:8787/admin/api", { method: "GET", headers: { host: "127.0.0.1:8787" } }), OBS, publicBind);
  assert.equal(publicNoToken.status, 404);
  assertNoCorsAndNoStore(publicNoToken, "GET public bind, no token");

  const denied = await handleRequest(new Request("http://127.0.0.1:8787/admin/api", { method: "GET", headers: { host: "127.0.0.1:8787" } }), WITH_TOKEN, publicBind);
  assert.equal(denied.status, 401);
  assertNoCorsAndNoStore(denied, "GET unauthenticated");

  const ok = await handleRequest(new Request("http://127.0.0.1:8787/admin/api", { method: "GET", headers: { host: "127.0.0.1:8787" } }), WITH_TOKEN, loopback);
  assert.equal(ok.status, 200);
  assertNoCorsAndNoStore(ok, "GET authorised");
});

test("PR2.2: the ordinary proxy preflight still works, with CORS [GREEN NOW]", async () => {
  // The reordering must not have removed CORS preflight from the path that legitimately needs it.
  const res = await handleRequest(new Request("https://proxy.example/H$https://api.example/v1/chat/completions", { method: "OPTIONS" }), { REDACT_CORS_ORIGIN: "*" }, {});
  assert.equal(res.status, 204, "the proxy preflight is unchanged");
  assert.equal(res.headers.get("access-control-allow-origin"), "*");
});
