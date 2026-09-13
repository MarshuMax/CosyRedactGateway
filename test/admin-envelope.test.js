// PR2.1 -- /admin security envelope: admission, runtime visibility, authentication.
//
// The route exposes NO data yet. What is tested here is the boundary: when the route exists, when it
// is hidden, and when it demands a credential. Admission and authorisation are one commit precisely
// so there is no intermediate state where the route is open and auth is still pending.

import test from "node:test";
import assert from "node:assert/strict";
import { handleRequest } from "../worker.js";

const OBS = { REDACT_OBSERVABILITY: "1" };
const WITH_TOKEN = { ...OBS, REDACT_ADMIN_TOKEN: "s3cret-value" };
const node = (bindHost) => ({ runtime: { kind: "node", bindHost } });
const cf = { runtime: { kind: "cloudflare" } };
const deno = { runtime: { kind: "deno" } };

/**
 * Build an admin request with an EXPLICIT Host header.
 *
 * Required since PR2.4: the loopback exemption now also requires the request to be ADDRESSED locally,
 * and Node's Request does not derive a Host header from the URL. The real adapter supplies one from
 * `req.headers`, so a request without it is not what a real client sends -- and it must not be
 * treated as local, which is the DNS-rebinding guard.
 */
const get = (env, options, headers = {}, url = "http://127.0.0.1:8787/admin") =>
  handleRequest(new Request(url, { method: "GET", headers: { host: "127.0.0.1:8787", ...headers } }), env, options);

test("PR2.1: observability disabled hides /admin as 404, never 403 [GREEN NOW]", async () => {
  // 404 rather than 403: a 403 confirms an admin surface exists.
  for (const [label, env, options] of [
    ["unset", {}, node("127.0.0.1")],
    ["0", { REDACT_OBSERVABILITY: "0" }, node("127.0.0.1")],
    ["true", { REDACT_OBSERVABILITY: "true" }, node("127.0.0.1")],
  ]) {
    const res = await get(env, options);
    assert.equal(res.status, 404, `${label}: must be hidden`);
  }
});

test("PR2.1: only the two LITERAL loopback values on the node adapter are exempt [GREEN NOW]", async () => {
  for (const host of ["127.0.0.1", "::1"]) {
    const res = await get(OBS, node(host));
    assert.equal(res.status, 200, `bindHost ${host} is explicit loopback`);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("access-control-allow-origin"), null, "an admin route gets no CORS");
  }
  // Everything else needs a token. `0.0.0.0`, `::`, hostnames and `localhost` are NOT guessed at.
  for (const host of ["0.0.0.0", "::", "localhost", "example.com", "", null]) {
    const res = await get(OBS, node(host));
    assert.equal(res.status, 404, `bindHost ${JSON.stringify(host)} must not be treated as local`);
  }
});

test("PR2.1: without adapter metadata the runtime is unknown and needs a token [GREEN NOW]", async () => {
  assert.equal((await get(OBS, {})).status, 404, "no metadata, no token configured -> hidden");
  assert.equal((await get(WITH_TOKEN, {}, { authorization: "Bearer s3cret-value" })).status, 200);
});

test("PR2.1: Cloudflare and Deno never qualify for the loopback exemption [GREEN NOW]", async () => {
  for (const [label, options] of [["cloudflare", cf], ["deno", deno]]) {
    assert.equal((await get(OBS, options)).status, 404, `${label}: no token configured -> hidden`);
    assert.equal((await get(WITH_TOKEN, options)).status, 401, `${label}: token configured, none supplied`);
    assert.equal((await get(WITH_TOKEN, options, { authorization: "Bearer wrong" })).status, 401);
    assert.equal((await get(WITH_TOKEN, options, { authorization: "Bearer s3cret-value" })).status, 200);
  }
  // Even a Worker that somehow carries a loopback bindHost must not be exempt: the exemption is for
  // the node adapter, and a Worker has no local bind.
  const workerWithLoopback = { runtime: { kind: "cloudflare", bindHost: "127.0.0.1" } };
  assert.equal((await get(OBS, workerWithLoopback)).status, 404, "a Worker is never local");
});

test("PR2.1: a configured token is required exactly as Bearer, and nothing else is read [GREEN NOW]", async () => {
  const opts = node("0.0.0.0");
  assert.equal((await get(WITH_TOKEN, opts)).status, 401, "no Authorization header");
  assert.equal((await get(WITH_TOKEN, opts, { authorization: "Bearer wrong" })).status, 401, "wrong token");
  assert.equal((await get(WITH_TOKEN, opts, { authorization: "s3cret-value" })).status, 401, "not a Bearer scheme");
  assert.equal((await get(WITH_TOKEN, opts, { authorization: "Basic s3cret-value" })).status, 401, "wrong scheme");
  assert.equal((await get(WITH_TOKEN, opts, { authorization: "Bearer  s3cret-value" })).status, 200, "extra spacing is tolerated");
  assert.equal((await get(WITH_TOKEN, opts, { authorization: "bearer s3cret-value" })).status, 200, "scheme is case-insensitive");
  assert.equal((await get(WITH_TOKEN, opts, { authorization: "Bearer s3cret-value" })).status, 200, "correct token");
});

test("PR2.1: a query-string credential is NOT accepted [GREEN NOW]", async () => {
  // Not supported at all -- a query credential leaks into browser history, proxy logs and referrers.
  const opts = node("0.0.0.0");
  for (const q of ["?token=s3cret-value", "?key=s3cret-value", "?access_token=s3cret-value", "?admin_token=s3cret-value"]) {
    const res = await get(WITH_TOKEN, opts, {}, `https://proxy.example/admin${q}`);
    assert.equal(res.status, 401, `${q} must not authenticate`);
  }
});

test("PR2.1: a Cookie credential is NOT accepted [GREEN NOW]", async () => {
  const opts = node("0.0.0.0");
  const res = await get(WITH_TOKEN, opts, { cookie: "token=s3cret-value; admin=s3cret-value" });
  assert.equal(res.status, 401);
});

test("PR2.1: attacker-controlled headers cannot make a public node look local [GREEN NOW]", async () => {
  // The bind address is adapter metadata. Host, X-Forwarded-For, Forwarded and the request URL's own
  // hostname are all attacker-controlled and must not be consulted.
  const opts = node("0.0.0.0");   // explicitly NOT loopback
  const forged = [
    { host: "127.0.0.1" },
    { host: "127.0.0.1:8787" },
    { host: "localhost" },
    { "x-forwarded-for": "127.0.0.1" },
    { "x-forwarded-host": "127.0.0.1" },
    { forwarded: "for=127.0.0.1;host=127.0.0.1" },
    { "x-real-ip": "127.0.0.1" },
    { "x-forwarded-for": "127.0.0.1", host: "127.0.0.1", forwarded: "for=127.0.0.1" },
  ];
  for (const headers of forged) {
    const res = await get(OBS, opts, headers);
    assert.equal(res.status, 404, `${JSON.stringify(headers)} must not yield loopback access`);
  }
  // And the request URL's own hostname is equally irrelevant.
  const urlForged = await get(OBS, opts, {}, "http://127.0.0.1/admin");
  assert.equal(urlForged.status, 404, "the request URL host is not the bind address");
});

test("PR2.1: 0.0.0.0 does not become exempt by adding a token-shaped header [GREEN NOW]", async () => {
  // Belt and braces on the same property: without a CONFIGURED token, no supplied value can help.
  for (const value of ["Bearer s3cret-value", "Bearer 127.0.0.1", "Bearer "]) {
    const res = await get(OBS, node("0.0.0.0"), { authorization: value });
    assert.equal(res.status, 404, `${value} cannot substitute for a configured token`);
  }
});

test("PR2.1: the admin token never reaches telemetry or the logs [GREEN NOW]", async () => {
  const { __resetTelemetryStore, __telemetryStore } = await import("../worker.js");
  __resetTelemetryStore();
  const lines = [];
  const original = console.error;
  console.error = (...a) => lines.push(a.join(" "));
  try {
    await get(WITH_TOKEN, node("0.0.0.0"), { authorization: "Bearer s3cret-value" });
    await get(WITH_TOKEN, node("0.0.0.0"), { authorization: "Bearer wrong-but-token-shaped" });
    await get(WITH_TOKEN, cf, { authorization: "Bearer s3cret-value" });
  } finally {
    console.error = original;
  }
  const store = __telemetryStore();
  const outlets = {
    recent: store ? JSON.stringify(store.recent.toArray()) : "[]",
    summary: store ? JSON.stringify(store.summary()) : "{}",
    logs: JSON.stringify(lines),
  };
  for (const [outlet, text] of Object.entries(outlets)) {
    assert.equal(text.includes("s3cret-value"), false, `${outlet} must not contain the admin token`);
    assert.equal(text.includes("wrong-but-token-shaped"), false, `${outlet} must not contain a supplied token`);
  }
  // An /admin request is a routing request, outside the telemetry admission boundary, so it records
  // nothing at all -- asserted so the absence above is not merely "nothing was recorded by accident".
  assert.equal(store ? store.recent.length : 0, 0, "/admin is not a proxy request and must record nothing");
});

test("PR2.1: /healthz and the proxy path are unchanged [GREEN NOW]", async () => {
  const health = await handleRequest(new Request("https://proxy.example/healthz"), {}, {});
  assert.equal(health.status, 200);
  assert.equal((await health.json()).ok, true);
  const root = await handleRequest(new Request("https://proxy.example/"), {}, {});
  assert.equal(root.status, 200);
  // A path that is not a proxy route answers 404 -- that is `!target`, not the 400 which is reserved
  // for a route whose format fails to parse. Asserted explicitly because the two are easy to confuse.
  assert.equal((await handleRequest(new Request("https://proxy.example/not-a-route"), OBS, {})).status, 404);
  assert.equal((await handleRequest(new Request("https://proxy.example/H$not-a-url"), OBS, {})).status, 400);
  // And a valid proxy route still works with observability on, with the same status and body as off.
  const call = (env) => handleRequest(
    new Request("https://proxy.example/H$https://api.example/v1/chat/completions", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "g", messages: [{ role: "user", content: "hello" }] }),
    }), env, { salt: "adm", fetchImpl: async () => new Response('{"ok":true}', { headers: { "content-type": "application/json" } }) });
  const off = await call({});
  const withObs = await call(OBS);
  assert.equal(withObs.status, off.status);
  assert.equal(await withObs.text(), await off.text(), "observability must not alter the proxy response");
});
