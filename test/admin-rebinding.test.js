// PR2.4 -- DNS rebinding: an untrusted Host must not inherit the loopback exemption.
//
// THE GAP: the exemption depended only on the adapter's bindHost. A page on attacker.example can
// point that name at 127.0.0.1, make a REAL TCP connection to this process, and send
// `Host: attacker.example`. The bind is loopback, so without a Host check the admin API was readable
// with no token.
//
// THE RULE, unchanged and now enforced on both sides:
//   the adapter's bindHost is the ONLY positive authority
//   the Host header can only CANCEL the exemption, never create it
//
// The adapter E2E below is not helper-only: it binds a real server to 127.0.0.1 and sends a real
// HTTP request over a real loopback TCP connection carrying a hostile Host header.

import test from "node:test";
import assert from "node:assert/strict";
import { handleRequest } from "../worker.js";
import { spawn } from "node:child_process";
import { request as httpRequest } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SERVER = resolve(REPO, "node-server.mjs");
const OBS = { REDACT_OBSERVABILITY: "1" };
const WITH_TOKEN = { ...OBS, REDACT_ADMIN_TOKEN: "rebind-token" };
const lb = { runtime: { kind: "node", bindHost: "127.0.0.1" } };
const lb6 = { runtime: { kind: "node", bindHost: "::1" } };

/**
 * Request with an explicit Host header, mirroring what a real HTTP client sends.
 * Returns the STATUS, not the Response -- comparing a Response to a number would fail for every case
 * including the ones that should pass.
 */
const ask = (env, options, host, headers = {}) =>
  handleRequest(new Request("http://127.0.0.1:8787/admin/api", { method: "GET", headers: { ...headers, ...(host === null ? {} : { host }) } }), env, options)
    .then((r) => r.status);

test("PR2.4: a hostile Host cancels the loopback exemption [GREEN NOW]", async () => {
  // Addressed locally: exemption holds.
  for (const host of ["127.0.0.1:8787", "127.0.0.1", "localhost:8787", "localhost", "LOCALHOST:8787"]) {
    assert.equal(await ask(OBS, lb, host), 200, `Host ${host} is a local name`);
  }
  assert.equal(await ask(OBS, lb6, "[::1]:8787"), 200, "IPv6 loopback with brackets");

  // Addressed to somebody else: NOT exempt, whatever the bind address says.
  for (const host of ["rebind.example:8787", "attacker.example", "evil.test:1234", "127.0.0.1.evil.example"]) {
    assert.equal(await ask(OBS, lb, host), 404, `Host ${host} must not yield loopback access with no token`);
  }
});

test("PR2.4: a hostile Host falls back to the token rules, not to a new failure mode [GREEN NOW]", async () => {
  const host = "rebind.example:8787";
  assert.equal(await ask(WITH_TOKEN, lb, host), 401, "no credential");
  assert.equal(await ask(WITH_TOKEN, lb, host, { authorization: "Bearer wrong" }), 401, "wrong credential");
  assert.equal(await ask(WITH_TOKEN, lb, host, { authorization: "Bearer rebind-token" }), 200, "a correct Bearer still works");
});

test("PR2.4: a missing or malformed Host is treated as not local [GREEN NOW]", async () => {
  assert.equal(await ask(OBS, lb, null), 404, "no Host header");
  assert.equal(await ask(OBS, lb, ""), 404, "empty Host header");
  assert.equal(await ask(OBS, lb, " "), 404, "blank Host header");
});

test("PR2.4: Host can never CREATE loopback access on a public bind [GREEN NOW]", async () => {
  // The rejection-only direction: a public bind sending a local Host is still public.
  const pub = { runtime: { kind: "node", bindHost: "0.0.0.0" } };
  for (const host of ["127.0.0.1:8787", "localhost", "[::1]:8787"]) {
    assert.equal(await ask(OBS, pub, host), 404, `Host ${host} must not create access on a public bind`);
  }
  // And a Worker/Deno deployment is unaffected by any Host value.
  for (const kind of ["cloudflare", "deno"]) {
    assert.equal(await ask(OBS, { runtime: { kind } }, "127.0.0.1:8787"), 404, `${kind}: still needs a token`);
  }
});

test("PR2.4: the dashboard route is guarded by the same Host check [GREEN NOW]", async () => {
  const page = (host) => handleRequest(new Request("http://127.0.0.1:8787/admin", { method: "GET", headers: host === null ? {} : { host } }), OBS, lb);
  assert.equal((await page("127.0.0.1:8787")).status, 200);
  assert.equal((await page("rebind.example:8787")).status, 404, "the HTML route must not be reachable either");
  assert.equal((await page(null)).status, 404);
});

// =====================================================================================
// Real adapter E2E: a genuine loopback TCP connection carrying a hostile Host
// =====================================================================================

/** Issue a raw HTTP request to 127.0.0.1:port with an arbitrary Host header. */
function rawRequest(port, path, hostHeader) {
  return new Promise((resolveP, rejectP) => {
    const req = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers: { host: hostHeader } }, (res) => {
      let body = "";
      res.on("data", (d) => { body += d; });
      res.on("end", () => resolveP({ status: res.statusCode, body, headers: res.headers }));
    });
    req.on("error", rejectP);
    req.end();
  });
}

async function withServer(env, fn) {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [SERVER], { cwd: REPO, env: { ...process.env, ...env, PORT: String(port) }, stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (d) => { stderr += String(d); });
  let up = false;
  for (let i = 0; i < 100; i++) {
    try { const r = await fetch(`http://127.0.0.1:${port}/healthz`); if (r.ok) { up = true; break; } } catch { /* not yet */ }
    await new Promise((r) => setTimeout(r, 50));
  }
  try {
    if (!up) throw new Error(`server did not start; stderr=${stderr.slice(0, 300)}`);
    return await fn(port);
  } finally {
    child.kill("SIGKILL");
    await new Promise((r) => child.once("exit", r));
  }
}

test("PR2.4 adapter: a real loopback connection with Host: rebind.example must not read /admin/api [GREEN NOW]", async () => {
  await withServer({ HOST: "127.0.0.1", REDACT_OBSERVABILITY: "1" }, async (port) => {
    // The legitimate local case, over the same socket path.
    const local = await rawRequest(port, "/admin/api", `127.0.0.1:${port}`);
    assert.equal(local.status, 200, "addressed locally, so the loopback exemption applies");

    // The same real TCP connection to 127.0.0.1, but a hostile Host -- the DNS rebinding case.
    const rebound = await rawRequest(port, "/admin/api", `rebind.example:${port}`);
    assert.notEqual(rebound.status, 200, "a hostile Host must NOT read the admin API");
    assert.equal(rebound.status, 404, "no configured token, so the route is hidden");
    assert.equal(rebound.body.includes("requests_total"), false, "and nothing about the data is disclosed");

    const reboundPage = await rawRequest(port, "/admin", `rebind.example:${port}`);
    assert.notEqual(reboundPage.status, 200, "and the dashboard is equally unreachable");
  });
});

test("PR2.4 adapter: with a token configured, a rebound Host requires it [GREEN NOW]", async () => {
  await withServer({ HOST: "127.0.0.1", REDACT_OBSERVABILITY: "1", REDACT_ADMIN_TOKEN: "rebind-token" }, async (port) => {
    const noCred = await rawRequest(port, "/admin/api", `rebind.example:${port}`);
    assert.equal(noCred.status, 401, "the route exists but demands a credential");
    const withCred = await new Promise((resolveP, rejectP) => {
      const req = httpRequest({ host: "127.0.0.1", port, path: "/admin/api", method: "GET",
        headers: { host: `rebind.example:${port}`, authorization: "Bearer rebind-token" } }, (res) => {
        let b = ""; res.on("data", (d) => { b += d; }); res.on("end", () => resolveP({ status: res.statusCode, body: b }));
      });
      req.on("error", rejectP); req.end();
    });
    assert.equal(withCred.status, 200, "a correct Bearer is still the way in");
    assert.ok(JSON.parse(withCred.body).counters, "and it serves the data");
  });
});
