// PR2.1 -- REAL adapter wiring, not a fabricated metadata object.
//
// The envelope suite calls handleRequest directly with `{ runtime: { kind: "node", bindHost } }`,
// which proves the POLICY handles that input. It does not prove the Node adapter actually SUPPLIES
// it. That distinction was a live gap: node-server.mjs still called `handleRequest(request, env)`
// while the envelope tests passed, so the loopback exemption was never reachable in a real
// deployment -- and every one of those 11 assertions was green regardless.
//
// This file therefore boots the real server in a real child process and makes real HTTP requests.
// It does not read node-server.mjs as text, because a source grep would have passed against the
// broken wiring too (the string it looked for was absent, but so was any evidence of behaviour).

import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SERVER = resolve(REPO, "node-server.mjs");

/** Boot the real adapter on an ephemeral port and wait until it answers. */
async function withServer(env, fn) {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [SERVER], {
    cwd: REPO,
    env: { ...process.env, ...env, PORT: String(port) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (d) => { stderr += String(d); });
  const base = `http://127.0.0.1:${port}`;
  // Give it a bounded window to come up; no fixed sleep as the only mechanism.
  let up = false;
  for (let i = 0; i < 100; i++) {
    try { const r = await fetch(`${base}/healthz`); if (r.ok) { up = true; break; } } catch { /* not yet */ }
    await new Promise((r) => setTimeout(r, 50));
  }
  try {
    if (!up) throw new Error(`server did not start; stderr=${stderr.slice(0, 400)}`);
    return await fn(base);
  } finally {
    child.kill("SIGKILL");
    await new Promise((r) => child.once("exit", r));
  }
}

test("PR2.1 adapter: a real node-server bound to 127.0.0.1 serves /admin without a token [GREEN NOW]", async () => {
  await withServer({ HOST: "127.0.0.1", REDACT_OBSERVABILITY: "1" }, async (base) => {
    const res = await fetch(`${base}/admin`);
    assert.equal(res.status, 200, "the REAL adapter must supply loopback metadata; a fabricated object proves nothing");
    assert.equal(await res.text(), "admin endpoint available\n");
    assert.equal(res.headers.get("cache-control"), "no-store");
  });
});

test("PR2.1 adapter: a real write to 127.0.0.1 is reachable, so the test is not vacuous [GREEN NOW]", async () => {
  // Confirms the server really is bound to loopback and answering, rather than the 200 coming from
  // some other path.
  await withServer({ HOST: "127.0.0.1", REDACT_OBSERVABILITY: "1" }, async (base) => {
    const health = await fetch(`${base}/healthz`);
    assert.equal(health.status, 200);
    assert.equal((await health.json()).ok, true);
  });
});

test("PR2.1 adapter: a public bind with no token hides /admin, and with a token requires Bearer [GREEN NOW]", async () => {
  // Host is 0.0.0.0 (a genuine public bind) while the test connects over loopback. The exemption must
  // follow the BIND ADDRESS, not the peer address -- otherwise any client could reach it.
  await withServer({ HOST: "0.0.0.0", REDACT_OBSERVABILITY: "1" }, async (base) => {
    const noToken = await fetch(`${base}/admin`);
    assert.equal(noToken.status, 404, "a public bind without a configured token must stay hidden");

    // Even the loopback peer address and a forged Host must not help.
    const forged = await fetch(`${base}/admin`, { headers: { host: "127.0.0.1", "x-forwarded-for": "127.0.0.1" } });
    assert.equal(forged.status, 404, "forged headers must not substitute for the bind address");
  });

  await withServer({ HOST: "0.0.0.0", REDACT_OBSERVABILITY: "1", REDACT_ADMIN_TOKEN: "adapter-secret" }, async (base) => {
    assert.equal((await fetch(`${base}/admin`)).status, 401, "no credential");
    assert.equal((await fetch(`${base}/admin`, { headers: { authorization: "Bearer wrong" } })).status, 401, "wrong credential");
    assert.equal((await fetch(`${base}/admin?token=adapter-secret`)).status, 401, "a query credential is not accepted");
    const ok = await fetch(`${base}/admin`, { headers: { authorization: "Bearer adapter-secret" } });
    assert.equal(ok.status, 200, "the correct Bearer reaches the route through the real adapter");
  });
});

test("PR2.1 adapter: observability off hides /admin even on a loopback bind [GREEN NOW]", async () => {
  await withServer({ HOST: "127.0.0.1" }, async (base) => {
    assert.equal((await fetch(`${base}/admin`)).status, 404);
  });
});

test("PR2.1 adapter: the proxy path still works end to end through the real server [GREEN NOW]", async () => {
  // Guards against the metadata wiring having disturbed normal operation.
  await withServer({ HOST: "127.0.0.1", REDACT_OBSERVABILITY: "1" }, async (base) => {
    // No upstream is reachable, so a valid route should fail at the FETCH, not at routing: 502.
    const res = await fetch(`${base}/H$https://127.0.0.1:1/v1/chat/completions`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "g", messages: [{ role: "user", content: "hi" }] }),
    });
    assert.equal(res.status, 502, "a valid route with an unreachable upstream is an upstream failure");
    const health = await fetch(`${base}/healthz`);
    assert.equal(health.status, 200, "and the server is still healthy afterwards");
  });
});

// =====================================================================================
// PR2.2 -- the read-only API through the real server
// =====================================================================================

test("PR2.2 adapter: a real proxy request produces telemetry that the real /admin/api serves [GREEN NOW]", async () => {
  const SECRET = "wJalrXUtnFEMIK7MDENGbPxRfiCY";
  const EMAIL = "pr22-e2e@example.com";
  // A real upstream standing in for a provider, so the request completes normally.
  const http = await import("node:http");
  const upstream = http.createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ choices: [{ message: { role: "assistant", content: "ok" } }] }));
  });
  await new Promise((r) => upstream.listen(0, "127.0.0.1", r));
  const upstreamPort = upstream.address().port;

  try {
    await withServer({ HOST: "127.0.0.1", REDACT_OBSERVABILITY: "1" }, async (base) => {
      // 1. Drive a REAL request through the real server so the store holds something.
      const proxied = await fetch(`${base}/H$http://127.0.0.1:${upstreamPort}/v1/chat/completions`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "g", messages: [{ role: "user", content: `PW=${SECRET} mail ${EMAIL}` }] }),
      });
      assert.equal(proxied.status, 200, "the proxy request must complete");
      const proxiedBody = await proxied.text();
      assert.equal(proxiedBody.includes(SECRET), false, "and the secret must not come back to the client");

      // 2. Read it back through the real /admin/api.
      const api = await fetch(`${base}/admin/api`);
      assert.equal(api.status, 200, "loopback bind, observability on");
      assert.equal(api.headers.get("cache-control"), "no-store");
      const data = await api.json();
      assert.ok(data.counters.requests_total >= 1, `expected the request to be counted; got ${JSON.stringify(data.counters)}`);
      assert.ok(data.counters.requests_redacted >= 1, "and counted as redacted");
      assert.ok(data.recent.length >= 1, "the record is there");
      assert.equal(data.recent[0].outcome, "forwarded");

      // 3. The API body must not leak the sentinel that travelled through that request.
      const raw = JSON.stringify(data);
      for (const forbidden of [SECRET, EMAIL, "CRG_"]) {
        assert.equal(raw.includes(forbidden), false, `/admin/api must not contain ${forbidden}`);
      }
    });
  } finally {
    upstream.close();
  }
});

test("PR2.2 adapter: /admin/api needs the same admission as /admin on a public bind [GREEN NOW]", async () => {
  await withServer({ HOST: "0.0.0.0", REDACT_OBSERVABILITY: "1", REDACT_ADMIN_TOKEN: "api-token" }, async (base) => {
    assert.equal((await fetch(`${base}/admin/api`)).status, 401, "no credential");
    assert.equal((await fetch(`${base}/admin/api?token=api-token`)).status, 401, "query credential is not accepted");
    const ok = await fetch(`${base}/admin/api`, { headers: { authorization: "Bearer api-token" } });
    assert.equal(ok.status, 200);
    const data = await ok.json();
    assert.ok(Array.isArray(data.recent), "and it serves JSON");
  });
});
