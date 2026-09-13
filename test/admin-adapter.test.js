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
