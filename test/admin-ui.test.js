// PR2.3 -- the self-contained /admin dashboard.
//
// The page must be ONE file: no npm front-end dependency, no CDN, no external JS/CSS, no fonts and
// no images. And every dynamic telemetry value must reach the DOM through textContent or
// createElement+textContent -- never concatenated into markup, so an upstream hostname or an enum
// cannot become script.

import test from "node:test";
import assert from "node:assert/strict";
import { handleRequest, __resetTelemetryStore } from "../worker.js";

const SECRET = "wJalrXUtnFEMIK7MDENGbPxRfiCY";
const EMAIL = "pr23.sentinel@example.com";
const TOKEN = "pr23-token";
const OBS = { REDACT_OBSERVABILITY: "1" };
const WITH_TOKEN = { ...OBS, REDACT_ADMIN_TOKEN: TOKEN };
const loopback = { runtime: { kind: "node", bindHost: "127.0.0.1" } };
const publicBind = { runtime: { kind: "node", bindHost: "0.0.0.0" } };

/** Admin page request with an EXPLICIT local Host; see admin-envelope.test.js for why. */
const getAdmin = (env, options, headers = {}) =>
  handleRequest(new Request("http://127.0.0.1:8787/admin", { method: "GET", headers: { host: "127.0.0.1:8787", ...headers } }), env, options);

/** Everything a browser would fetch from another origin, or any subresource at all. */
const EXTERNAL_PATTERNS = [
  /https?:\/\//i,          // any absolute URL
  /<link\b/i,              // stylesheets, icons, preloads
  /<img\b/i,
  /<script[^>]+\bsrc=/i,   // external scripts
  /@import/i,
  /url\(/i,                // CSS url() references
  /<iframe\b/i,
  /<object\b/i,
  /<embed\b/i,
];

test("PR2.3: the dashboard is one self-contained document with no external subresources [GREEN NOW]", async () => {
  const res = await getAdmin(OBS, loopback);
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") || "", /^text\/html/);
  const html = await res.text();
  // The ONLY url()/https:// allowed is none at all. The page's own fetch target is a relative path,
  // so even the API call does not produce an absolute URL in the markup.
  for (const pat of EXTERNAL_PATTERNS) {
    assert.equal(pat.test(html), false, `the dashboard must not reference external resources: ${pat}`);
  }
  assert.match(html, /fetch\("\/admin\/api"/, "data comes from the existing API, relatively");
  assert.match(html, /^<!doctype html>/i);
  assert.match(html, /<\/html>\s*$/);
});

test("PR2.3: dynamic values are written with textContent, never into markup [GREEN NOW]", async () => {
  const html = await (await getAdmin(OBS, loopback)).text();
  // Strip the comment explaining the rule, then require zero innerHTML usage in actual code.
  const withoutComments = html.replace(/\/\/[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
  assert.equal(withoutComments.includes("innerHTML"), false, "no innerHTML may remain in code");
  assert.equal(withoutComments.includes("outerHTML"), false);
  assert.equal(withoutComments.includes("insertAdjacentHTML"), false);
  assert.equal(withoutComments.includes("document.write"), false);
  assert.ok(withoutComments.includes("textContent"), "and textContent is actually used");
  // createElement + textContent is the only construction path.
  assert.ok(withoutComments.includes("createElement"), "elements are built explicitly");
});

test("PR2.3: the dashboard carries admin hardening headers and no CORS [GREEN NOW]", async () => {
  const res = await getAdmin(OBS, loopback);
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  assert.match(res.headers.get("content-security-policy") || "", /default-src 'none'/);
  assert.match(res.headers.get("content-security-policy") || "", /script-src 'sha256-[A-Za-z0-9+/=]+'/);
  assert.equal(res.headers.get("access-control-allow-origin"), null, "no CORS on the admin page");
});

test("PR2.3: the CSP script hash matches the FULL inline script textContent a browser hashes [GREEN NOW]", async () => {
  // THIS TEST WAS VACUOUS AND THE PAGE WAS BROKEN IN A REAL BROWSER.
  //
  // Chrome computes a CSP hash over the script element's textContent -- the bytes BETWEEN <script>
  // and </script>, INCLUDING any leading and trailing newlines. The previous version matched
  // `/<script>\n([\s\S]*?)\n<\/script>/` and hashed the capture group, which excludes those two
  // newlines. It therefore verified a byte sequence no browser ever hashes, and reported success
  // while CSP refused to execute the dashboard's script.
  //
  // The hash now comes from the FULL textContent, and the template no longer has boundary newlines,
  // so the test's input and the browser's input are byte-identical by construction.
  const { createHash } = await import("node:crypto");
  const res = await getAdmin(OBS, loopback);
  const html = await res.text();
  const csp = res.headers.get("content-security-policy") || "";
  const declared = /script-src 'sha256-([A-Za-z0-9+/=]+)'/.exec(csp);
  assert.ok(declared, "the CSP must pin a script hash");
  const script = /<script>([\s\S]*?)<\/script>/.exec(html);
  assert.ok(script, "the inline script must be found");
  const textContent = script[1];
  // The property that makes the two computations comparable, asserted rather than assumed: no
  // boundary whitespace, so a browser's textContent is exactly this string.
  assert.equal(textContent.startsWith("\n") || textContent.startsWith("\r"), false,
    "no leading newline inside <script>: a browser would hash it and the declared hash would not cover it");
  assert.equal(/[\r\n]$/.test(textContent), false,
    "no trailing newline inside <script>, for the same reason");
  const actual = createHash("sha256").update(textContent, "utf8").digest("base64");
  assert.equal(actual, declared[1], "the declared hash must match the FULL script textContent");
  // And the script must actually be the dashboard, so a hashed-but-empty script cannot pass.
  assert.ok(textContent.includes("/admin/api"), "the hashed script is the dashboard's fetch loop");
  assert.ok(textContent.length > 1000, "and it is the real script, not a stub");
});

test("PR2.3: /admin is GET-only, admission first [GREEN NOW]", async () => {
  // Non-GET is refused AFTER admission, so an unauthorised caller learns nothing about method support.
  for (const method of ["POST", "PUT", "DELETE", "OPTIONS"]) {
    const unauth = await handleRequest(new Request("http://127.0.0.1:8787/admin", { method, headers: { host: "127.0.0.1:8787" } }), WITH_TOKEN, publicBind);
    assert.equal(unauth.status, 401, `${method}: admission runs first`);
    assert.equal(unauth.headers.get("cache-control"), "no-store");
    assert.equal(unauth.headers.get("access-control-allow-origin"), null);
    const authed = await handleRequest(new Request("http://127.0.0.1:8787/admin", { method, headers: { host: "127.0.0.1:8787", authorization: `Bearer ${TOKEN}` } }), WITH_TOKEN, publicBind);
    assert.equal(authed.status, 405, `${method}: admitted, so the method is what fails`);
    assert.equal(authed.headers.get("allow"), "GET");
    assert.equal(authed.headers.get("cache-control"), "no-store");
    assert.equal(authed.headers.get("access-control-allow-origin"), null);
  }
});

test("PR2.3: the dashboard requires the same admission as the API [GREEN NOW]", async () => {
  assert.equal((await getAdmin({}, loopback)).status, 404, "observability off");
  assert.equal((await getAdmin(OBS, publicBind)).status, 404, "public bind, no token configured");
  assert.equal((await getAdmin(WITH_TOKEN, publicBind)).status, 401, "public bind, no credential");
  assert.equal((await getAdmin(WITH_TOKEN, publicBind, { authorization: "Bearer wrong" })).status, 401);
  assert.equal((await getAdmin(WITH_TOKEN, publicBind, { authorization: `Bearer ${TOKEN}` })).status, 200);
  // Query and cookie credentials are still not accepted for the page either.
  const q = await handleRequest(new Request(`http://127.0.0.1:8787/admin?token=${TOKEN}`, { method: "GET", headers: { host: "127.0.0.1:8787" } }), WITH_TOKEN, publicBind);
  assert.equal(q.status, 401, "a query credential must not open the page");
  const c = await getAdmin(WITH_TOKEN, publicBind, { cookie: `token=${TOKEN}` });
  assert.equal(c.status, 401, "a cookie must not open the page");
});

test("PR2.3: the served page contains no sentinel from a real request lifecycle [GREEN NOW]", async () => {
  __resetTelemetryStore();
  // Produce real telemetry first, so the absence checks below are meaningful.
  await (await handleRequest(new Request("https://proxy.example/H$https://api.example/v1/chat/completions", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "g", messages: [{ role: "user", content: `PW=${SECRET} mail ${EMAIL}` }] }),
  }), OBS, { salt: "pr23", fetchImpl: async () => new Response('{"ok":true}', { headers: { "content-type": "application/json" } }) })).text();

  const html = await (await getAdmin(OBS, loopback)).text();
  for (const forbidden of [SECRET, EMAIL, "CRG_", "api.example"]) {
    // "api.example" is the upstream HOSTNAME, which the API legitimately records and the page
    // renders. It must appear in the PAGE ONLY as a value fetched at runtime, never baked into the
    // served markup -- that is the property being asserted here.
    assert.equal(html.includes(forbidden), false, `the served page must not contain ${forbidden}; values arrive via /admin/api at runtime`);
  }
  assert.ok((await getAdmin(OBS, loopback)).status === 200, "and it is still served");
});
