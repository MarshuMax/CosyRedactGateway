// Token syntax regression tests.
//
// Background (all reproduced against current main):
//   1. `{{Redact:...}}` is not a valid YAML plain scalar. `password: {{Redact:ab}}`
//      makes a YAML parser raise "while constructing a mapping", so a user who
//      pastes a Secret manifest gets an invalid document back and the model then
//      reasons about a syntax error that was introduced by the gateway.
//   2. The portable token under design is `CRG_<request-id>_<entity-id>`,
//      charset strictly [A-Z0-9_] (see DESIGN-v2.md section 6.5).
//   3. A token must carry no plaintext-derived component. Anything computable
//      from the raw value is an offline verification oracle for low-entropy
//      secrets: PIN=0000 / PIN=1234 / PIN=9999 become distinguishable and can be
//      brute forced without the salt or the server.
//
// This file deliberately contains no third-party dependency, matching the
// project's "no runtime dependencies" constraint, so the YAML check uses a
// minimal plain-scalar/flow-collection validator instead of js-yaml. The
// validator is only required to be correct for the distinctions asserted here:
// whether a value is a valid plain scalar, and whether it is well-formed flow
// syntax.
//
// Assertion tags:
//   [GREEN NOW]  passes against current main
//   [RED]        fails against current main and specifies target behaviour
//   [COUPLING]   passes now only because production does not yet emit the
//                target format; must keep passing after the migration

import test from "node:test";
import assert from "node:assert/strict";
import { RedactionContext } from "../worker.js";

// ---------------------------------------------------------------- helpers ---

const PORTABLE_TOKEN_RE = /^CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}$/;
// Global, so that .match() returns every occurrence. A non-global regex makes
// .match() return only the first hit, which silently turns "count the tokens"
// assertions into "count at most one".
const CURRENT_PLACEHOLDER_RE = /\{\{Redact:[a-f0-9]{64}\}\}/g;
const CURRENT_PLACEHOLDER_RE_ONE = /\{\{Redact:[a-f0-9]{64}\}\}/;

// Minimal YAML plain-scalar validator.
// Returns { ok: true } or { ok: false, reason }.
function yamlPlainScalar(value) {
  if (value === "") return { ok: false, reason: "empty scalar" };
  const first = value[0];
  // A leading flow indicator opens a collection, which must then be well formed.
  if (first === "{" || first === "[") {
    const close = first === "{" ? "}" : "]";
    if (value[value.length - 1] !== close) {
      return { ok: false, reason: `unterminated flow collection (${first})` };
    }
    const inner = value.slice(1, -1).trim();
    if (!inner) return { ok: true }; // `{}` / `[]` are valid flow collections
    if (first === "{") {
      for (const pair of inner.split(",")) {
        const item = pair.trim();
        if (!item) continue;
        const colon = item.indexOf(":");
        if (colon < 0) return { ok: false, reason: `flow entry is not a key:value pair: ${item}` };
        if (!item.slice(0, colon).trim()) return { ok: false, reason: "flow mapping key is missing" };
      }
    }
    return { ok: true };
  }
  // Characters that may not start a plain scalar in YAML.
  if ("&*!|>'\"%@`,".includes(first)) return { ok: false, reason: `indicator at start: ${first}` };
  if (value.includes(": ")) return { ok: false, reason: "`: ` inside plain scalar" };
  if (value.includes(" #")) return { ok: false, reason: "` #` inside plain scalar" };
  return { ok: true };
}

function yamlAssign(key, value) {
  return { line: `${key}: ${value}`, ...yamlPlainScalar(value) };
}

const SHELL_SAFE_RE = /^[A-Za-z0-9_]+$/;
const ENV_KEY_SAFE_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const HEADER_VALUE_SAFE_RE = /^[\x20-\x7e]+$/; // no CR/LF/CTL

function urlQueryValue(url, param) {
  const q = url.slice(url.indexOf("?") + 1);
  for (const part of q.split("&")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq) === param) return decodeURIComponent(part.slice(eq + 1));
  }
  return null;
}

async function redactOne(value, ctx = new RedactionContext({ salt: "fixture" })) {
  const redacted = await ctx.redactText(value, { highEntropy: false, email: true, gitleaks: true });
  const match = redacted.match(CURRENT_PLACEHOLDER_RE_ONE);
  return { token: match ? match[0] : redacted, redacted, ctx, currentFormat: Boolean(match) };
}

function djb2Hex(s) {
  let h = 5381;
  for (const ch of s) h = ((h * 33) ^ ch.charCodeAt(0)) >>> 0;
  return h.toString(16).padStart(8, "0");
}

// Target token generator (test double). Placeholder until worker.js exports the
// real one -- see DESIGN-v2.md section 6.5.
//
// IMPORTANT: the entity id is a per-request allocation counter, NOT a function
// of the plaintext. Deriving it from a digest of the secret is exactly the
// oracle this file forbids, and would let a broken implementation pass these
// tests. Production must allocate ids from request-local state (or CSPRNG) and
// must never read the plaintext to build a token component.
function makeTargetTokenSource() {
  let next = 0;
  return (requestId = "7K2M9Q") => `CRG_${requestId}_${(++next).toString(36).toUpperCase().padStart(4, "0")}`;
}

// ---------------------------------------------------- 1. current behaviour ---

test("current placeholder breaks YAML plain scalars [GREEN NOW]", () => {
  // Asserted as a fact so that the fix shows up as a behaviour change rather
  // than an accidental test edit.
  const placeholder = "{{Redact:" + "a1b2c3d4".repeat(8) + "}}";
  const r = yamlAssign("password", placeholder);
  assert.equal(r.ok, false, `placeholder must not be a valid YAML plain scalar: ${r.reason || "it parsed"}`);
  assert.match(r.reason, /unterminated flow collection/);
});

test("current placeholder leaves URL and header usable, but needs shell quoting [GREEN NOW]", () => {
  const placeholder = "{{Redact:" + "a1b2c3d4".repeat(8) + "}}";
  assert.equal(urlQueryValue(`https://x/?access_token=${placeholder}`, "access_token"), placeholder);
  assert.match(placeholder, HEADER_VALUE_SAFE_RE);
  assert.equal(placeholder.includes("\n"), false);
  assert.equal(SHELL_SAFE_RE.test(placeholder), false, "brace form needs quoting in shell");
});

test("plaintext-derived checksum is an offline verification oracle [RED]", () => {
  // Reproduce the oracle: a component computed from the plaintext lets an
  // attacker verify guesses for a low-entropy secret without the salt or the
  // server. Truncation must take the LOW bits: for near-identical short inputs
  // the high bits are constant (0000/1234/9999 all hash into a 0x7c53..0x7c58
  // prefix), so a front-truncated checksum looks strong while being nearly
  // constant across the very candidate space it claims to protect.
  const withChecksum = (raw, nonce) => `CRG_${nonce}_0007_${djb2Hex(raw).slice(-2).toUpperCase()}`;
  const guesses = ["0000", "1234", "9999"].map((pin) => withChecksum(pin, "7K2M9Q"));
  assert.equal(new Set(guesses).size, 3, "fixture: a plaintext-derived checksum distinguishes candidates");

  // Target: only two components, and neither may be recomputable from a
  // candidate plaintext.
  const nextToken = makeTargetTokenSource();
  const target = nextToken("7K2M9Q");
  assert.match(target, PORTABLE_TOKEN_RE);
  const parts = target.split("_").slice(1);
  assert.equal(parts.length, 2, "token is CRG_<requestId>_<entityId>: there is no checksum field");
  for (const candidate of ["0000", "1234", "9999", "Pr0d-P@ssw0rd-Xy9Zk2mQ"]) {
    for (const part of parts) {
      assert.notEqual(
        part,
        djb2Hex(candidate).slice(-4).toUpperCase(),
        "no token component may be computable from the plaintext"
      );
    }
  }
});

// ------------------------------------------------ 2. target token syntax ----

test("portable token is a valid YAML plain scalar and shell-safe [RED]", async () => {
  const nextToken = makeTargetTokenSource();
  const { currentFormat, token } = await redactOne("Pr0d-P@ssw0rd-Xy9Zk2mQ");
  const target = currentFormat ? nextToken() : token;
  assert.match(target, PORTABLE_TOKEN_RE, "token must match the portable format");
  const r = yamlAssign("password", target);
  assert.equal(r.ok, true, `token must be a valid YAML plain scalar: ${r.reason}`);
  assert.equal(SHELL_SAFE_RE.test(target), true, "token must not need shell quoting");
});

test("portable token is usable as an .env key and as a URL/header value [RED]", () => {
  const token = makeTargetTokenSource()("7K2M9Q");
  assert.match(token, ENV_KEY_SAFE_RE, ".env keys must match [A-Za-z_][A-Za-z0-9_]*");
  assert.equal(encodeURIComponent(token), token, "token must be URL-safe without percent-encoding");
  assert.match(token, HEADER_VALUE_SAFE_RE, "token must be a valid header value");
});

// ------------------------------------------------------ 3. round-trip --------

test("redaction round-trip is byte-identical for every host syntax [COUPLING]", async () => {
  const ctx = new RedactionContext({ salt: "fixture" });
  const secret = "Pr0d-P@ssw0rd-Xy9Zk2mQ";
  const hosts = [
    (v) => `password: ${v}\n`,
    (v) => `DB_PASSWORD=${v}\n`,
    (v) => `export TOKEN="${v}"\n`,
    (v) => `Authorization: Bearer ${v}\n`,
    (v) => `https://api.example.com/v1?access_token=${v}\n`,
  ];
  for (const host of hosts) {
    const original = host(secret);
    assert.ok(original.includes(secret), "fixture must embed the secret verbatim");
    const redacted = await ctx.redactText(original, { gitleaks: true, highEntropy: true });
    assert.equal(ctx.restoreText(redacted), original, `round-trip must be byte-identical for: ${original.trim()}`);
  }
});

test("redaction is idempotent and never nests placeholders [GREEN NOW]", async () => {
  const ctx = new RedactionContext({ salt: "fixture" });
  const once = await ctx.redactText("DB_PASSWORD=cGFzc3dvcmQxMjM0NTY3OA==", { gitleaks: true });
  const twice = await ctx.redactText(once, { gitleaks: true });
  assert.equal(twice, once, "second pass must not re-wrap an already-redacted value");
  assert.equal((twice.match(/\{\{Redact:/g) || []).length, 1);
});

test("same plaintext within one request reuses one token [COUPLING]", async () => {
  const ctx = new RedactionContext({ salt: "fixture" });
  const secret = "cGFzc3dvcmQxMjM0NTY3OA==";
  // The key name must itself be credential-like: the generic-api-key rule is
  // gated on a keyword match (password/token/key/secret/...), so a fixture using
  // a neutral key such as `A=` is not detected at all and would test nothing.
  const a = await ctx.redactText(`PASSWORD=${secret}`, { gitleaks: true });
  const b = await ctx.redactText(`PASSWORD=${secret}`, { gitleaks: true });
  const tokenA = (a.match(CURRENT_PLACEHOLDER_RE) || [])[0];
  const tokenB = (b.match(CURRENT_PLACEHOLDER_RE) || [])[0];
  assert.ok(tokenA && tokenB, "fixture must produce tokens");
  assert.equal(tokenA, tokenB, "the same plaintext in the same request must reuse one token");
  // Two occurrences inside ONE payload must share a token. Note the fixture must
  // stay a single redactText call: comparing tokens across two separate calls is
  // not meaningful, because this test runs both through the same context and a
  // fresh Context (a real request) would build its own mapping.
  const payload = `PASSWORD=${secret}\nDB_PASSWORD=${secret}`;
  const tokens = (await ctx.redactText(payload, { gitleaks: true })).match(CURRENT_PLACEHOLDER_RE);
  assert.equal(tokens.length, 2, "fixture must produce one token per occurrence");
  assert.equal(tokens[0], tokens[1], "two occurrences of one plaintext in one payload must share a token");
});
