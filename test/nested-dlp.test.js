// Nested DLP / foreign token ownership tests.
//
// Scenario: the client already runs its own DLP (clipboard guard, IDE secret
// scanner, upstream proxy) and sends values that are already pseudonymized when
// they reach this gateway.
//
// Measured against current main:
//   CRG_K7M2Q9_T8F4N6P3      -> re-wrapped by the gateway (generic-api-key rule)
//   VAULT_TOKEN_xyz789       -> re-wrapped
//   MASKED_abc123def456      -> re-wrapped
//   <32 hex>                 -> re-wrapped
//   [[PII_EMAIL_1]]          -> passes through (contains brackets, escapes the
//                               value character class of generic-api-key)
//
// The trigger is the generic-api-key rule (left-hand key name matches
// password|token|key|secret|... plus a value character class), not entropy.
//
// The correct invariant is NOT `model_visible === restored`. Ordinary redaction
// deliberately makes those differ:
//
//   client sends AKIA...  ->  model sees GW_TOKEN  ->  client receives AKIA...
//
// The invariant that matters for a *registered foreign token* is that this layer
// must not rewrite it at all:
//
//   input_to_gateway === model_visible === gateway_output
//
// Assertion tags:
//   [GREEN NOW]  passes against current main
//   [RED]        fails against current main and specifies target behaviour

import test from "node:test";
import assert from "node:assert/strict";
import { RedactionContext, ForeignTokenRegistry, isRedactedText } from "../worker.js";

const ALL = { highEntropy: true, phone: true, secret: true, identity: true, bank: true, email: true, gitleaks: true };
const PLACEHOLDER_RE = /\{\{Redact:[a-f0-9]{64}\}\}/g;

const FOREIGN_TOKENS = [
  ["client DLP token (proposed CRG format)", "CRG_K7M2Q9_T8F4N6P3"],
  ["Vault-style token", "VAULT_TOKEN_xyz789"],
  ["masked prefix", "MASKED_abc123def456"],
  ["raw hex placeholder", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"],
  ["bracketed token", "[[PII_EMAIL_1]]"],
];

function newCtx() {
  return new RedactionContext({ salt: "fixture" });
}

// A redaction is defined structurally (any registered token shape), not by
// matching one format's literal syntax -- the v1 pattern is being retired.
function rewriteCount(before, after) {
  return isRedactedText(after) && !isRedactedText(before) ? 1 : 0;
}

// ------------------------------------------- 1. what happens right now ------

test("an UNREGISTERED token-shaped literal is redacted, not exempted [GREEN NOW]", async () => {
  // This replaces three earlier tests that asserted the opposite and were WRONG.
  // A shape guard in the binding layer used to skip any CRG-shaped value, so
  // `DB_PASSWORD=CRG_AAAA_AAAA` -- a perfectly plausible low-entropy password -- was
  // forwarded in the clear: the binding candidate never reached the merge, and neither
  // entropy nor the generic rule fires on it. Shape is not ownership.
  const ctx = newCtx();
  for (const token of ["CRG_AAAA_AAAA", "CRG_K7M2Q9_T8F4N6P3", "VAULT_TOKEN_xyz789"]) {
    const inbound = `DB_PASSWORD=${token}`;
    const out = await ctx.redactText(inbound, ALL);
    assert.notEqual(out, inbound, `${token}: an unowned token-shaped literal must be redacted`);
    assert.equal(out.includes(token), false, `${token}: and must not survive in the output`);
  }
});

test("KNOWN TRANSITIONAL GAP: the legacy v1 shape is still exempt on input [GREEN NOW]", async () => {
  // Recorded as a fact, NOT as desired behaviour. During the dual-format transition
  // `protectedTokenPatterns` still contains the legacy shape, because a v1 token
  // carries no request-local namespace and therefore cannot be checked against the
  // mapping. The consequence is the same bypass shape that was just fixed for v2:
  // anyone can write `{{Redact:<64 hex>}}` and have that value skipped.
  //
  // Removal condition already noted in DESIGN-v2 9.1: when the legacy restore branch
  // is deleted, this exemption goes with it. Until then the gap is documented here so
  // it cannot be forgotten.
  const ctx = newCtx();
  const forgedLegacy = "{{Redact:" + "a".repeat(64) + "}}";
  const inbound = `DB_PASSWORD=${forgedLegacy}`;
  assert.equal(await ctx.redactText(inbound, ALL), inbound, "still exempt today");
  assert.equal(ctx.tokenToRaw.has(forgedLegacy), false, "and the request does not own it");
});

test("an OWNED token is preserved on the input path [GREEN NOW]", async () => {
  // The legitimate case the shape guard was trying to serve, now decided by ownership.
  const ctx = newCtx();
  const owned = (await ctx.redactText("a@example.com", { email: true })).match(/CRG_[A-Z0-9]+_[A-Z0-9]+/)[0];
  const inbound = `DB_PASSWORD=${owned}`;
  assert.equal(await ctx.redactText(inbound, ALL), inbound, "a token this request minted is passed through");
});

test("a REGISTERED foreign token is preserved on the input path too [GREEN NOW]", async () => {
  // Closes a gap left by the B group: the registry only governed the restore policy,
  // so the forward path still re-tokenised a token an outer DLP had issued. Input
  // ownership now uses the same three-way judgement as the return path.
  const ACME = { name: "acme", pattern: /(?<![A-Za-z0-9_])ACME_[A-Z0-9_]{4,}(?![A-Za-z0-9_])/ };
  const registry = new ForeignTokenRegistry([ACME]);
  const ctx = new RedactionContext({ salt: "fixture", foreignRegistry: registry });
  const inbound = "DB_PASSWORD=ACME_ABCDEF_0001";
  assert.equal(await ctx.redactText(inbound, ALL), inbound, "a registered foreign token passes through");

  // Without the registration the same literal is an ordinary value and is redacted.
  const bare = newCtx();
  assert.notEqual(await bare.redactText(inbound, ALL), inbound, "unregistered: redacted");
});

test("ownership is the only exemption, on both paths [GREEN NOW]", async () => {
  // One table covering input ownership and the restore policy together, so the two
  // cannot drift apart again.
  const ACME = { name: "acme", pattern: /(?<![A-Za-z0-9_])ACME_[A-Z0-9_]{4,}(?![A-Za-z0-9_])/ };
  const registry = new ForeignTokenRegistry([ACME]);
  const ctx = new RedactionContext({ salt: "fixture", foreignRegistry: registry });
  const owned = (await ctx.redactText("a@example.com", { email: true })).match(/CRG_[A-Z0-9]+_[A-Z0-9]+/)[0];

  const table = [
    ["OWN", owned, "preserve"],
    ["FOREIGN_REGISTERED", "ACME_ABCDEF_0001", "preserve"],
    ["UNKNOWN token-shaped", "CRG_AAAA_AAAA", "redact"],
    ["UNKNOWN foreign-shaped", "EVIL_ABCDEF_0001", "redact"],
    ["ordinary secret", "cGFzc3dvcmQxMjM0NTY3OA==", "redact"],
  ];
  for (const [kind, value, expected] of table) {
    const inbound = `DB_PASSWORD=${value}`;
    const out = await ctx.redactText(inbound, ALL);
    const action = out === inbound ? "preserve" : "redact";
    assert.equal(action, expected, `${kind}: expected ${expected}, got ${action} (${out})`);
  }
});

test("unregistered secrets are still redacted (no blanket pass-through) [GREEN NOW]", async () => {
  const ctx = newCtx();
  const line = "DB_PASSWORD=cGFzc3dvcmQxMjM0NTY3OA==";
  const out = await ctx.redactText(line, ALL);
  assert.equal(rewriteCount(line, out), 1, "an ordinary secret must still be redacted");
});

// ------------------------------- 3. the real variable: outer DLP direction ---

test("tool-call fidelity depends on the outer layer, not on wrapping [GREEN NOW]", () => {
  // Simulates the full chain. The decisive question is whether the OUTER DLP
  // restores secrets on the egress (tool-call) direction.
  const REAL = "Pr0d-P@ssw0rd-Xy9Zk2mQ";
  const CLIENT_TOKEN = "CRG_K7M2Q9_T8F4N6P3";
  const GW_TOKEN = "{{Redact:" + "a".repeat(64) + "}}";
  const disk = `DB_PASSWORD=${REAL}\n`;

  const run = ({ gatewayWraps, outerRestoresEgress }) => {
    const inbound = `DB_PASSWORD=${gatewayWraps ? CLIENT_TOKEN : CLIENT_TOKEN}`;
    const modelVisible = gatewayWraps ? `DB_PASSWORD=${GW_TOKEN}` : inbound;
    const seenValue = modelVisible.split("=")[1];
    let command = `grep -r "${seenValue}" /etc/app/config`;
    if (gatewayWraps) command = command.replace(GW_TOKEN, CLIENT_TOKEN);
    if (outerRestoresEgress) command = command.replace(CLIENT_TOKEN, REAL);
    const pattern = command.match(/"([^"]+)"/)[1];
    return { pattern, hits: disk.split("\n").filter((l) => l.includes(pattern)).length };
  };

  const a = run({ gatewayWraps: true, outerRestoresEgress: false });
  assert.equal(a.hits, 0, "wrapping + outer DLP without egress restore => tool call misses");

  const b = run({ gatewayWraps: true, outerRestoresEgress: true });
  assert.equal(b.hits, 1, "outer DLP with egress restore => tool call hits");

  const c = run({ gatewayWraps: false, outerRestoresEgress: false });
  assert.equal(c.hits, 0, "pass-through alone does NOT fix the miss: the model grep'd a pseudonym");

  // Conclusion asserted as a test: pass-through is required for the outer layer
  // to do its job, but it is not sufficient, and it is not the cause of the
  // miss either. Only egress restoration decides the outcome.
  assert.equal(b.pattern, REAL);
});
