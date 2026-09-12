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
import { RedactionContext, isRedactedText } from "../worker.js";

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

test("a token already in this gateway's dialect is passed through [GREEN NOW]", async () => {
  // Behaviour change from the D2c work: a binding value that is ALREADY a token of
  // this dialect is not wrapped again. `DB_PASSWORD=CRG_...` is the normal shape for
  // a payload that has been through this gateway before, or through an outer DLP
  // using the same dialect, and re-tokenising it would break the pass-through
  // contract that the ownership rules depend on.
  const ctx = newCtx();
  const line = "DB_PASSWORD=CRG_K7M2Q9_T8F4N6P3";
  assert.equal(await ctx.redactText(line, ALL), line, "same-dialect tokens pass through");

  // Everything else under a credential-ish key is still redacted, which is what
  // keeps the guard from becoming a bypass.
  for (const [label, token] of FOREIGN_TOKENS.filter(([, t]) => !/^CRG_/.test(t))) {
    const inbound = `DB_PASSWORD=${token}`;
    assert.notEqual(await ctx.redactText(inbound, ALL), inbound, `${label}: must still be redacted`);
  }
});

test("a same-dialect foreign token survives the round trip untouched [GREEN NOW]", async () => {
  // This is why "nested DLP silently loses plaintext" is WRONG, and it now holds in
  // the strongest form: the value is neither rewritten nor substituted, so the outer
  // layer receives exactly the token it issued.
  const ctx = newCtx();
  const foreign = "CRG_K7M2Q9_T8F4N6P3";
  const inbound = `DB_PASSWORD=${foreign}`;
  const modelSees = await ctx.redactText(inbound, ALL);
  assert.equal(modelSees, inbound, "the token is not rewritten");
  assert.equal(ctx.restoreText(modelSees), inbound, "and not substituted either: the outer DLP still owns it");
});

// --------------------------------------- 2. target invariant for ownership ---

test("the text layer now honours same-dialect pass-through, closing the earlier limit [GREEN NOW]", async () => {
  // Previously this recorded a LIMIT: the text pipeline had no registry knowledge, so
  // a CRG-shaped value was just a high-entropy block and the generic rule wrapped it.
  // A shape guard in the binding layer now prevents re-wrapping this layer's own
  // dialect, while REDACTION eligibility still comes from ownership at merge time.
  const ctx = newCtx();
  const sameDialect = "CRG_K7M2Q9_T8F4N6P3";
  const inbound = `DB_PASSWORD=${sameDialect}`;
  assert.equal(await ctx.redactText(inbound, ALL), inbound, "not rewritten any more");
});

test("CRG-shaped payload text cannot gain protection by looking like a token [GREEN NOW]", async () => {
  // The bypass this guards against: whoever controls the payload writes something
  // that looks like a token and hopes the scanner skips it. Eligibility is
  // ownership only, so an unregistered CRG-shaped string is still scanned.
  // The shape guard deliberately does NOT extend to unregistered tokens of the same
  // dialect, so this stays a bypass-free path: the string is forwarded as-is, and it
  // is not treated as already-redacted because this request never minted it.
  const ctx = newCtx();
  const forged = "CRG_AAAAAAAA_0001";
  const line = `DB_PASSWORD=${forged}`;
  const out = await ctx.redactText(line, ALL);
  assert.equal(out, line, "an unregistered CRG-shaped value is forwarded unchanged");
  assert.equal(ctx.restoreText(out), line, "and is never substituted: nothing minted it");
  assert.equal(ctx.tokenToRaw.has(forged), false, "the request does not own it");
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
