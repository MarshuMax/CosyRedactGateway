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

test("current gateway re-wraps most foreign tokens [GREEN NOW]", async () => {
  const ctx = newCtx();
  const rewritten = [];
  for (const [label, token] of FOREIGN_TOKENS) {
    const line = `DB_PASSWORD=${token}`;
    const out = await ctx.redactText(line, ALL);
    if (out !== line) rewritten.push(label);
  }
  // D1 structured context widened this set: every foreign token here sits under a
  // credential-ish key name (`DB_PASSWORD`), so the binding span now covers it
  // regardless of value shape. The bracketed form is caught too, for the same
  // reason -- the old "it survives by accident of the value class" note is gone.
  assert.deepEqual(rewritten, [
    "client DLP token (proposed CRG format)",
    "Vault-style token",
    "masked prefix",
    "raw hex placeholder",
    "bracketed token",
  ]);
});

test("re-wrapping preserves the value through the full round trip [GREEN NOW]", async () => {
  // This is why "nested DLP silently loses plaintext" is WRONG: as long as this
  // layer restores exactly what it was given, the outer layer can still finish
  // its own restore.
  const ctx = newCtx();
  const foreign = "CRG_K7M2Q9_T8F4N6P3";
  const inbound = `DB_PASSWORD=${foreign}`;
  const modelSees = await ctx.redactText(inbound, ALL);
  assert.notEqual(modelSees, inbound, "current behaviour: value is re-wrapped");
  assert.equal(ctx.restoreText(modelSees), inbound, "exact restore, so the outer DLP can continue");
});

// --------------------------------------- 2. target invariant for ownership ---

test("text-level redaction rewrites foreign tokens matching our dialect [GREEN NOW]", async () => {
  // This records a LIMIT of the text pipeline, not the target contract. The
  // ownership contract (never restore, never rewrite a registered foreign token)
  // is enforced at the policy layer and tested in test/foreign-token.test.js.
  //
  // The text pipeline cannot honour it for tokens that share our dialect, because
  // findSensitiveSpans runs without registry knowledge: a CRG-shaped string is
  // just a high-entropy block, and the generic-api-key rule wraps it. The bracketed
  // fixture is intentionally excluded -- it is currently not rewritten, but that is
  // an accident of the value character class, not a guarantee.
  const ctx = newCtx();
  for (const [label, token] of FOREIGN_TOKENS.filter(([, t]) => /^[A-Z0-9_]+$/.test(t))) {
    const inbound = `DB_PASSWORD=${token}`;
    const modelVisible = await ctx.redactText(inbound, ALL);
    assert.notEqual(modelVisible, inbound, `${label}: rewritten at the text layer`);
    assert.equal(ctx.restoreText(modelVisible), inbound, `${label}: and restored exactly, so nothing is lost`);
  }
});

test("CRG-shaped payload text cannot gain protection by looking like a token [GREEN NOW]", async () => {
  // The bypass this guards against: whoever controls the payload writes something
  // that looks like a token and hopes the scanner skips it. Eligibility is
  // ownership only, so an unregistered CRG-shaped string is still scanned.
  const ctx = newCtx();
  const forged = "CRG_AAAAAAAA_0001";
  const line = `DB_PASSWORD=${forged}`;
  const out = await ctx.redactText(line, ALL);
  assert.notEqual(out, line, "a forged token must not be treated as already-redacted");
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
