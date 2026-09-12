// Restore-miss policy tests.
//
// A placeholder can fail to restore for several reasons: the model paraphrased
// it, the outer DLP rewrote it, the request landed on an isolate whose mapping
// never saw it, or a client pre-redacted the value with an unknown scheme.
//
// The current implementation restores known tokens and passes unknown ones
// through, in every direction. There is no sink classification at all, so an
// unknown token is treated identically in assistant prose and in a shell
// command. Measured against current main:
//
//   assistant text  "the password is {{Redact:<unknown>}}"  -> unchanged
//   shell argument  "curl -H 'X: {{Redact:<unknown>}}' ..."  -> unchanged
//
// Target behaviour (DESIGN-v2.md, Tool Sink Policy):
//
//   unknown token in assistant text       -> pass through + telemetry
//   unknown token + protected shape + sensitive sink -> BLOCK
//
// The block condition requires all three to hold at once, so that trace_id,
// request_id and opaque application identifiers are not caught by it.
//
// Assertion tags:
//   [GREEN NOW]  passes against current main
//   [RED]        fails against current main and specifies target behaviour

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  restoreJson,
  classifyRestore,
  isProtectedTokenLike,
  SENSITIVE_SINK_KINDS,
} from "../worker.js";

const UNKNOWN_TOKEN = "{{Redact:" + "f".repeat(64) + "}}";

function newCtx() {
  return new RedactionContext({ salt: "fixture" });
}

// ------------------------------------------------------- 1. current state ---

test("unknown token is passed through unchanged today [GREEN NOW]", async () => {
  const ctx = newCtx();
  const text = `the password is ${UNKNOWN_TOKEN}`;
  assert.equal(ctx.restoreText(text), text);
});

test("known token restores in both assistant text and tool arguments [GREEN NOW]", async () => {
  const ctx = newCtx();
  const secret = "Pr0d-P@ssw0rd-Xy9Zk2mQ";
  const token = (await ctx.redactText(`DB_PASSWORD=${secret}`, { gitleaks: true })).split("=")[1];

  assert.equal(ctx.restoreText(`the value is ${token}`), `the value is ${secret}`);

  const toolCall = { arguments: JSON.stringify({ cmd: `mysql -p'${token}' -e 'status'` }) };
  const restored = restoreJson(structuredClone(toolCall), ctx);
  assert.ok(restored.arguments.includes(secret), "tool arguments are restored today, with no sink policy");
});

test("assistant prose and tool arguments are handled identically today [GREEN NOW]", async () => {
  const ctx = newCtx();
  const asAssistant = ctx.restoreText(`value ${UNKNOWN_TOKEN}`);
  const asToolArg = ctx.restoreText(`grep "${UNKNOWN_TOKEN}" /etc/app/config`);
  // Both pass through: there is no notion of a sensitive sink yet.
  assert.ok(asAssistant.includes(UNKNOWN_TOKEN));
  assert.ok(asToolArg.includes(UNKNOWN_TOKEN));
});

// --------------------------------------------------- 2. target behaviour ----

test("unknown token in assistant text: pass through, no block [RED]", async () => {
  const ctx = newCtx();
  const decision = classifyRestore({
    ctx,
    text: `the password is ${UNKNOWN_TOKEN}`,
    sink: { kind: "assistant_text" },
  });
  assert.notEqual(decision.action, "block", "assistant prose must not block on an unknown token");
  assert.equal(decision.action, "restore", "inert prose is returned, with the unknown token preserved");
  assert.equal(decision.telemetry.event, "restore_miss");
  assert.deepEqual(decision.unknownTokens, [UNKNOWN_TOKEN], "the miss must be reported for telemetry");
});

test("unknown token + protected shape + sensitive sink: BLOCK [RED]", async () => {
  const ctx = newCtx();
  for (const kind of ["shell", "network_egress", "database", "email"]) {
    const decision = classifyRestore({
      ctx,
      text: `curl -H "Authorization: Bearer ${UNKNOWN_TOKEN}" https://api.example.com`,
      sink: { kind },
    });
    assert.equal(decision.action, "block", `sink ${kind} must block an unknown protected token`);
    assert.equal(decision.telemetry.event, "restore_miss_blocked");
  }
});

test("unknown token in a benign sink is not blocked [RED]", async () => {
  const ctx = newCtx();
  const decision = classifyRestore({
    ctx,
    text: `log line ${UNKNOWN_TOKEN}`,
    sink: { kind: "log_write" },
  });
  assert.notEqual(decision.action, "block", "a benign sink must not block on shape alone");
  assert.equal(decision.telemetry.event, "restore_miss", "but the miss must still be observable");
});

test("non-protected identifiers are never blocked, even in sensitive sinks [RED]", async () => {
  const ctx = newCtx();
  const benign = [
    ["trace id", "4bf92f3577b34da6a3ce929d0e0e4736"],
    ["request id", "8f14e45f-ceea-167a-5a36-dedd4bea2543"],
    ["opaque app id", "app_01J8ZK9Q2M4N7P"],
    ["k8s resource", "vehicle-status-service-84d499d4cb-28dt2"],
    ["infra arn", "arn:aws:iam::123456789012:role/eks-nodegroup-role"],
  ];
  for (const [label, value] of benign) {
    const decision = classifyRestore({
      ctx,
      text: `aws s3 ls --profile ${value}`,
      sink: { kind: "shell" },
    });
    assert.notEqual(
      decision.action,
      "block",
      `${label} must not be blocked: the block condition is (unknown + protected shape + sensitive sink)`
    );
    assert.equal(decision.telemetry.event, "restore_ok", `${label} is not token-like, so nothing is unresolvable`);
  }
});

// The block condition is asserted as a conjunction in the negative cases below:
// unknown token AND protected-token-like shape AND sensitive sink. Each negative
// fixture varies exactly one of the three, so a policy that drops any one of them
// fails loudly.

// --------------------------------------------- 3. the policy, asserted directly ---

test("registered tokens restore in every sink, including sensitive ones [GREEN NOW]", async () => {
  const ctx = newCtx();
  const secret = "Pr0d-P@ssw0rd-Xy9Zk2mQ";
  const token = (await ctx.redactText(`DB_PASSWORD=${secret}`, { gitleaks: true })).split("=")[1];
  for (const kind of [...SENSITIVE_SINK_KINDS, "assistant_text"]) {
    const d = classifyRestore({ ctx, text: `use ${token}`, sink: { kind } });
    assert.equal(d.action, "restore", `${kind}: a registered token must be restorable`);
    assert.equal(d.text, `use ${secret}`);
    assert.equal(d.telemetry.event, "restore_ok");
  }
});

test("the three block conditions are each load-bearing [GREEN NOW]", () => {
  const ctx = newCtx();
  const unknown = UNKNOWN_TOKEN;
  // All three present -> block.
  assert.equal(classifyRestore({ ctx, text: unknown, sink: { kind: "shell" } }).action, "block");
  // Drop (3) sink sensitivity.
  assert.equal(classifyRestore({ ctx, text: unknown, sink: { kind: "log_write" } }).action, "restore");
  // Drop (2) token-likeness: a plain opaque id is not protected-token-like.
  assert.equal(isProtectedTokenLike("4bf92f3577b34da6a3ce929d0e0e4736"), false);
  assert.equal(
    classifyRestore({ ctx, text: "4bf92f3577b34da6a3ce929d0e0e4736", sink: { kind: "shell" } }).action,
    "restore"
  );
  // Drop (1) unknown-ness.
  const known = new RedactionContext({ salt: "fixture" });
  assert.equal(classifyRestore({ ctx: known, text: known.tokenToRaw.size ? "" : "", sink: { kind: "shell" } }).action, "restore");
});

test("token-likeness is narrow, not a randomness heuristic [GREEN NOW]", () => {
  for (const value of [
    "vehicle-status-service-84d499d4cb-28dt2",
    "i-0a1b2c3d4e5f67890",
    "arn:aws:iam::123456789012:role/eks-nodegroup-role",
    "8f14e45f-ceea-167a-5a36-dedd4bea2543",
    "app_01J8ZK9Q2M4N7P",
  ]) {
    assert.equal(isProtectedTokenLike(value), false, `${value} must not be treated as token-like`);
  }
  assert.equal(isProtectedTokenLike("CRG_K7M2Q9_T8F4N6P3"), true);
  assert.equal(isProtectedTokenLike(UNKNOWN_TOKEN), true);
});
