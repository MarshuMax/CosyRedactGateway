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
import { RedactionContext, restoreJson } from "../worker.js";

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
  assert.equal(decision.action, "preserve", "assistant prose must not block on an unknown token");
  assert.equal(decision.telemetry.event, "restore_miss");
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
  assert.equal(decision.action, "preserve", "a benign sink must not block on shape alone");
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
    assert.equal(
      decision.action,
      "preserve",
      `${label} must not be blocked: the block condition is (unknown + protected shape + sensitive sink)`
    );
  }
});

// ------------------------------------------------------- target interface ---
// Placeholder for the sink policy that does not exist yet. Kept local so that
// the failure message points at the missing capability instead of at a module
// resolution error.
function classifyRestore({ ctx, text, sink }) {
  if (typeof ctx.classifyRestore === "function") return ctx.classifyRestore({ text, sink });
  throw new Error(
    "RED: restore-miss sink policy is not implemented (DESIGN-v2.md item 8: Tool Sink Policy)"
  );
}
