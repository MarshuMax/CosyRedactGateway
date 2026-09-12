// G0.1 -- Responses SSE operand routing, and ownership closure in the delivery policy.
//
// Two gaps left by G0:
//
// 1. The Responses SSE path labelled every string `delta` as assistant_text, so
//    `response.function_call_arguments.delta` and its siblings were resolved like prose.
//    "The field is called delta" is not a statement about the sink; the EVENT TYPE and the
//    FIELD PATH together are.
//
// 2. G0 dropped ForeignTokenRegistry from the live policy path: classifyRestore() still
//    accepted the argument, applySinkPolicy() never consulted it, and handleRequest() had
//    no plumbing at all. The three-way ownership split was reachable only from unit tests,
//    which is exactly the "helper correct, production unwired" shape G0 existed to fix.
//
// Assertion tags:
//   [GREEN NOW]  already true
//   [RED]        specifies the target

import test from "node:test";
import assert from "node:assert/strict";
import { handleRequest, ForeignTokenRegistry } from "../worker.js";

const SECRET = "Pr0d-P@ssw0rd-Xy9Zk2mQ";
const ACME = { name: "acme", pattern: /(?<![A-Za-z0-9_])ACME_[A-Z0-9_]{4,}(?![A-Za-z0-9_])/ };

function responsesRequest() {
  return new Request("https://proxy.example/G$https://api.example/v1/responses", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "g", stream: true, input: `PASSWORD=${SECRET}` }),
  });
}

/** Round trip where the SSE events are built from the token the gateway actually minted. */
async function sseTrip(buildEvents, options = {}) {
  let token = null;
  const fetchImpl = async (_u, init) => {
    token = (JSON.stringify(JSON.parse(init.body)).match(/CRG_[A-Z0-9]+_[A-Z0-9]+/) || [])[0] || null;
    const events = buildEvents(token);
    const body = events.map((e) => `event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join("") + "data: [DONE]\n\n";
    return new Response(body, { headers: { "content-type": "text/event-stream" } });
  };
  const response = await handleRequest(responsesRequest(), {}, { fetchImpl, salt: "fixed", ...options });
  return { out: await response.text(), token };
}

// ------------------------------------------- 1. Responses SSE operand routing ----

test("Responses output_text.delta restores an own token [RED]", async () => {
  const { out, token } = await sseTrip((t) => [{ type: "response.output_text.delta", delta: `the value is ${t}` }]);
  assert.ok(token, "fixture must mint a token");
  assert.ok(out.includes(SECRET), "assistant text deltas restore");
});

test("Responses tool-operand DELTA events must not be resolved [RED]", async () => {
  const events = [
    ["response.function_call_arguments.delta", "delta"],
    ["response.mcp_call_arguments.delta", "delta"],
    ["response.custom_tool_call_input.delta", "delta"],
  ];
  for (const [type, field] of events) {
    const { out, token } = await sseTrip((t) => [{ type, [field]: `{"cmd":"curl x?y=${t}"}` }]);
    assert.equal(out.includes(SECRET), false, `${type}: the operand must not be resolved`);
    assert.ok(out.includes(token), `${type}: the token is what gets delivered`);
  }
});

test("Responses tool-operand DONE events must not be resolved [RED]", async () => {
  const events = [
    ["response.function_call_arguments.done", "arguments"],
    ["response.mcp_call_arguments.done", "arguments"],
    ["response.custom_tool_call_input.done", "input"],
  ];
  for (const [type, field] of events) {
    const { out, token } = await sseTrip((t) => [{ type, [field]: `{"cmd":"curl x?y=${t}"}` }]);
    assert.equal(out.includes(SECRET), false, `${type}: the operand must not be resolved`);
    assert.ok(out.includes(token), `${type}: the token is what gets delivered`);
  }
});

test("an unrecognised delta event does not inherit RESTORE from its field name [RED]", async () => {
  // The default for an unknown event has to be the conservative one: a field called
  // `delta` says nothing about where the string is going.
  const { out, token } = await sseTrip((t) => [{ type: "response.some.future.thing.delta", delta: `value ${t}` }]);
  assert.equal(out.includes(SECRET), false, "an unknown event must not be resolved by default");
  assert.ok(out.includes(token), "the token is delivered unchanged");
});

// --------------------------------------------- 2. ownership closure end to end ----

test("a registered foreign token is preserved in assistant text [RED]", async () => {
  const { out } = await sseTrip(
    () => [{ type: "response.output_text.delta", delta: "value ACME_ABCDEF_0001" }],
    { foreignRegistry: new ForeignTokenRegistry([ACME]) }
  );
  assert.ok(out.includes("ACME_ABCDEF_0001"), "this layer does not own it, so it is not rewritten");
  assert.equal(out.includes(SECRET), false);
});

test("a registered foreign token in a tool operand is refused, not delivered [RED]", async () => {
  // The outer DLP is exactly where the plaintext would be substituted, and this layer
  // cannot resolve the token itself, so forwarding it is not honest either.
  const { out } = await sseTrip(
    () => [{ type: "response.function_call_arguments.delta", delta: "curl x?y=ACME_ABCDEF_0001" }],
    { foreignRegistry: new ForeignTokenRegistry([ACME]) }
  );
  assert.equal(out.includes("ACME_ABCDEF_0001"), false, "not delivered as an operand");
  assert.match(out, /blocked/i, "and the refusal is visible");
});

test("a registered foreign token is preserved under a trusted broker too [RED]", async () => {
  // Trusted does not mean re-mapped: this layer holds no mapping for a foreign token, so
  // the most it can do is hand it over unchanged.
  const { out } = await sseTrip(
    () => [{ type: "response.output_text.delta", delta: "ref ACME_ABCDEF_0001" }],
    {
      foreignRegistry: new ForeignTokenRegistry([ACME]),
      trustedSinks: ["acme_broker"],
    }
  );
  assert.ok(out.includes("ACME_ABCDEF_0001"));
  assert.equal(out.includes(SECRET), false);
});

test("an UNREGISTERED token-shaped value in a tool operand is refused [RED]", async () => {
  // The three-way split has to hold end to end: only registered ownership earns
  // pass-through, and an unclaimed token-shaped string in an operand is unresolvable.
  const { out } = await sseTrip(() => [{ type: "response.function_call_arguments.delta", delta: "curl x?y=CRG_AAAA_AAAA" }]);
  assert.match(out, /blocked/i, "an unowned operand cannot be delivered");
});
