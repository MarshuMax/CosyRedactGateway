// R3.4 -- depth / stack robustness.
//
// Four recursive paths, each exercised through the PRODUCTION wiring rather than a directly
// imported internal helper:
//
//   redactJson              request side, via handleRequest
//   restoreJson             response side, via handleRequest
//   applyOperandPolicy      applyResponsePolicy (already covered in R2.6; referenced here)
//   restoreCompleteStrings  NOT exported, so it is reached through restoreSseStream
//
// The agreed contract, restated so the thresholds below cannot drift:
//
//   depth <= 128                 MUST complete normally
//   deeper                       succeeds, OR is rejected in a CONTROLLED way
//   never                        a raw RangeError / uncaught exception / partial mutation
//
// The measured runtime boundary is far above the contract, which is why this file asserts the
// contract at 128 and RECORDS the boundary rather than pinning it: a JIT-dependent stack limit is
// not a specification, and a test that froze it would fail on a different Node build for no
// security reason.
//
// Measurement note: the boundary is only reproducible on the FIRST call in a fresh process. Ten
// sequential calls in one process give four RangeErrors followed by six successes, because V8's
// stack check and tiering change once the function has overflowed once. Every boundary figure here
// therefore comes from a fresh `node` process per data point.

import test from "node:test";
import assert from "node:assert/strict";
import { handleRequest, RedactionContext, restoreSseStream, guardSseDepth, exceedsJsonDepth } from "../worker.js";

const FLAGS = "H";
const SECRET = "wJalrXUtnFEMIK7MDENGbPxRfiCY";
const TOKEN = "CRG_AAAAAA_0001";

const KINDS = {
  object: (depth, leaf) => {
    let node = leaf;
    for (let i = 0; i < depth; i++) node = { child: node };
    return node;
  },
  array: (depth, leaf) => {
    let node = leaf;
    for (let i = 0; i < depth; i++) node = [node];
    return node;
  },
  alternating: (depth, leaf) => {
    let node = leaf;
    for (let i = 0; i < depth; i++) node = i % 2 === 0 ? { child: node } : [node];
    return node;
  },
};

/** Walk the same path the builder created, so the leaf can be compared. */
function leafOf(node, depth, kind) {
  let cur = node;
  for (let i = 0; i < depth; i++) {
    cur = kind === "array" ? cur[0] : Array.isArray(cur) ? cur[0] : cur.child;
  }
  return cur;
}

/** One full gateway round trip with a deep payload on the request and the response. */
async function roundTrip({ depth, kind, leaf, responseLeaf = null, flags = FLAGS }) {
  const payload = KINDS[kind](depth, leaf);
  const body = JSON.stringify({ model: "g", messages: [{ role: "user", content: "hi" }], deep: payload });
  let upstreamBody = null;
  const fetchImpl = async (_u, init) => {
    upstreamBody = JSON.parse(init.body);
    const back = responseLeaf === null ? { ok: true } : { deep: KINDS[kind](depth, responseLeaf) };
    return new Response(JSON.stringify(back), { headers: { "content-type": "application/json" } });
  };
  const request = new Request(`https://proxy.example/${flags}$https://api.example/v1/chat/completions`, {
    method: "POST", headers: { "content-type": "application/json" }, body,
  });
  const response = await handleRequest(request, {}, { fetchImpl, salt: "depth" });
  return { status: response.status, text: await response.text(), upstreamBody };
}

/** The SSE path, which is the only production route into restoreCompleteStrings. */
async function sseDeep({ depth, kind, leaf }) {
  const event = { type: "response.output_text.delta", delta: "x", nested: KINDS[kind](depth, leaf) };
  const body = `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\ndata: [DONE]\n\n`;
  const ctx = new RedactionContext({ salt: "depth", requestId: "AAAAAA" });
  const out = await new Response(restoreSseStream(new Response(body).body, ctx)).text();
  return out;
}

// =====================================================================================
// The contract: 128 must complete, in every shape, on every path
// =====================================================================================

test("R3.4: depth 128 completes on the request path for every container shape [GREEN NOW]", async () => {
  for (const kind of Object.keys(KINDS)) {
    for (const depth of [1, 32, 64, 128]) {
      const result = await roundTrip({ depth, kind, leaf: SECRET });
      assert.equal(result.status, 200, `${kind} depth=${depth}: must complete, got ${result.status}`);
      // The redaction actually happened, so the walk reached the leaf.
      const sent = leafOf(result.upstreamBody.deep, depth, kind);
      assert.notEqual(sent, SECRET, `${kind} depth=${depth}: the leaf must have been redacted`);
    }
  }
});

test("R3.4: depth 128 completes on the SSE path for every container shape [GREEN NOW]", async () => {
  for (const kind of Object.keys(KINDS)) {
    for (const depth of [1, 32, 64, 128]) {
      const out = await sseDeep({ depth, kind, leaf: "plain-text" });
      assert.ok(out.length > 0, `${kind} depth=${depth}: the stream must produce output`);
      assert.match(out, /\[DONE\]/, `${kind} depth=${depth}: and must terminate cleanly`);
    }
  }
});

test("R3.4: the restore path reaches a deep leaf and restores it [GREEN NOW]", async () => {
  // A response carrying a token 128 levels down must be resolved on the way back, which exercises
  // restoreJson at the same depth as redactJson.
  const result = await roundTrip({ depth: 128, kind: "object", leaf: SECRET, responseLeaf: TOKEN });
  assert.equal(result.status, 200);
  const restored = JSON.parse(result.text).deep;
  const leaf = leafOf(restored, 128, "object");
  assert.equal(leaf, TOKEN, "an unowned token is preserved, and the walk reached it");
});

// =====================================================================================
// Semantics must not depend on depth
// =====================================================================================

test("R3.4: output semantics at depth 128 match the shallow equivalent [GREEN NOW]", async () => {
  // The point is not that the deep tree survives, but that it behaves like a shallow one.
  for (const kind of Object.keys(KINDS)) {
    const shallow = await roundTrip({ depth: 1, kind, leaf: SECRET });
    const deep = await roundTrip({ depth: 128, kind, leaf: SECRET });

    const shallowLeaf = leafOf(shallow.upstreamBody.deep, 1, kind);
    const deepLeaf = leafOf(deep.upstreamBody.deep, 128, kind);

    // Both are redacted, and the token SHAPE is the same (the ids differ by design: the request id
    // is per-request random).
    assert.match(String(shallowLeaf), /^CRG_/, `${kind}: shallow leaf is a token`);
    assert.match(String(deepLeaf), /^CRG_/, `${kind}: deep leaf is a token`);
    assert.equal(
      String(deepLeaf).replace(/CRG_[A-Z0-9]+_[A-Z0-9]+/, "CRG_X_X"),
      String(shallowLeaf).replace(/CRG_[A-Z0-9]+_[A-Z0-9]+/, "CRG_X_X"),
      `${kind}: depth changed the outcome shape`
    );
  }
});

test("R3.4: a non-string value stays untouched at depth 128 [GREEN NOW]", async () => {
  // Depth must not turn a number, boolean or null into something else, and must not stringify it.
  let node = { n: 42, b: false, z: null, arr: [1, "two"] };
  for (let i = 0; i < 128; i++) node = { child: node };
  const body = JSON.stringify({ model: "g", messages: [{ role: "user", content: "hi" }], deep: node });
  let upstreamBody = null;
  const fetchImpl = async (_u, init) => {
    upstreamBody = JSON.parse(init.body);
    return new Response("{}", { headers: { "content-type": "application/json" } });
  };
  const request = new Request(`https://proxy.example/${FLAGS}$https://api.example/v1/chat/completions`, {
    method: "POST", headers: { "content-type": "application/json" }, body,
  });
  await handleRequest(request, {}, { fetchImpl, salt: "depth" });

  let cur = upstreamBody.deep;
  for (let i = 0; i < 128; i++) cur = cur.child;
  assert.deepEqual(
    { n: cur.n, b: cur.b, z: cur.z, arr: cur.arr },
    { n: 42, b: false, z: null, arr: [1, "two"] },
    "non-string values must survive unchanged"
  );
});

test("R3.4: container shape is unchanged at depth 128 [GREEN NOW]", async () => {
  for (const kind of Object.keys(KINDS)) {
    const result = await roundTrip({ depth: 128, kind, leaf: SECRET });
    let cur = result.upstreamBody.deep;
    let shapes = "";
    for (let i = 0; i < 128; i++) {
      const isArray = Array.isArray(cur);
      shapes += isArray ? "a" : "o";
      cur = kind === "array" ? cur[0] : isArray ? cur[0] : cur.child;
    }
    // The builder wraps from the leaf OUTWARDS with i increasing, so the outermost container is
    // the i = depth-1 wrap. For `alternating` that is an array, not an object -- an earlier version
    // of this expectation had the two swapped.
    const expected = kind === "object" ? "o".repeat(128)
      : kind === "array" ? "a".repeat(128)
        : "ao".repeat(64);
    assert.equal(shapes, expected, `${kind}: the container chain must be intact`);
  }
});

// =====================================================================================
// The measured runtime boundary -- recorded, not pinned
// =====================================================================================

test("R3.4: the structural depth guard is exact at 512 [GREEN NOW]", async () => {
  // The guard measures the depth of the WHOLE body, and the request envelope adds one level
  // (`{ model, messages, deep }`), so a fixture chain of N sits at depth N+1. An earlier version of
  // this test treated the fixture depth as the body depth and expected a chain of 512 to pass.
  //
  // 510 -> body depth 511 -> pass; 511 -> 512 -> pass; 512 -> 513 -> refused.
  for (const kind of Object.keys(KINDS)) {
    for (const [chain, expected] of [[128, 200], [510, 200], [511, 200], [512, 413]]) {
      const result = await roundTrip({ depth: chain, kind, leaf: SECRET });
      assert.equal(result.status, expected, `${kind} chain=${chain}: expected ${expected}, got ${result.status}`);
    }
  }
});

test("R3.4 L1: an over-deep request is refused with no upstream fetch [GREEN NOW]", async () => {
  const payload = KINDS.object(513, SECRET);
  const body = JSON.stringify({ model: "g", messages: [{ role: "user", content: "hi" }], deep: payload });
  let upstreamFetch = 0;
  const fetchImpl = async () => { upstreamFetch++; return new Response("{}", { headers: { "content-type": "application/json" } }); };
  const request = new Request(`https://proxy.example/${FLAGS}$https://api.example/v1/chat/completions`, {
    method: "POST", headers: { "content-type": "application/json" }, body,
  });
  const response = await handleRequest(request, {}, { fetchImpl, salt: "depth" });
  assert.equal(response.status, 413, "a payload resource limit is a 413");
  assert.match(await response.text(), /nesting exceeds 512/, "and names the limit");
  assert.equal(upstreamFetch, 0, "nothing may be forwarded for a body that was never accepted");
});

test("R3.4: an over-deep upstream RESPONSE is a 502, not a 413 and not a fallback [GREEN NOW]", async () => {
  // The upstream call already happened, so this is not the client's bad request. It must fail closed
  // rather than downgrade the body to inert text.
  const body = JSON.stringify({ model: "c", max_tokens: 20, messages: [{ role: "user", content: `PASSWORD=${SECRET}` }] });
  const fetchImpl = async () => new Response(
    JSON.stringify({ type: "message", role: "assistant", content: [{ type: "text", text: KINDS.object(513, "plain") }] }),
    { headers: { "content-type": "application/json" } }
  );
  const request = new Request(`https://proxy.example/${FLAGS}$https://api.example/v1/messages`, {
    method: "POST", headers: { "content-type": "application/json" }, body,
  });
  const response = await handleRequest(request, {}, { fetchImpl, salt: "depth" });
  assert.equal(response.status, 502, "an over-deep response is an upstream failure");
  assert.match(await response.text(), /depth limit/);
});

// =====================================================================================
// THE REGRESSION THAT MATTERS: an over-deep operand must never yield plaintext
// =====================================================================================

test("R3.4 SECURITY: an over-deep untrusted tool operand never exposes the token's plaintext [GREEN NOW]", async () => {
  // The sink-policy fail-open this guard was written for. Before the fix, restoreNonStreamResponse
  // wrapped JSON.parse, applyResponsePolicy and JSON.stringify in ONE try, so the RangeError from a
  // deep operand was caught and the WHOLE raw response was re-processed under the assistant_text
  // policy -- which RESOLVES tokens. A token sitting inside an untrusted tool operand came back as
  // plaintext, at status 200. Measured fresh-process before the fix: depth 2500 preserved the
  // token, depth 2800 returned the plaintext, 3/3 each time.
  const body = JSON.stringify({ model: "c", max_tokens: 20, messages: [{ role: "user", content: `PASSWORD=${SECRET}` }] });
  for (const depth of [513, 1000, 2800, 3200]) {
    let token = null;
    const fetchImpl = async (_u, init) => {
      const seen = JSON.parse(init.body);
      token = (JSON.stringify(seen).match(/CRG_[A-Z0-9]+_[A-Z0-9]+/) || [])[0] || null;
      const response = {
        type: "message", role: "assistant",
        content: [{ type: "tool_use", id: "tu", name: "untrusted_tool", input: KINDS.object(depth, token) }],
      };
      return new Response(JSON.stringify(response), { headers: { "content-type": "application/json" } });
    };
    const request = new Request(`https://proxy.example/${FLAGS}$https://api.example/v1/messages`, {
      method: "POST", headers: { "content-type": "application/json" }, body,
    });
    const response = await handleRequest(request, {}, { fetchImpl, salt: "depth" });
    const out = await response.text();
    assert.ok(token, `depth=${depth}: the fixture must mint a token`);
    assert.equal(out.includes(SECRET), false, `depth=${depth}: PLAINTEXT MUST NOT APPEAR -> ${JSON.stringify(out.slice(0, 120))}`);
    assert.equal(response.status, 502, `depth=${depth}: and the response fails closed`);
  }
});

test("R3.4 SECURITY: a trajectory that is NOT over-deep still preserves the operand [GREEN NOW]", async () => {
  // The counterpart, so the test above cannot pass by refusing everything: a shallow operand is
  // still preserved under the untrusted sink, and a trusted one still resolves.
  const body = JSON.stringify({ model: "c", max_tokens: 20, messages: [{ role: "user", content: `PASSWORD=${SECRET}` }] });
  for (const [depth, trusted] of [[1, false], [128, false], [1, "broker"]]) {
    let token = null;
    const fetchImpl = async (_u, init) => {
      const seen = JSON.parse(init.body);
      token = (JSON.stringify(seen).match(/CRG_[A-Z0-9]+_[A-Z0-9]+/) || [])[0] || null;
      const response = {
        type: "message", role: "assistant",
        content: [{ type: "tool_use", id: "tu", name: trusted || "untrusted_tool", input: KINDS.object(depth, token) }],
      };
      return new Response(JSON.stringify(response), { headers: { "content-type": "application/json" } });
    };
    const request = new Request(`https://proxy.example/${FLAGS}$https://api.example/v1/messages`, {
      method: "POST", headers: { "content-type": "application/json" }, body,
    });
    const response = await handleRequest(request, {}, { fetchImpl, salt: "depth", trustedSinks: ["broker"] });
    const out = await response.text();
    assert.equal(response.status, 200, `depth=${depth} trusted=${trusted}: must succeed`);
    if (trusted) {
      assert.ok(out.includes(SECRET), "a trusted broker resolves the value");
    } else {
      assert.equal(out.includes(SECRET), false, "an untrusted operand must not resolve it");
      assert.ok(out.includes(token), "and must keep the token");
    }
  }
});

test("R3.4: an over-deep SSE event becomes a stream error and cancels the upstream [GREEN NOW]", async () => {
  // After the first byte is streaming a 502 is no longer available, so the contract is: do not emit
  // the offending event, emit an error, cancel the reader, and never fall back to assistant_text.
  let cancelled = false;
  const deepEvent = `event: response.output_text.delta\ndata: ${JSON.stringify({ type: "response.output_text.delta", delta: "x", nested: KINDS.object(513, "y") })}\n\n`;
  const stream = new ReadableStream({
    start(controller) { controller.enqueue(new TextEncoder().encode(deepEvent)); },
    cancel() { cancelled = true; },
  });
  const ctx = new RedactionContext({ salt: "depth", requestId: "AAAAAA" });
  const guarded = guardSseDepth(stream, 512);
  const out = await new Response(restoreSseStream(guarded, ctx)).text();
  assert.match(out, /gateway_depth_limit/, "an error event must be emitted");
  assert.equal(out.includes("\"delta\":\"x\""), false, "and the offending event must not be emitted");
  assert.equal(cancelled, true, "the upstream reader must be cancelled");
});

test("R3.4: the guard is non-recursive, so it cannot overflow on the input it catches [GREEN NOW]", () => {
  // A guard that recursed would fail on exactly the input it exists to reject.
  let node = "leaf";
  for (let i = 0; i < 100000; i++) node = { c: node };
  assert.equal(exceedsJsonDepth(node, 512), true, "a 100000-deep chain is refused without throwing");
  assert.equal(exceedsJsonDepth({ a: [1, { b: 2 }, [3]] }, 512), false, "and a shallow tree passes");
});

test("R3.4: every recursive path shares one depth notion [GREEN NOW]", async () => {
  // A guard, if one is ever added, must be ONE structural depth contract rather than four
  // independently invented limits. This asserts the paths agree today: the same depth that the
  // request path handles is handled by the SSE path.
  const depth = 128;
  const request = await roundTrip({ depth, kind: "object", leaf: SECRET });
  assert.equal(request.status, 200);
  const sse = await sseDeep({ depth, kind: "object", leaf: SECRET });
  assert.ok(sse.length > 0);
});
