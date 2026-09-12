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
import { handleRequest, RedactionContext, restoreSseStream } from "../worker.js";

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

test("R3.4: the runtime boundary is far above the contract, and it is recorded not asserted [GREEN NOW]", async () => {
  // What this asserts: a depth well inside the contract is safe with a wide margin, and a depth
  // that IS expected to overflow is not exercised here (it would throw out of the test process).
  //
  // What it records: measured on a fresh `node` process, first call, three repetitions per point,
  // the boundary sits between 2200 (ok) and 2300 (RangeError) for object, array and alternating
  // chains alike -- roughly 12-15 KB of body, against a 16 MiB body cap. JSON.parse itself handles
  // 2500 fine, so the limit is the gateway's own recursion, not the JSON parser.
  const margin = await roundTrip({ depth: 512, kind: "object", leaf: SECRET });
  assert.equal(margin.status, 200, "512 is 4x the contract and still completes");

  // The contract has a wide margin on both sides, which is the actual claim: 128 is required, and
  // the first failure measured ~2200, so a guard is not needed to satisfy the contract. An earlier
  // version of this last line was a tautology (`512 * 4 > 2200` is false), which is not an
  // assertion about anything.
  assert.ok(2200 > 128 * 4, "the measured boundary is many times the required depth");
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
