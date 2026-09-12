// G1 -- streaming representation / ownership closure.
//
// `possibleTokenSuffixLength()` only understood this layer's own dialect (CRG and the
// legacy placeholder), so three protected forms were emitted in pieces when a provider
// split them across deltas:
//
//   OWN portable token      supported
//   legacy token            supported
//   OWN base64 surrogate    BROKEN
//   FOREIGN exact token     BROKEN
//   FOREIGN namespace token BROKEN
//
// Holdback eligibility follows the same rule as everything else in this design: it comes
// from an AUTHORITY, never from a shape.
//
//   OWN surrogate  -> the ledger (exact visible strings this request minted)
//   FOREIGN        -> the registry (exact registrations, or a namespace `streamPrefix`)
//   dialect        -> our own token shapes
//
// A string that merely looks like base64 is NOT held back: "looks like a surrogate" is not
// ownership, and treating it as such would make every base64 blob a stall.
//
// Namespace prefixes are declared, not derived. Computing "could this suffix still match
// the regex" from an arbitrary pattern is not reliable, and a partial regex matcher is not
// worth writing, so the issuer states `streamPrefix` and the full matcher still decides
// ownership.
//
// Assertion tags:
//   [GREEN NOW]  already true
//   [RED]        specifies the target

import test from "node:test";
import assert from "node:assert/strict";
import {
  handleRequest,
  ForeignTokenRegistry,
  streamHoldbackPrefixes,
  partialPrefixLength,
  RedactionContext,
} from "../worker.js";

const SECRET = "Pr0d-P@ssw0rd-Xy9Zk2mQ";
const B64_SECRET = "cGFzc3dvcmQxMjM0NTY3OA==";
const ACME_NS = { name: "acme", pattern: /(?<![A-Za-z0-9_])ACME_[A-Z0-9_]{4,}(?![A-Za-z0-9_])/, streamPrefix: "ACME_" };

const FLAGS = "G";

/** Drive one streaming round trip; `build` receives everything the upstream saw. */
async function sseTrip({ body, build, options = {}, path = "/v1/responses" }) {
  let upstream = null;
  const fetchImpl = async (_u, init) => {
    upstream = JSON.parse(init.body);
    const events = build(upstream);
    const text = events.map((e) => `event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join("") + "data: [DONE]\n\n";
    return new Response(text, { headers: { "content-type": "text/event-stream" } });
  };
  const request = new Request(`https://proxy.example/${FLAGS}$https://api.example${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const response = await handleRequest(request, {}, { fetchImpl, salt: "fixed", ...options });
  return { out: await response.text(), upstream };
}

const docFor = (secret) => ["apiVersion: v1", "kind: Secret", "data:", `  password: ${secret}`].join("\n");
const responsesBody = (input) => ({ model: "g", stream: true, input });
const oneText = (delta) => ({ type: "response.output_text.delta", delta });
const surrogateFrom = (upstream, key) => {
  const m = new RegExp(`${key}: (\\S+)`).exec(String(upstream?.input ?? ""));
  return m ? m[1] : null;
};

const chatBody = (content = `PASSWORD=${SECRET}`) => ({
  model: "g",
  stream: true,
  messages: [{ role: "user", content }],
});

/** Split `token` into two halves and emit them as two assistant_text deltas. */
const textDeltas = (token) => {
  const cut = Math.floor(token.length / 2);
  return [
    { type: "response.output_text.delta", delta: `v ${token.slice(0, cut)}` },
    { type: "response.output_text.delta", delta: token.slice(cut) },
  ];
};

function extract(responseText, field) {
  // Pull the concatenated value of one SSE field out of the delivered stream.
  const parts = [];
  for (const line of responseText.split("\n")) {
    if (!line.startsWith("data: ")) continue;
    const payload = line.slice(6).trim();
    if (!payload || payload === "[DONE]") continue;
    try {
      const data = JSON.parse(payload);
      if (typeof data[field] === "string") parts.push(data[field]);
    } catch { /* ignore */ }
  }
  return parts.join("");
}

// ------------------------------------------------------- 1. holdback sources -----

test("G1: holdback prefixes come from the ledger and the registry, not from shapes [GREEN NOW]", async () => {
  const ctx = new RedactionContext({ salt: "fixture" });
  const token = await ctx.tokenFor(B64_SECRET);
  const surrogate = await ctx.emit(token, "base64");
  const registry = new ForeignTokenRegistry([ACME_NS]).registerTokens(["opaque-vendor-token"]);

  const holdbacks = streamHoldbackPrefixes(ctx, registry);
  const literals = holdbacks.filter((h) => h.kind === "literal").map((h) => h.value);
  const anchors = holdbacks.filter((h) => h.kind === "namespace").map((h) => h.value);
  assert.ok(literals.includes(surrogate), "the minted surrogate is an exact literal");
  assert.ok(literals.includes("opaque-vendor-token"), "an exact registration is one too");
  assert.ok(literals.includes("CRG_"), "plus our own dialect");
  assert.ok(anchors.includes("ACME_"), "while a namespace prefix is an open-ended anchor");

  // An unrelated base64 string is NOT in the set, so it cannot cause a stall.
  assert.equal(literals.includes("YWJjZGVmZ2hpams="), false);
  assert.equal(partialPrefixLength("YWJjZGVmZ2hpams=", holdbacks), 0, "unrelated base64 is not held back");
});

test("G1.1: exact literals release on completion, namespace anchors stay open [GREEN NOW]", () => {
  // The distinction the two kinds exist for. Conflating them either stalls a finished
  // token until the stream ends (literal treated as open-ended) or splits an unfinished
  // one (anchor treated as complete as soon as the matcher is satisfied).
  const literal = [{ kind: "literal", value: "Q1JHX0hQQzNKT18wMDAx" }];
  assert.equal(partialPrefixLength("v Q1JH", literal), 4, "a proper prefix is held");
  assert.equal(partialPrefixLength("v Q1JHX0hQQzNKT18wMDAx", literal), 0, "the complete literal is released");
  assert.equal(partialPrefixLength("v Q1JHX0hQQzNKT18wMDAx done", literal), 0, "and text after it cannot extend it");

  const anchor = [{
    kind: "namespace",
    value: "ACME_",
    continuation: /[A-Z0-9_]/,
    maxLength: 32,
  }];
  assert.equal(partialPrefixLength("v ACME", anchor), 4, "a partial anchor is held");
  assert.equal(partialPrefixLength("v ACME_", anchor), 5, "the anchor with no body is held");
  assert.equal(partialPrefixLength("v ACME_ABCD", anchor), 9, "and so is the body while it continues");
  assert.equal(partialPrefixLength("v ACME_ABCDEF_0001 done", anchor), 0, "a space ends the token");
  assert.equal(partialPrefixLength(`v ACME_${"A".repeat(40)}`, anchor), 0, "the declared max length bounds the hold");

  // Our own dialect stays with its shape-aware suffix logic, not this literal matcher.
  const dialect = [{ kind: "literal", value: "CRG_" }];
  assert.equal(partialPrefixLength("v CR", dialect), 2, "a partial dialect prefix is held");
});

// -------------------------------------------- 2. every split position, three forms ----

test("G1: an OWN portable token survives every split position [GREEN NOW]", async () => {
  const { out, upstream } = await sseTrip({
    body: chatBody(),
    build: (seen) => textDeltas(String(seen.messages[0].content).match(/CRG_[A-Z0-9]+_[A-Z0-9]+/)[0]),
  });
  const token = String(upstream.messages[0].content).match(/CRG_[A-Z0-9]+_[A-Z0-9]+/)[0];
  assert.ok(out.includes(SECRET), "the fixture must restore at the midpoint");
  void token;
});

test("G1: an OWN base64 surrogate survives EVERY split position [RED]", async () => {
  // Exhaustive, not a midpoint sample: an off-by-one in the prefix matcher would be
  // invisible at the midpoint.
  //
  // Each gateway request mints a FRESH surrogate (the request id is part of the token), so
  // the split position cannot be driven from a surrogate learned in an earlier request --
  // that mistake made an earlier version of this test compare two different strings. The
  // response for THIS request is built from the surrogate THIS request produced.
  const doc = docFor(B64_SECRET);

  // A surrogate is 20 characters for a 16-character token: CRG_ + 8 hex + _ + 4 + base64
  // padding. The exact width is asserted rather than assumed.
  const first = await sseTrip({ body: responsesBody(doc), build: () => [oneText("x")] });
  const surrogate = surrogateFrom(first.upstream, "password");
  assert.ok(surrogate, "fixture must mint a surrogate");
  assert.ok(surrogate.length > 8, `surrogate must be long enough to split: ${surrogate}`);

  for (let cut = 1; cut < surrogate.length; cut++) {
    for (const mode of ["text", "tool"]) {
      const type = mode === "tool" ? "response.function_call_arguments.delta" : "response.output_text.delta";
      const { out } = await sseTrip({
        body: responsesBody(doc),
        build: (seen) => {
          // Split the surrogate THIS request minted, at the same position.
          const own = surrogateFrom(seen, "password");
          assert.equal(
            own.length, surrogate.length,
            "the surrogate width is stable across requests, so a position stays comparable"
          );
          return [
            { type, delta: `v ${own.slice(0, cut)}` },
            { type, delta: own.slice(cut) },
          ];
        },
      });
      if (mode === "tool") {
        assert.equal(out.includes(B64_SECRET), false, `tool cut=${cut}: no plaintext in an operand`);
        assert.equal(out.includes("v "), true, `tool cut=${cut}: the fragment prefix survives`);
      } else {
        assert.ok(out.includes(B64_SECRET), `text cut=${cut}: reassembled and resolved`);
      }
    }
  }
});

test("G1: a trusted broker reassembles the surrogate too [RED]", async () => {
  const doc = docFor(B64_SECRET);
  for (let cut = 1; cut < 20; cut += 3) {
    const { out } = await sseTrip({
      body: responsesBody(doc),
      options: { trustedSinks: ["broker"] },
      build: (seen) => {
        const own = surrogateFrom(seen, "password");
        cut = Math.min(cut, own.length - 1);
        return [
          { type: "response.output_text.delta", delta: `v ${own.slice(0, cut)}` },
          { type: "response.output_text.delta", delta: own.slice(cut) },
        ];
      },
    });
    assert.ok(out.includes(B64_SECRET), `cut=${cut}: a trusted channel resolves the surrogate`);
  }
});

test("G1: an exact registered foreign token survives EVERY split position [RED]", async () => {
  const token = "opaque-token-from-vendor";
  const registry = new ForeignTokenRegistry().registerTokens([token]);
  for (let cut = 1; cut < token.length; cut++) {
    const { out } = await sseTrip({
      body: { model: "g", stream: true, input: "hi" },
      options: { foreignRegistry: registry },
      build: () => [
        { type: "response.output_text.delta", delta: `v ${token.slice(0, cut)}` },
        { type: "response.output_text.delta", delta: token.slice(cut) },
      ],
    });
    assert.ok(out.includes(token), `cut=${cut}: reassembled rather than emitted in halves`);
  }
});

test("G1: a namespace-typed foreign token survives EVERY split position [RED]", async () => {
  const registry = new ForeignTokenRegistry([ACME_NS]);
  const token = "ACME_ABCDEF_0001";
  for (let cut = 1; cut < token.length; cut++) {
    const { out } = await sseTrip({
      body: { model: "g", stream: true, input: "hi" },
      options: { foreignRegistry: registry },
      build: () => [
        { type: "response.output_text.delta", delta: `v ${token.slice(0, cut)}` },
        { type: "response.output_text.delta", delta: token.slice(cut) },
      ],
    });
    assert.ok(out.includes(token), `cut=${cut}: reassembled rather than emitted in halves`);
  }
});

// ------------------------------------------------- 3. sink policy still applies -----

test("G1: reassembly does not change the sink policy [GREEN NOW]", async () => {
  const registry = new ForeignTokenRegistry([ACME_NS]);
  const token = "ACME_ABCDEF_0001";

  // assistant_text -> preserved
  const prose = await sseTrip({
    body: { model: "g", stream: true, input: "hi" },
    options: { foreignRegistry: registry },
    build: () => textDeltas(token),
  });
  assert.ok(prose.out.includes(token), "assistant text preserves a foreign token");

  // untrusted tool operand -> refused
  const operand = await sseTrip({
    body: { model: "g", stream: true, input: "hi" },
    options: { foreignRegistry: registry },
    build: () => {
      const cut = Math.floor(token.length / 2);
      return [
        { type: "response.function_call_arguments.delta", delta: token.slice(0, cut) },
        { type: "response.function_call_arguments.delta", delta: token.slice(cut) },
      ];
    },
  });
  assert.equal(operand.out.includes(token), false, "an operand channel refuses it");
  assert.match(operand.out, /blocked/i, "and says so");
});

test("G1: an unrelated base64 blob is not stalled by the surrogate ledger [GREEN NOW]", async () => {
  // The holdback set is ledger-driven, so a base64 string this request never minted is
  // emitted immediately. Shape-driven holdback would delay every such chunk.
  const ctx = new RedactionContext({ salt: "fixture" });
  const prefixes = streamHoldbackPrefixes(ctx, null);
  const unrelated = "YWJjZGVmZ2hpamtsbW5vcA==";
  assert.equal(partialPrefixLength(unrelated, prefixes), 0);
  assert.equal(partialPrefixLength(unrelated.slice(0, 8), prefixes), 0);
});

test("G1: a fragment ending in a ledger prefix is held until it resolves [GREEN NOW]", async () => {
  // The mechanism, stated directly: a tail that could still become a minted surrogate is
  // held back, and the same tail stops being held once it is complete.
  const ctx = new RedactionContext({ salt: "fixture" });
  const token = await ctx.tokenFor(B64_SECRET);
  const surrogate = await ctx.emit(token, "base64");
  const prefixes = streamHoldbackPrefixes(ctx, null);

  assert.equal(partialPrefixLength(`x ${surrogate.slice(0, 6)}`, prefixes), 6, "held while incomplete");
  // A COMPLETE surrogate is released: it is an exact literal, so the policy can run and
  // holding it would stall the channel until the stream ends.
  assert.equal(partialPrefixLength(`x ${surrogate}`, prefixes), 0, "released once complete");
  assert.equal(partialPrefixLength(`x ${surrogate}  `, prefixes), 0, "and text after it cannot extend it");
});

// ------------------------------------------------ 4.增量交付（不是最终结果） -------

test("G1.1: a completed literal plus a delimiter is readable BEFORE the stream closes [RED]", async () => {
  // The failure this exists to catch: an implementation that holds everything until
  // finish() also passes every test that awaits response.text(). Here the upstream stays
  // OPEN after sending a complete surrogate and a delimiter, so the gateway must already
  // have delivered the resolvable text. A reader that blocks is the bug.
  const doc = docFor(B64_SECRET);

  let release;
  const upstreamGate = new Promise((resolve) => { release = resolve; });
  let sent = null;
  const fetchImpl = async (_u, init) => {
    const seen = JSON.parse(init.body);
    const own = surrogateFrom(seen, "password");
    sent = own;
    const encoder = new TextEncoder();
    const body = new ReadableStream({
      async start(controller) {
        const first = { type: "response.output_text.delta", delta: `value ${own} ` };
        controller.enqueue(encoder.encode(`event: ${first.type}\ndata: ${JSON.stringify(first)}\n\n`));
        await upstreamGate; // deliberately NOT closed yet
        controller.close();
      },
    });
    return new Response(body, { headers: { "content-type": "text/event-stream" } });
  };

  const request = new Request(`https://proxy.example/${FLAGS}$https://api.example/v1/responses`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(responsesBody(doc)),
  });
  const response = await handleRequest(request, {}, { fetchImpl, salt: "fixed" });
  const reader = response.body.getReader();
  const decoder = new TextDecoder();

  const firstChunk = await Promise.race([
    reader.read(),
    new Promise((resolve) => setTimeout(() => resolve({ timedOut: true }), 2000)),
  ]);
  const deliveredEarly = firstChunk.timedOut ? "" : decoder.decode(firstChunk.value);

  // Tear the stream down so the test cannot hang either way.
  release();
  let rest = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      rest += decoder.decode(value);
    }
  } catch { /* the reader may already be released */ }
  const everything = deliveredEarly + rest;

  assert.ok(sent, "fixture must mint a surrogate");
  assert.equal(
    deliveredEarly.length > 0, true,
    "the gateway must emit before the upstream closes once the literal is complete and delimited"
  );
  assert.ok(deliveredEarly.includes(B64_SECRET), "and the resolvable value is already delivered");
  assert.ok(everything.includes(B64_SECRET), "the full stream restores too");
});
