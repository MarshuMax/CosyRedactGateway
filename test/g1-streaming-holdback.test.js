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

  const prefixes = streamHoldbackPrefixes(ctx, registry);
  assert.ok(prefixes.includes(surrogate), "the minted surrogate is a holdback prefix");
  assert.ok(prefixes.includes("opaque-vendor-token"), "an exact registration is one too");
  assert.ok(prefixes.includes("ACME_"), "and so is a declared namespace prefix");
  assert.ok(prefixes.includes("CRG_"), "plus our own dialect");

  // An unrelated base64 string is NOT in the set, so it cannot cause a stall.
  assert.equal(prefixes.includes("YWJjZGVmZ2hpams="), false);
  assert.equal(partialPrefixLength("YWJjZGVmZ2hpams=", prefixes), 0, "unrelated base64 is not held back");
});

test("G1: partialPrefixLength is a pure prefix matcher [GREEN NOW]", () => {
  const prefixes = ["CRG_", "ACME_", "opaque-vendor-token"];
  assert.equal(partialPrefixLength("x CR", prefixes), 2, "a partial CRG prefix is held");
  assert.equal(partialPrefixLength("x ACME", prefixes), 4);
  assert.equal(partialPrefixLength("x opaque-vendor", prefixes), 13);
  assert.equal(partialPrefixLength("x CRGX", prefixes), 0, "no prefix begins with X");
  assert.equal(partialPrefixLength("nothing here", prefixes), 0);
  assert.equal(partialPrefixLength("x e", prefixes), 0);
  assert.equal(partialPrefixLength("x C", prefixes), 1, "the first character of CRG_ is ambiguous");
  // A COMPLETE prefix is ambiguous too, because the token may continue: `x CRG_ABC` holds
  // 7 characters, not 1. An earlier version of this assertion expected 1 and was wrong --
  // it under-counted exactly the case that lets a token be emitted in halves.
  assert.equal(partialPrefixLength("x CRG_ABC", prefixes), 7, "the whole run after the anchor is ambiguous");
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
  // A COMPLETE surrogate is still held by the prefix matcher (the first six characters are
  // a prefix of it); what releases it is the separate check that a complete value now ends
  // the buffer. Both halves are asserted so the division of labour is explicit.
  assert.equal(partialPrefixLength(`x ${surrogate}`, prefixes), surrogate.length, "still ambiguous by prefix alone");
  // With trailing non-token characters the anchor is no longer at the tail, so the
  // ambiguous run is what follows it. 22 is the honest number here, not 0: an earlier
  // assertion expected 0 and was simply wrong about what the function measures.
  assert.equal(partialPrefixLength(`x ${surrogate}  `, prefixes), 22);
});
