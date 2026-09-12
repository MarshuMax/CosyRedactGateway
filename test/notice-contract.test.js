// The runtime notice -- a SEMANTIC contract, not a frozen string.
//
// REDACT_NOTICE is injected into every forwarded request, so it is a promise the gateway
// makes to the model. A blanket promise that cannot be kept is worse than a vague one: the
// model writes a credential into a tool call expecting resolution, the sink policy preserves
// or blocks it, and the failure surfaces as an unexplained tool error.
//
// The notice previously said "placeholders you emit in text or tool calls are restored to the
// original secrets". G0 made that false. This file pins the SEMANTICS, so the wording can be
// improved freely while the security meaning cannot silently regress.
//
// Deliberately NOT a full-text freeze: a frozen string is brittle, and it would have to be
// rewritten for every improvement to the wording.

import test from "node:test";
import assert from "node:assert/strict";
import { REDACT_NOTICE } from "../worker.js";

const lower = REDACT_NOTICE.toLowerCase();

test("the notice calls CRG tokens opaque and requires exact preservation [GREEN NOW]", () => {
  assert.match(lower, /opaque/, "must say the tokens are opaque");
  assert.match(lower, /preserve them exactly|preserve exactly/, "must require exact preservation");
  assert.match(REDACT_NOTICE, /CRG_/, "and must name the token form so the model can recognise it");
});

test("the notice forbids decoding, modifying or inventing tokens [GREEN NOW]", () => {
  assert.match(lower, /do not decode/, "decoding is what would let a model re-derive a value");
  assert.match(lower, /modify/, "modification breaks the mapping");
  assert.match(lower, /invent/, "an invented token is indistinguishable from a real one to the model");
});

test("the notice states that the OUTCOME depends on the channel [GREEN NOW]", () => {
  // The load-bearing sentence. Restoration is not universal, and the notice has to say so.
  assert.match(lower, /depends on the output channel/, "the outcome is channel-dependent");
  assert.match(lower, /trust policy/, "and trust-dependent");
  assert.match(lower, /restored, preserved, or blocked/, "all three outcomes must be named");
});

test("the notice does NOT promise blanket restoration [GREEN NOW]", () => {
  // The exact regression this file exists for. Any phrasing that promises every placeholder
  // comes back as a secret is a false promise under the sink policy.
  const blanket = [
    /placeholders? you emit[^.]*restored/,
    /tool calls?[^.]*are restored/,
    /all (?:placeholders|tokens)[^.]*restored/,
    /tokens? (?:are|will be) restored/,
  ];
  for (const pattern of blanket) {
    assert.equal(pattern.test(lower), false, `the notice must not promise blanket restoration: ${pattern}`);
  }
});

test("the notice does not claim tool arguments can resolve tokens [GREEN NOW]", () => {
  assert.match(lower, /do not assume that tool arguments can resolve tokens/,
    "the one place a model most wants resolution is the one place it must not assume it");
});

test("the notice states the injection scope [GREEN NOW]", () => {
  assert.match(lower, /messages/, "messages are redacted");
  assert.match(lower, /tool inputs/, "tool inputs are redacted");
  assert.match(lower, /tool results/, "tool results are redacted");
});

test("the notice is a single line-safe block [GREEN NOW]", () => {
  // It is prefixed to payloads, so a stray newline would change the shape for a consumer that
  // treats the first line specially.
  assert.equal(REDACT_NOTICE.includes("\n"), false, "no embedded newline");
  assert.equal(REDACT_NOTICE, REDACT_NOTICE.trim(), "no leading or trailing whitespace");
  assert.ok(REDACT_NOTICE.length > 100, "and it is substantial enough to carry the contract");
});
