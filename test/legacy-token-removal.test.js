// Legacy dialect removal.
//
// The v1 `{{Redact:<64 hex>}}` format used to be recognised on input as a "protected shape",
// which was a standing bypass: the shape is trivially forgeable, so anyone could wrap a
// value in it and have detection skip that value entirely. The dual-dialect transition is
// over and the dialect is gone from the production code:
//
//   LEGACY_TOKEN_PREFIX / LEGACY_TOKEN_RE / LEGACY_TOKEN_LENGTH
//   legacyRedactToken()
//   the legacy entry in protectedTokenPatterns
//   the re-mint pass
//   the legacy restore branch
//   the legacy stream holdback
//   the legacy branch of REDACTED_TOKEN
//
// The regression that matters: a legacy-LOOKING payload gets no special treatment. Whether
// it is redacted is decided by the ordinary detectors, exactly like any other text.
//
// Assertion tags:
//   [GREEN NOW]  passes against the current tree

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  REDACTED_TOKEN,
  REDACTED_TOKEN_ONE,
  PROTECTED_TOKEN_LIKE_RE,
  TOKEN_PREFIX,
  isRedactedText,
  isProtectedTokenLike,
} from "../worker.js";

const ALL = { highEntropy: true, phone: true, secret: true, identity: true, bank: true, email: true, gitleaks: true };
const LEGACY_LOOKING = "{{Redact:" + "a1b2c3d4".repeat(8) + "}}";
const UNKNOWN_CRG = "CRG_AAAA_AAAA";

test("the legacy dialect is not exported at all [GREEN NOW]", async () => {
  const module = await import("../worker.js");
  for (const name of ["LEGACY_TOKEN_PREFIX", "LEGACY_TOKEN_RE", "LEGACY_TOKEN_LENGTH", "legacyRedactToken"]) {
    assert.equal(name in module, false, `${name} must be gone, not merely unused`);
  }
});

test("generation emits only the v2 dialect [GREEN NOW]", async () => {
  const ctx = new RedactionContext({ salt: "fixture" });
  const out = await ctx.redactText("PASSWORD=cGFzc3dvcmQxMjM0NTY3OA==", ALL);
  assert.ok(out.includes(TOKEN_PREFIX), "a v2 token is produced");
  assert.equal(out.includes("{{Redact:"), false, "and nothing resembling the old format");
});

test("a legacy-looking payload has no special status [GREEN NOW]", async () => {
  // The bypass this closes: `{{Redact:<64 hex>}}` used to be exempt from detection, so a
  // secret wrapped in it was forwarded untouched. It is now ordinary input.
  assert.equal(isProtectedTokenLike(LEGACY_LOOKING), false, "not token-like");
  assert.equal(isRedactedText(LEGACY_LOOKING), false, "and not recognised as redacted text");
  assert.equal(REDACTED_TOKEN_ONE.test(LEGACY_LOOKING), false);
  assert.equal(PROTECTED_TOKEN_LIKE_RE.test(LEGACY_LOOKING), false);

  const ctx = new RedactionContext({ salt: "fixture" });
  const line = `DB_PASSWORD=${LEGACY_LOOKING}`;
  const out = await ctx.redactText(line, ALL);
  // Whether it is redacted is now the ordinary decision: the strong binding fires, so it is.
  assert.notEqual(out, line, "the value is treated like any other input");
  assert.equal(out.includes(LEGACY_LOOKING), false, "and the legacy-looking text does not survive");
});

test("an unregistered v2-shaped token is treated the same way [GREEN NOW]", async () => {
  // Both shapes are just text to this layer now. Nothing is exempt because it "looks like a
  // token" -- that principle applies to the current dialect too.
  const ctx = new RedactionContext({ salt: "fixture" });
  const line = `DB_PASSWORD=${UNKNOWN_CRG}`;
  const out = await ctx.redactText(line, ALL);
  assert.notEqual(out, line, "redacted by the ordinary binding evidence");
  assert.equal(out.includes(UNKNOWN_CRG), false);
});

test("the legacy-looking shape does not enable stream holdback [GREEN NOW]", async () => {
  // `{{Reda` and `{{Redact:` used to be held back as a possible legacy token, which stalled
  // the stream for a dialect that no longer exists.
  const { streamHoldbackPrefixes, partialPrefixLength } = await import("../worker.js");
  const ctx = new RedactionContext({ salt: "fixture" });
  const holdbacks = streamHoldbackPrefixes(ctx, null);
  for (const fragment of ["{{Reda", "{{Redact:", "{{Redact:" + "a".repeat(64)]) {
    assert.equal(partialPrefixLength(fragment, holdbacks), 0, `${fragment} must not be held back`);
  }
});

test("a legacy-looking value in a tool operand is not blocked as an unresolvable token [GREEN NOW]", async () => {
  // It is not a token, so there is nothing unresolvable about it: the operand channel keeps
  // it as ordinary text rather than replacing it with a block marker.
  const { classifyRestore } = await import("../worker.js");
  const ctx = new RedactionContext({ salt: "fixture" });
  const decision = classifyRestore({ ctx, text: `curl x?y=${LEGACY_LOOKING}`, sink: { kind: "tool_argument" } });
  assert.equal(decision.action, "preserve");
  assert.equal(decision.text.includes(LEGACY_LOOKING), true, "delivered as ordinary text");
});
