// Legacy v1 token compatibility.
//
// Scope: this file is the ONLY place that exercises the `{{Redact:<64 hex>}}`
// format. Everything else asserts the v2 `CRG_<requestId>_<entityId>` format
// through the format-agnostic helpers exported by worker.js
// (REDACTED_TOKEN / REDACTED_TOKEN_ONE / isRedactedText).
//
// Lifecycle: dual-format is a transition, not a destination. Generation already
// emits only v2. Once the remaining consumers have migrated, this file shrinks to
// the handful of cases below and the legacy branch in `restoreText`, plus
// LEGACY_TOKEN_* in worker.js, are deleted.
//
// Why re-minting matters: a client that cached a pre-migration response, or a
// multi-turn transcript containing v1 tokens, still carries the old format. The
// gateway must not forward two token dialects into one conversation, so a legacy
// token present on input is converted to a v2 token bound to the current request
// while the mapping stays intact.

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  REDACTED_TOKEN,
  TOKEN_PREFIX,
  LEGACY_TOKEN_PREFIX,
  legacyRedactToken,
  isRedactedText,
} from "../worker.js";

const HEX = "a1b2c3d4".repeat(8); // 64 hex chars
const LEGACY = legacyRedactToken(HEX);
const FLAGS = { gitleaks: true, highEntropy: true, email: true };

test("generation never emits the legacy format [GREEN NOW]", async () => {
  const ctx = new RedactionContext({ salt: "fixture" });
  const out = await ctx.redactText("DB_PASSWORD=cGFzc3dvcmQxMjM0NTY3OA==\na@example.com", FLAGS);
  assert.equal(out.includes(LEGACY_TOKEN_PREFIX), false, "no v1 placeholder may be produced");
  assert.ok(out.includes(TOKEN_PREFIX), "a v2 token must be produced");
  assert.equal(isRedactedText(out), true);
});

test("an unknown legacy token is left untouched [GREEN NOW]", async () => {
  // Mapping lookup is the only authority: never restore what this context did not
  // register, and never invent a value for an unknown token.
  const ctx = new RedactionContext({ salt: "fixture" });
  const text = `the value is ${LEGACY}`;
  assert.equal(ctx.restoreText(text), text);
  assert.equal(await ctx.redactText(text, FLAGS), text, "an unregistered legacy token is not re-minted");
});

test("a registered legacy token is restored [GREEN NOW]", async () => {
  const ctx = new RedactionContext({ salt: "fixture" });
  const ctxToken = await ctx.tokenFor("legacy-secret-value");
  // Simulate a v1 mapping entry surviving from a pre-migration response.
  ctx.tokenToRaw.set(LEGACY, "legacy-secret-value");
  assert.equal(ctx.restoreText(`x=${LEGACY}`), "x=legacy-secret-value");
  assert.ok(ctxToken.startsWith(TOKEN_PREFIX));
});

test("a registered legacy token on input is re-minted to v2 [GREEN NOW]", async () => {
  const ctx = new RedactionContext({ salt: "fixture" });
  // Bind the legacy token to the plaintext on the RESTORE side only. Populating
  // rawToToken as well would make re-minting a no-op (tokenFor would hand back the
  // legacy token) and the test would assert nothing.
  ctx.tokenToRaw.set(LEGACY, "legacy-secret-value");
  const out = await ctx.redactText(`PASSWORD=${LEGACY}`, FLAGS);
  assert.equal(out.includes(LEGACY_TOKEN_PREFIX), false, "the v1 dialect must not be forwarded");
  assert.match(out, new RegExp(`${TOKEN_PREFIX}${ctx.requestId}_[A-Z0-9]{4,}`), "a v2 token must replace it");
  assert.equal(ctx.restoreText(out), "PASSWORD=legacy-secret-value", "the mapping must survive re-minting");
});

test("both dialects restore in a single payload [GREEN NOW]", async () => {
  const ctx = new RedactionContext({ salt: "fixture" });
  const v2 = await ctx.tokenFor("v2-secret");
  ctx.tokenToRaw.set(LEGACY, "v1-secret");
  const out = ctx.restoreText(`a=${v2} b=${LEGACY}`);
  assert.equal(out, "a=v2-secret b=v1-secret");
});

test("format-agnostic helpers cover both dialects [GREEN NOW]", () => {
  const v2 = `${TOKEN_PREFIX}ABCDEF_0001`;
  assert.equal(isRedactedText(v2), true);
  assert.equal(isRedactedText(LEGACY), true);
  assert.equal((`${v2} ${LEGACY}`.match(REDACTED_TOKEN) || []).length, 2);
  assert.equal(isRedactedText("CRG_"), false, "a bare prefix is not a token");
  assert.equal(isRedactedText("not a token"), false);
});
