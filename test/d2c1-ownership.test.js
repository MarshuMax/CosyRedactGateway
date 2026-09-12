// D2c.1 ownership hardening.
//
// A security regression introduced while fixing foreign-token pass-through: the
// binding layer skipped any value that merely LOOKED like this layer's token, on the
// reasoning that "eligibility is still decided by ownership at merge time". The
// candidate never reached the merge, so the reasoning was false and the bypass was
// open:
//
//   DB_PASSWORD=CRG_AAAA_AAAA
//
// `CRG_AAAA_AAAA` is a perfectly plausible low-entropy password. The binding candidate
// was dropped by shape, entropy does not fire on it, and the generic rule does not
// either -- so it was forwarded in the clear on the input path.
//
// The same mistake existed in a third place: `RedactionContext.emit()` returned any
// TOKEN_FULL_RE match verbatim instead of checking whether this request had minted it.
//
// The rule, applied uniformly:
//
//   OWN                 -> preserve
//   FOREIGN_REGISTERED  -> preserve
//   UNKNOWN token-shaped -> NO exemption; normal redaction if any detector fires
//
// Assertion tags:
//   [GREEN NOW]  passes against the current tree

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  ForeignTokenRegistry,
  classifyOwnership,
  TOKEN_OWNERSHIP,
} from "../worker.js";

const ALL = { highEntropy: true, phone: true, secret: true, identity: true, bank: true, email: true, gitleaks: true };
const ACME = { name: "acme", pattern: /(?<![A-Za-z0-9_])ACME_[A-Z0-9_]{4,}(?![A-Za-z0-9_])/ };

function ctxWith(registry = null) {
  return new RedactionContext({ salt: "fixture", foreignRegistry: registry });
}

async function mintOwnToken(ctx) {
  const out = await ctx.redactText("a@example.com", { email: true });
  const token = out.match(/CRG_[A-Z0-9]+_[A-Z0-9]+/)?.[0];
  assert.ok(token, "fixture must mint a token");
  return token;
}

async function action(ctx, value) {
  const inbound = `DB_PASSWORD=${value}`;
  const out = await ctx.redactText(inbound, ALL);
  return out === inbound ? "preserve" : "redact";
}

// ------------------------------------------------ 1. the four required cases ---

test("1. an OWN CRG token under a strong key is preserved [GREEN NOW]", async () => {
  const ctx = ctxWith();
  const owned = await mintOwnToken(ctx);
  assert.equal(await action(ctx, owned), "preserve");
});

test("2. a REGISTERED foreign token under a strong key is preserved [GREEN NOW]", async () => {
  const ctx = ctxWith(new ForeignTokenRegistry([ACME]));
  assert.equal(await action(ctx, "ACME_ABCDEF_0001"), "preserve");
  // Exact registration works too, for issuers with no usable prefix shape.
  const exact = ctxWith(new ForeignTokenRegistry().registerTokens(["opaque-token-from-vendor"]));
  assert.equal(await action(exact, "opaque-token-from-vendor"), "preserve");
});

test("3. an UNREGISTERED CRG-shaped literal is redacted [GREEN NOW]", async () => {
  const ctx = ctxWith();
  for (const value of ["CRG_AAAA_AAAA", "CRG_K7M2Q9_T8F4N6P3", "CRG_ZZZZ_0001"]) {
    assert.equal(await action(ctx, value), "redact", `${value} must not be exempt`);
  }
});

test("4. an UNREGISTERED foreign-shaped literal is redacted [GREEN NOW]", async () => {
  const ctx = ctxWith(new ForeignTokenRegistry([ACME]));
  // Same shape as a registered namespace, different issuer.
  assert.equal(await action(ctx, "EVIL_ABCDEF_0001"), "redact");
  // And the registered one is only preserved when a registry is actually present.
  assert.equal(await action(ctxWith(), "ACME_ABCDEF_0001"), "redact");
});

// ------------------------------------------------- 2. the exemption table ------

test("ownership is the only exemption, asserted as one table [GREEN NOW]", async () => {
  const registry = new ForeignTokenRegistry([ACME]);
  const ctx = ctxWith(registry);
  const owned = await mintOwnToken(ctx);

  const table = [
    ["OWN", owned, TOKEN_OWNERSHIP.OWN, "preserve"],
    ["FOREIGN_REGISTERED", "ACME_ABCDEF_0001", TOKEN_OWNERSHIP.FOREIGN_REGISTERED, "preserve"],
    ["UNKNOWN own-shaped", "CRG_AAAA_AAAA", TOKEN_OWNERSHIP.UNKNOWN, "redact"],
    ["UNKNOWN foreign-shaped", "EVIL_ABCDEF_0001", TOKEN_OWNERSHIP.UNKNOWN, "redact"],
    ["ordinary base64 secret", "cGFzc3dvcmQxMjM0NTY3OA==", TOKEN_OWNERSHIP.UNKNOWN, "redact"],
    ["ordinary symbol secret", "Pr0d-P@ssw0rd-Xy9Zk2mQ", TOKEN_OWNERSHIP.UNKNOWN, "redact"],
  ];
  for (const [label, value, expectedOwnership, expectedAction] of table) {
    assert.equal(classifyOwnership(value, ctx, registry).ownership, expectedOwnership, `${label}: ownership`);
    assert.equal(await action(ctx, value), expectedAction, `${label}: action`);
  }
});

test("`emit` itself checks ownership, not shape [GREEN NOW]", async () => {
  // The third copy of the same mistake: emit() returned any TOKEN_FULL_RE match
  // verbatim, so a token-shaped literal was published unchanged even after the merge
  // had correctly produced a span for it.
  const ctx = ctxWith();
  const shaped = "CRG_AAAA_AAAA";
  const emitted = await ctx.emit(shaped);
  assert.notEqual(emitted, shaped, "an unowned token-shaped value must be minted, not passed through");
  assert.equal(ctx.tokenToRaw.has(emitted), true, "the result is owned by this request");

  // An owned token is still returned as-is, which is what makes idempotency work.
  assert.equal(await ctx.emit(emitted), emitted, "an owned token is returned unchanged");
});

test("no shape-based exemption remains in the binding layer [GREEN NOW]", async () => {
  // Guard against reintroducing the filter: every token-shaped value that is not owned
  // must produce a span and be redacted, regardless of how plausible the shape is.
  const ctx = ctxWith();
  for (const value of [
    "CRG_AAAA_AAAA", "CRG_1_1", "CRG_ABCDEF_0001", "CRG_ABCDEF_0001_EXTRA",
  ]) {
    const inbound = `DB_PASSWORD=${value}`;
    assert.notEqual(await ctx.redactText(inbound, ALL), inbound, `${value} must be redacted`);
  }
});
