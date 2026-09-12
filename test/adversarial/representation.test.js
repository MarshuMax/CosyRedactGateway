// R2.5 -- representation / ownership / ledger adversarial.
//
// Priority follows "cross-layer authority plus request-local state", which is where the findings
// have actually come from:
//
//   1. SurrogateLedger exact authority -- shape must not create ownership, and neither must
//      encoding. Only an exact ledger mapping lets a surrogate inherit authority.
//   2. EntityLedger first-write-wins -- the same plaintext in different occurrences, schemas and
//      paths. A metadata difference is NOT a finding on its own; it becomes one only when it
//      changes a security outcome.
//   3. restoreText two-stage cascade -- a surrogate that restores to another token-looking value.
//
// The overall oracle:
//
//   plaintext appears  ==>  current-context exact ownership AND sink has restore authority
//
// and, separately:
//
//   the same plaintext may reuse one token identity, but occurrence-specific schema and policy
//   must not be borrowed between occurrences.

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  SurrogateLedger,
  resolveSurrogate,
  classifyOwnership,
  classifyRestore,
  findSensitiveSpans,
  ENCODING_KIND,
  isRedactedText,
} from "../../worker.js";
import { generate, makeRng } from "../helpers/property.mjs";

const SEED_REPRESENTATION = 0x2e610005;
const FLAGS = { gitleaks: true, highEntropy: true, email: true };
const B64 = "cGFzc3dvcmQxMjM0NTY3OA==";
const PAT = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
const FLAGS_PAT = { gitleaks: true, highEntropy: true };

const b64 = (s) => Buffer.from(s).toString("base64");

/** A context holding one real entity, plus the representations derived from it. */
async function fixture() {
  const ctx = new RedactionContext({ salt: "r25", requestId: "AAAAAA" });
  // `apiVersion: v1` is REQUIRED for the object-level recogniser to impose the base64
  // representation; without it the field gets an ordinary token. Asserted below so the fixture
  // cannot silently stop producing a surrogate.
  const doc = ["apiVersion: v1", "kind: Secret", "data:", `  password: ${B64}`].join("\n");
  const out = await ctx.redactText(doc, FLAGS);
  const surrogate = (out.match(/password: (\S+)/) || [])[1];
  const entry = ctx.ledger.lookup(surrogate);
  assert.ok(entry, `the fixture must mint a ledger surrogate, got ${JSON.stringify(out)}`);
  assert.equal(entry.encodingKind, ENCODING_KIND.BASE64, "and it must be the base64 representation");
  return { ctx, surrogate, token: entry.token };
}

// =====================================================================================
// 1. SurrogateLedger exact authority
// =====================================================================================

test("R2.5: neither shape nor encoding creates ownership [RED]", async () => {
  const { ctx, surrogate, token } = await fixture();
  assert.ok(token && surrogate, "fixture must produce both representations");

  // A base64-kind surrogate IS base64 of its token, so the two representations coincide here.
  // Stated explicitly because several assertions below depend on it.
  assert.equal(b64(token), surrogate, "a base64 surrogate IS base64 of its token");

  const cases = [
    ["real OWN token", token, "OWN", true],
    ["real ledger surrogate", surrogate, "OWN", true],
    ["forged CRG", "CRG_AAAA_AAAA", "UNKNOWN", false],
    ["base64(forged CRG)", b64("CRG_AAAA_AAAA"), "UNKNOWN", false],
    ["double-base64(real token)", b64(b64(token)), "UNKNOWN", false],
    ["double-base64(forged)", b64(b64("CRG_AAAA_AAAA")), "UNKNOWN", false],
    ["surrogate then base64", b64(surrogate), "UNKNOWN", false],
    ["near-miss: one char off the surrogate", surrogate.slice(0, -1) + "X", "UNKNOWN", false],
    ["near-miss: token with a changed id", "CRG_AAAAAA_0002", "UNKNOWN", false],
  ];

  for (const [label, value, expectedOwnership, expectedProtected] of cases) {
    assert.equal(classifyOwnership(value, ctx).ownership, expectedOwnership, `${label}: ownership`);
    assert.equal(ctx.isProtectedToken(value), expectedProtected, `${label}: protection`);
    // A representation that is not owned must not resolve to anything.
    if (expectedOwnership !== "OWN") {
      assert.equal(resolveSurrogate(value, ctx), value, `${label}: must not resolve`);
    }
  }
});

test("R2.5: only an exact ledger mapping grants surrogate authority [RED]", async () => {
  // Built directly on the ledger, so "exact" is the only variable.
  const ledger = new SurrogateLedger();
  const token = "CRG_AAAAAA_0001";
  const visible = ledger.mint(token, ENCODING_KIND.BASE64);

  assert.deepEqual(ledger.lookup(visible), { token, encodingKind: ENCODING_KIND.BASE64 }, "an exact hit resolves");
  for (const near of [visible.slice(0, -1), `${visible}X`, visible.toLowerCase(), visible.toUpperCase(), b64(visible), ` ${visible}`]) {
    if (near === visible) continue;
    assert.equal(ledger.lookup(near), null, `a near-miss must not resolve: ${JSON.stringify(near)}`);
  }

  // Minting a PLAIN encoding registers nothing, so a plain token is never treated as a surrogate.
  const other = "CRG_AAAAAA_0002";
  const plain = ledger.mint(other, ENCODING_KIND.PLAIN);
  assert.equal(plain, other, "a plain encoding is the token itself");
  assert.equal(ledger.lookup(other), null, "and is not registered as a surrogate");
});

test("R2.5: plaintext appears only with exact ownership AND restore authority [RED]", async () => {
  // The overall oracle, across occurrences and sinks.
  const { ctx, surrogate, token } = await fixture();
  const contexts = [
    ["plain field", (v) => `x: ${v}`],
    ["K8s Secret.data", (v) => `kind: Secret\ndata:\n  password: ${v}`],
    ["K8s stringData", (v) => `kind: Secret\nstringData:\n  password: ${v}`],
    ["strong binding", (v) => `DB_PASSWORD=${v}`],
    ["weak binding", (v) => `notes: ${v}`],
    ["prose", (v) => `the value is ${v}`],
  ];
  const sinks = ["assistant_text", "tool_argument", "shell", "database", "email", "unknown_channel"];
  const violations = [];

  for (const [cname, wrap] of contexts) {
    for (const [vname, value] of [["token", token], ["surrogate", surrogate]]) {
      for (const sink of sinks) {
        for (const trusted of [false, true]) {
          const sinkSpec = trusted ? { kind: sink, trust: "trusted" } : { kind: sink };
          const decision = classifyRestore({ ctx, text: wrap(value), sink: sinkSpec });
          const ownership = classifyOwnership(value, ctx).ownership;
          const hasAuthority = ownership === "OWN" && (trusted || sink === "assistant_text" || sink === "log_write");
          if (decision.text.includes(B64) && !hasAuthority) {
            violations.push({ cname, vname, sink, trusted, out: decision.text });
          }
        }
      }
    }
  }
  assert.deepEqual(violations.slice(0, 3), [], `plaintext escaped without authority: ${JSON.stringify(violations.slice(0, 3))}`);
});

test("R2.5: cross-context isolation holds in both directions [RED]", async () => {
  // A surrogate is request-local, so another context must not resolve it -- and must not treat it as
  // owned either. That is the same conclusion as R1.1, restated for the representation axis.
  const { surrogate, token } = await fixture();
  const other = new RedactionContext({ salt: "r25", requestId: "BBBBBB" });

  assert.equal(classifyOwnership(surrogate, other).ownership, "UNKNOWN", "another context must not inherit the surrogate");
  assert.equal(classifyOwnership(token, other).ownership, "UNKNOWN", "nor the token");
  assert.equal(other.isProtectedToken(surrogate), false);
  assert.equal(resolveSurrogate(surrogate, other), surrogate, "and must not resolve it");

  // The value is therefore redacted like any other input.
  const out = (await other.redactText(`A=${surrogate}`, FLAGS_PAT)).out;
  assert.notEqual(out, `A=${surrogate}`, "it is ordinary text to another context");
});

// =====================================================================================
// 2. EntityLedger first-write-wins
// =====================================================================================

test("R2.5: the same plaintext reuses one identity across occurrences [RED]", async () => {
  // Reuse is the documented behaviour, and it must hold however the occurrences are arranged.
  const variants = [
    ["two env lines", `A=${PAT}\nB=${PAT}`],
    ["one line twice", `A=${PAT} B=${PAT}`],
    ["yaml two keys", `a: ${PAT}\nb: ${PAT}`],
    ["weak then strong", `notes: ${PAT}\nDB_PASSWORD=${PAT}`],
    ["strong then weak", `DB_PASSWORD=${PAT}\nnotes: ${PAT}`],
  ];
  for (const [label, doc] of variants) {
    const ctx = new RedactionContext({ salt: "r25", requestId: "AAAAAA" });
    const out = await ctx.redactText(doc, FLAGS_PAT);
    const tokens = out.match(/CRG_[A-Z0-9]+_[A-Z0-9]+/g) || [];
    assert.equal(tokens.length, 2, `${label}: both occurrences are rewritten`);
    assert.equal(new Set(tokens).size, 1, `${label}: and share one identity`);
    assert.equal(ctx.restoreText(out), doc, `${label}: round trip is exact`);
  }
});

test("R2.5: the ledger entry is first-write-wins and order-sensitive in its metadata [GREEN NOW]", async () => {
  // Recorded, NOT a finding: the ledger keeps the FIRST record for a token, so a metadata field can
  // differ depending on which occurrence came first. That is only escalated if it changes a security
  // outcome -- see the test below, which is the one that matters.
  const docA = ["kind: Secret", "data:", `  password: ${B64}`, "stringData:", `  alt: ${B64}`].join("\n");
  const docB = ["kind: Secret", "stringData:", `  alt: ${B64}`, "data:", `  password: ${B64}`].join("\n");

  const ctxA = new RedactionContext({ salt: "r25", requestId: "AAAAAA" });
  const outA = await ctxA.redactText(docA, FLAGS);
  const ctxB = new RedactionContext({ salt: "r25", requestId: "AAAAAA" });
  const outB = await ctxB.redactText(docB, FLAGS);

  // The SECURITY outcome is what must not depend on order: the secret is gone either way.
  assert.equal(outA.includes(B64), false, "order A: the secret is redacted");
  assert.equal(outB.includes(B64), false, "order B: the secret is redacted");
  assert.equal(ctxA.restoreText(outA), docA, "order A: round trip exact");
  assert.equal(ctxB.restoreText(outB), docB, "order B: round trip exact");
});

// =====================================================================================
// 3. restoreText cascade and token hygiene
// =====================================================================================

test("R2.5: a restored value that looks like a token is not restored again [RED]", async () => {
  // The two-stage cascade: if a surrogate restored to another token-looking string, a second pass
  // could resolve it into something else entirely. The mapping is built explicitly so the case is
  // reachable rather than hypothetical.
  const ctx = new RedactionContext({ salt: "r25", requestId: "AAAAAA" });
  const inner = "CRG_AAAAAA_0001";
  const outer = "CRG_AAAAAA_0002";
  ctx.tokenToRaw.set(inner, B64);
  ctx.tokenToRaw.set(outer, inner);

  const once = ctx.restoreText(outer);
  assert.equal(once.includes(B64), false, "restoration must be a single pass, not a cascade");
  assert.equal(once, inner, "the outer token maps to exactly what was recorded for it");
});

// =====================================================================================
// FINDING R2-REP-001
// =====================================================================================

test("R2-REP-001: a redaction never leaves a partial value beside the replacement [RED]", async () => {
  // DISCOVERED while exercising K8s Secret documents. The entropy detector's span stops before
  // base64 padding, so the padding survives next to the replacement:
  //
  //   apiVersion: v1
  //   kind: Secret
  //   data:
  //     a: cGFzc3dvcmQxMjM0NTY3OA==   ->  a: Q1JHX0FBQUFBQV8wMDAx        (correct)
  //     b: cGFzc3dvcmQxMjM0NTY3OA==   ->  b: Q1JHX0FBQUFBQV8wMDAy==      (padding left behind)
  //
  // MINIMAL REPRODUCER, no other mechanism involved:
  //
  //   A=cGFzc3dvcmQxMjM0NTY3OA==   ->  A=CRG_AAAAAA_0001==
  //   A=cGFzc3dvcmQxMjM0NTY3OA=    ->  A=CRG_AAAAAA_0001=
  //   A=cGFzc3dvcmQxMjM0NTY3OA     ->  A=CRG_AAAAAA_0001
  //
  // VIOLATED CONTRACT: the replacement is self-delimiting. R1 already asserts that every emitted
  // token matches ^CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}$ and that no TRUNCATED PREFIX survives; the
  // converse -- a complete replacement with leftover characters glued to it -- was never covered.
  // The emitted value is therefore neither the replacement nor the original.
  //
  // IMPACT: integrity and representation correctness, in EVERY context, not only K8s. Round-trip
  // happens to survive because the surviving `==` is still the original's padding and restoration is
  // substring-based; that is asserted separately so the claim stays exact. No confidentiality
  // fail-open.
  for (const [label, value, residue] of [
    ["two padding chars", "cGFzc3dvcmQxMjM0NTY3OA==", "=="],
    ["one padding char", "cGFzc3dvcmQxMjM0NTY3OA=", "="],
  ]) {
    // a) the ordinary binding path emits an ASCII token with padding glued on.
    const ctx = new RedactionContext({ salt: "r25", requestId: "AAAAAA" });
    const out = await ctx.redactText(`A=${value}`, FLAGS_PAT);
    assert.equal(out.includes(residue), false, `${label}: ${JSON.stringify(residue)} must not be left beside the token -> ${JSON.stringify(out)}`);

    // b) the base64-representation path emits a base64 surrogate, which must still be valid base64
    //    of a replacement rather than a truncated encode with the original padding appended.
    const k8s = ["apiVersion: v1", "kind: Secret", "data:", `  a: ${value}`].join("\n");
    const kctx = new RedactionContext({ salt: "r25", requestId: "AAAAAA" });
    const kout = await kctx.redactText(k8s, FLAGS_PAT);
    const emitted = (kout.match(/a: (\S+)/) || [])[1];
    assert.ok(emitted, `${label}: the fixture must produce a value`);
    assert.equal(
      Buffer.from(emitted, "base64").toString("base64"), emitted,
      `${label}: the replacement must be canonical base64, not a truncated encode -> ${JSON.stringify(emitted)}`
    );
  }
});

test("R2-REP-001: the residue is present in every occurrence of the value [RED]", async () => {
  // The same defect through the K8s path that surfaced it. Two occurrences of one plaintext produce
  // two spans -- `gitleaks` matches the padded form and `entropy` the unpadded one -- which overlap
  // without containment, so the merge keeps both and the padding is left on the second.
  const doc = ["apiVersion: v1", "kind: Secret", "data:", `  a: ${B64}`, `  b: ${B64}`].join("\n");
  const spans = findSensitiveSpans(doc, FLAGS_PAT);
  const covered = spans.map((sp) => doc.slice(sp.start, sp.end));
  assert.deepEqual(
    covered, [B64, B64.slice(0, -2)],
    "the two spans differ by the padding: gitleaks takes the padded form, entropy the unpadded one"
  );

  const ctx = new RedactionContext({ salt: "r25", requestId: "AAAAAA" });
  const out = await ctx.redactText(doc, FLAGS_PAT);

  // Both emitted values must be canonical replacements. The second one is a base64 encode of a
  // SECOND token with the original padding appended, so decoding it does not yield a token.
  for (const key of ["a", "b"]) {
    const emitted = (out.match(new RegExp(`${key}: (\\S+)`)) || [])[1];
    assert.ok(emitted, `${key}: a replacement must be produced`);
    assert.equal(
      isRedactedText(emitted) || Buffer.from(emitted, "base64").toString("base64") === emitted,
      true,
      `${key}: the replacement must be a token or canonical base64 -> ${JSON.stringify(emitted)}`
    );
  }
});

test("R2.5: the representation corpus is deterministic [GREEN NOW]", () => {
  const draw = (r) => [r.pick(["token", "surrogate", "forged", "double"]), r.bool(), r.int(0, 3)];
  assert.deepEqual(draw(makeRng(SEED_REPRESENTATION)), draw(makeRng(SEED_REPRESENTATION)));
});

test("R2.5: seeded representation variants keep the oracle [RED]", async () => {
  const { ctx, surrogate, token } = await fixture();
  const values = [token, surrogate, b64("CRG_AAAA_AAAA"), b64(b64(token)), "CRG_AAAA_AAAA"];
  const sinks = ["assistant_text", "tool_argument", "shell"];
  let cases = 0;
  const violations = [];
  for (const { value, sink } of generate({
    seed: SEED_REPRESENTATION,
    count: 200,
    gen: (r) => ({ value: r.pick(values), sink: r.pick(sinks) }),
  })) {
    const decision = classifyRestore({ ctx, text: `x ${value} y`, sink: { kind: sink } });
    if (decision.text.includes(B64) && sink !== "assistant_text") {
      violations.push({ value: value.slice(0, 16), sink, out: decision.text.slice(0, 60) });
    }
    cases++;
  }
  assert.equal(cases, 200);
  assert.deepEqual(violations.slice(0, 3), [], `the oracle was violated: ${JSON.stringify(violations.slice(0, 3))}`);
});
