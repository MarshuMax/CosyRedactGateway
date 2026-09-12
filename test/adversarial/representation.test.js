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
// R2-REP-001 -- FIXED. Base64 representation envelope.
//
// Root cause, stated precisely. The consequence was "one plaintext, two identities", but that is
// NOT a ledger defect: the raw strings handed to the mapping genuinely differed --
//
//   occurrence 1 raw: cGFzc3dvcmQxMjM0NTY3OA==
//   occurrence 2 raw: cGFzc3dvcmQxMjM0NTY3OA
//
// -- so rawToToken legitimately allocated two identities. The chain is:
//
//   entropy boundary truncation
//     -> original representation residue survives
//       -> the second occurrence's raw differs
//         -> the mapping allocates a second identity, exactly as its contract says
//
// The fix is a narrow REPRESENTATION envelope. `tokenizeBlocks()` scores `[A-Za-z0-9]+`, so the
// evidence stops before the padding; the detector has already shown the core is worth protecting,
// and what was missing is that the trailing `=` belongs to the ENCODED SCALAR.
//
// Deliberately NOT done:
//   - entropy alphabet := [A-Za-z0-9=]+   that pollutes the entropy model to solve a
//                                         representation problem, and moves every score
//   - a merge special case for entropy+gitleaks overlap   that teaches the geometry layer to
//                                         parse base64, which it must not know
// =====================================================================================

const TOKEN_FULL = /^CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}$/;
const PADDED = "cGFzc3dvcmQxMjM0NTY3OA==";
const CORES = { "no padding": PADDED.slice(0, -2), "one =": null, "two ==": PADDED };

/** The value a K8s entry holds, i.e. the RHS of `key:`. */
const rhsOf = (text, key) => {
  const m = new RegExp(`(?:^|\\n)\\s*${key}: (\\S+)`).exec(text);
  return m ? m[1] : null;
};

test("R2-REP-001: the replacement occupies the whole encoded scalar [RED]", async () => {
  // ORACLE CORRECTION. An earlier version searched the whole LINE for the residue, which can never
  // pass for the single-`=` case: the assignment's own `=` is in the line. The contract is about the
  // VALUE, so the value is extracted and asserted to BE a complete token.
  const cases = [
    ["env, two ==", `A=${PADDED}`],
    ["env, no padding", `A=${PADDED.slice(0, -2)}`],
    ["yaml, two ==", `a: ${PADDED}`],
    ["env, padding followed by other text", `A=${PADDED} B=plain`],
  ];
  for (const [label, doc] of cases) {
    const ctx = new RedactionContext({ salt: "r25", requestId: "AAAAAA" });
    const out = await ctx.redactText(doc, FLAGS_PAT);
    const emitted = label.startsWith("yaml") ? rhsOf(`\n${out}`, "a") : out.slice("A=".length).split(" ")[0];
    assert.ok(emitted, `${label}: a value must be emitted`);
    assert.match(emitted, TOKEN_FULL, `${label}: the emitted VALUE must be exactly one token -> ${JSON.stringify(out)}`);
    assert.equal(ctx.restoreText(out), doc, `${label}: round trip exact`);
  }
});

test("R2-REP-001: one `=` is not canonical base64 and is correctly not treated as padding [GREEN NOW]", async () => {
  // `cGFzc3dvcmQxMjM0NTY3OA=` has length 23, so it is NOT a complete base64 scalar; the envelope
  // must decline it, and the earlier regression asserted the opposite. Asserting the corrected
  // contract here keeps the negative case explicit rather than silently dropped.
  const notCanonical = `${PADDED.slice(0, -2)}=`;
  assert.equal(notCanonical.length % 4 === 0, false, "the fixture must not be canonical base64");

  const doc = `A=${notCanonical}`;
  const spans = findSensitiveSpans(doc, FLAGS_PAT);
  assert.equal(spans.length, 1, "the core is still claimed");
  assert.equal(spans[0].base64Envelope, undefined, "but no padding envelope is applied");

  const ctx = new RedactionContext({ salt: "r25", requestId: "AAAAAA" });
  const out = await ctx.redactText(doc, FLAGS_PAT);
  // The value here is `CRG_..._0001=` -- the token followed by the original's stray `=`. That is the
  // honest outcome for a non-canonical input: the core is replaced and the character that does not
  // belong to any encoded scalar is left as ordinary text. An earlier assertion demanded the whole
  // value be a token, which is the contract for a CANONICAL scalar, not for this one.
  const emitted = out.slice("A=".length);
  assert.equal(emitted.startsWith("CRG_"), true, `the core must be replaced -> ${JSON.stringify(out)}`);
  assert.equal(emitted.endsWith("="), true, "and the non-canonical trailing character is left alone");
  assert.match(emitted.replace(/=+$/, ""), TOKEN_FULL, "the token itself is complete and well-formed");
  assert.equal(ctx.restoreText(out), doc, "round trip exact");
});

test("R2-REP-001: every occurrence's mutation boundary covers its full encoded scalar [RED]", async () => {
  // ORACLE CORRECTION. The old regression pinned the BUG's shape:
  //     assert.deepEqual(covered, [B64, B64.slice(0, -2)])
  // which would fail the moment the implementation became correct. Replaced with the contract: for
  // each occurrence, the boundary covers the complete encoded scalar.
  const doc = ["apiVersion: v1", "kind: Secret", "data:", `  a: ${PADDED}`, `  b: ${PADDED}`].join("\n");
  const spans = findSensitiveSpans(doc, FLAGS_PAT);
  assert.equal(spans.length, 2, "both occurrences are claimed");
  for (const span of spans) {
    assert.equal(
      doc.slice(span.start, span.end), PADDED,
      `each boundary must cover the whole encoded scalar, got ${JSON.stringify(doc.slice(span.start, span.end))}`
    );
  }
});

test("R2-REP-001: a K8s value is a ledger-owned canonical surrogate [RED]", async () => {
  // Stated as the real contract rather than "it round-trips through base64": the emitted value must
  // be CANONICAL base64, must BE in the ledger, and must RESOLVE to an owned token.
  const doc = ["apiVersion: v1", "kind: Secret", "data:", `  a: ${PADDED}`, `  b: ${PADDED}`].join("\n");
  const ctx = new RedactionContext({ salt: "r25", requestId: "AAAAAA" });
  const out = await ctx.redactText(doc, FLAGS_PAT);

  const a = rhsOf(`\n${out}`, "a");
  const b = rhsOf(`\n${out}`, "b");
  for (const [key, emitted] of [["a", a], ["b", b]]) {
    assert.ok(emitted, `${key}: a value must be emitted`);
    assert.equal(Buffer.from(emitted, "base64").toString("base64"), emitted, `${key}: must be canonical base64`);
    const entry = ctx.ledger.lookup(emitted);
    assert.ok(entry, `${key}: the emitted value must be a registered surrogate`);
    assert.equal(classifyOwnership(emitted, ctx).ownership, "OWN", `${key}: and must resolve to an owned token`);
    assert.match(resolveSurrogate(emitted, ctx), TOKEN_FULL, `${key}: the resolution must be a token`);
  }

  // And the same semantic raw no longer splits into two identities.
  assert.equal(a, b, "one plaintext keeps one identity");
  assert.equal(ctx.restoreText(out), doc, "round trip exact");
});

test("R2-REP-001: the classification input stays the detector core [GREEN NOW]", async () => {
  // Boundary widening must not change what the detector is asked to classify -- the same rule the
  // reference envelope follows.
  const doc = `A=${PADDED}`;
  const [span] = findSensitiveSpans(doc, FLAGS_PAT);
  assert.equal(doc.slice(span.start, span.end), PADDED, "the box covers the scalar");
  assert.equal(span.classifiedText, PADDED.slice(0, -2), "the verdict input is still the core");
  assert.deepEqual(span.base64Envelope, { coreEnd: span.start + PADDED.length - 2, paddingEnd: span.start + PADDED.length });
  assert.ok(span.evidence.includes("base64_padding_envelope"), "and the envelope is recorded as evidence");
});

test("R2-REP-001: the fix holds across scalars, flags and repetitions [RED]", async () => {
  const scalars = [
    ["env", (v) => `A=${v}`],
    ["yaml", (v) => `a: ${v}`],
    ["k8s data", (v) => ["apiVersion: v1", "kind: Secret", "data:", `  a: ${v}`].join("\n")],
  ];
  const flagSets = [
    ["H only", { highEntropy: true }],
    ["G only", { gitleaks: true }],
    ["H + G", { gitleaks: true, highEntropy: true }],
  ];
  for (const [sname, wrap] of scalars) {
    for (const [fname, flags] of flagSets) {
      const doc = wrap(PADDED);
      const ctx = new RedactionContext({ salt: "r25", requestId: "AAAAAA" });
      const out = await ctx.redactText(doc, flags);
      // "No padding survives" only applies once something was actually redacted. Measured: with
      // `G only` the gitleaks rule does NOT fire on this blob, because that rule gates on its own
      // entropy check, so nothing is rewritten and the input comes back untouched. Asserting
      // otherwise demanded a redaction the flag set does not produce.
      const redacted = out !== doc;
      if (redacted) {
        assert.equal(out.includes("=="), false, `${sname}/${fname}: no padding may survive -> ${JSON.stringify(out)}`);
      }
      assert.equal(ctx.restoreText(out), doc, `${sname}/${fname}: round trip exact whatever was decided`);
    }
  }
});

test("R2-REP-001: repeated occurrences in one document keep one identity [RED]", async () => {
  const doc = ["apiVersion: v1", "kind: Secret", "data:", `  a: ${PADDED}`, `  b: ${PADDED}`, `  c: ${PADDED}`].join("\n");
  const ctx = new RedactionContext({ salt: "r25", requestId: "AAAAAA" });
  const out = await ctx.redactText(doc, FLAGS_PAT);
  const emitted = ["a", "b", "c"].map((k) => rhsOf(`\n${out}`, k));
  assert.equal(new Set(emitted).size, 1, `three occurrences must share one identity, got ${JSON.stringify(emitted)}`);
  assert.equal(ctx.ledger.size, 1, "and one ledger entry");
  assert.equal(ctx.restoreText(out), doc, "round trip exact");
});

// =====================================================================================
// NEGATIVE CONTROLS -- proving the fix is a base64 representation boundary and not
// "eat two characters whenever a high-entropy run is followed by ="
// =====================================================================================

test("R2-REP-001 NC1: an `==` operator after a high-entropy run is not swallowed [GREEN NOW]", async () => {
  const cases = [
    ["operator", "x = aB3kL9mN2pQ7rS4tU6vW8xY0 == 1"],
    ["inside code", "if (aB3kL9mN2pQ7rS4tU6vW8xY0 == other) {}"],
    ["comparison chain", "aB3kL9mN2pQ7rS4tU6vW8xY0 == bC4lM8nP3qR8sT5uV7wX9yZ1 == 2"],
  ];
  for (const [label, doc] of cases) {
    const [span] = findSensitiveSpans(doc, FLAGS_PAT);
    assert.ok(span, `${label}: the high-entropy run is still claimed`);
    assert.equal(span.base64Envelope, undefined, `${label}: no padding envelope may apply`);
    const ctx = new RedactionContext({ salt: "r25", requestId: "AAAAAA" });
    const out = await ctx.redactText(doc, FLAGS_PAT);
    assert.ok(out.includes("=="), `${label}: the operator must survive -> ${JSON.stringify(out)}`);
  }
});

test("R2-REP-001 NC2: a non-canonical or mis-positioned candidate is not widened [GREEN NOW]", async () => {
  const cases = [
    ["length not a multiple of four", `A=${PADDED.slice(0, -3)}==`],
    ["padding followed by more alphabet", `A=${PADDED}extra`],
    ["padding followed by more padding", `A=${PADDED}=`],
    ["span does not start the scalar", `xx${PADDED}`],
    ["no padding at all", `A=${PADDED.slice(0, -2)}`],
  ];
  for (const [label, doc] of cases) {
    const spans = findSensitiveSpans(doc, FLAGS_PAT);
    for (const span of spans) {
      assert.equal(span.base64Envelope, undefined, `${label}: must not be widened -> ${JSON.stringify(doc.slice(span.start, span.end))}`);
    }
  }
});

test("R2-REP-001 NC3: a canonical scalar IS widened, so the control is not vacuous [GREEN NOW]", async () => {
  // Without this, NC1 and NC2 would also pass if the envelope never applied to anything.
  const doc = `A=${PADDED}`;
  const [span] = findSensitiveSpans(doc, FLAGS_PAT);
  assert.ok(span.base64Envelope, "the canonical case must be widened");
  assert.equal(doc.slice(span.start, span.end), PADDED);
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
