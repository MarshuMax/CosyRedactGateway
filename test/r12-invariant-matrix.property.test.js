// R1.2 -- invariant matrix closure.
//
// No production behaviour is added or changed by this file. It closes five acceptance items
// from R1 that had no property of their own: what existed covered parts of them, but not the
// matrix cells that matter most.
//
//   P3  OWN token x sink x trust authority matrix
//   P5  plain token and surrogate obey the SAME delivery policy
//   P6  a parser failure does not shut a detector down
//   P7  AMBIGUOUS infrastructure cannot obtain an exemption
//   P8  bytes outside the selected span are untouched
//
// The rule when one of these goes red is the standing one: verify the PROPERTY before
// concluding it is an implementation bug.

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  SINK_MODE,
  resolveSinkMode,
  classifyRestore,
  decideSpanAction,
  findSensitiveSpans,
  recogniseInfra,
  INFRA_TYPE,
  INFRA_CERTAINTY,
  INFRA_DISPOSITION,
  DEFAULT_PROFILE,
  DEVOPS_PROFILE,
  SurrogateLedger,
} from "../worker.js";
import { generate, DEFAULT_SEED } from "./helpers/property.mjs";

const FLAGS = { gitleaks: true, highEntropy: true, email: true, secret: true };
const PAT = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";        // claimed by gitleaks
const AWS = "wJalrXUtnFEMIK7MDENGbPxRfiCY";                      // claimed by entropy/binding
const SECRETS = [PAT, AWS, "cGFzc3dvcmQxMjM0NTY3OA=="];
const SENSITIVE = ["shell", "network_egress", "database", "email"];

/** Redact, returning the context so ownership can be probed afterwards. */
async function redact(text, options = {}, flags = FLAGS) {
  const ctx = new RedactionContext({ salt: "r12", ...options });
  return { ctx, out: await ctx.redactText(text, flags) };
}

/** The context's own token for a value, minted through the normal path. */
async function tokenFor(value) {
  const ctx = new RedactionContext({ salt: "r12" });
  const out = await ctx.redactText(`DB_PASSWORD=${value}`, FLAGS);
  const token = (out.match(/CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}/) || [])[0];
  return { ctx, token };
}

// ============================================================ P3: authority matrix =====

test("P3: restore authority is exactly the set of channels that may emit plaintext [RED]", async () => {
  // The property is stated on the OUTPUT, not on a mode or action string:
  //
  //     output contains plaintext  ==>  the channel has restore authority
  //
  // Checking `mode`/`action` would pass even if the plumbing ignored them, which is the same
  // helper-correct/production-unwired trap this session keeps hitting.
  const authority = {
    "assistant_text": true,
    "log_write": false,
    "tool_argument": false,
    "shell": false,
    "network_egress": false,
    "database": false,
    "email": false,
    "unknown_channel": false,
  };
  const cases = generate({
    seed: DEFAULT_SEED + 21,
    count: 200,
    gen: (rng) => ({
      secret: rng.pick(SECRETS),
      sink: rng.pick(Object.keys(authority)),
      trusted: rng.bool(0.2),
    }),
  });

  for (let i = 0; i < cases.length; i++) {
    const { secret, sink, trusted } = cases[i];
    const { ctx, token } = await tokenFor(secret);
    assert.ok(token, "the fixture must mint a token");

    const text = `the value is ${token}`;
    const sinkSpec = trusted ? { kind: sink, trust: "trusted" } : { kind: sink };
    const decision = classifyRestore({ ctx, text, sink: sinkSpec });

    const mayRestore = trusted || authority[sink] === true;
    const emittedPlaintext = decision.text.includes(secret);
    const input = `case ${i}: sink=${sink} trusted=${trusted} secret=${JSON.stringify(secret)}`;

    if (emittedPlaintext) {
      assert.equal(mayRestore, true, `${input}: plaintext emitted by a channel without restore authority -> ${JSON.stringify(decision.text)}`);
    }
    if (mayRestore && decision.action !== "block") {
      assert.equal(emittedPlaintext, true, `${input}: a channel WITH restore authority did not resolve the token -> ${JSON.stringify(decision.text)}`);
    }
    if (!mayRestore) {
      assert.equal(decision.text.includes(secret), false, `${input}: no plaintext outside restore authority`);
      // And the token is what gets delivered instead, not a rewritten value.
      assert.ok(decision.text.includes(token) || decision.action === "block", `${input}: expected the token or a refusal`);
    }
  }
});

test("P3: a trusted broker is the only tool channel with restore authority [RED]", async () => {
  const { ctx, token } = await tokenFor(PAT);
  const untrusted = classifyRestore({ ctx, text: token, sink: { kind: "tool_argument" } });
  const trusted = classifyRestore({ ctx, text: token, sink: { kind: "tool_argument", trust: "trusted" } });
  assert.equal(untrusted.text.includes(PAT), false, "an untrusted tool argument must not resolve");
  assert.ok(trusted.text.includes(PAT), "a trusted broker must resolve");
  // Declared through the registry list rather than the sink object, which is the other route.
  const viaList = classifyRestore({ ctx, text: token, sink: { kind: "tool_argument", toolName: "broker" }, trusted: ["broker"] });
  assert.ok(viaList.text.includes(PAT), "the trusted-name route must work too");
});

// ============================================== P5: representation policy equivalence ====

test("P5: a token and its surrogate obey the same delivery policy [RED]", async () => {
  // R1.1 proved the two representations agree on OWNERSHIP. This proves they agree on the
  // DELIVERY POLICY, which is a separate question: ownership is answered by the ledger, policy
  // by the sink, and a representation that resolved ownership but not policy would show up here.
  const doc = ["apiVersion: v1", "kind: Secret", "metadata:", "  name: app", "data:", `  password: ${"cGFzc3dvcmQxMjM0NTY3OA=="}`].join("\n");
  const { ctx, out } = await redact(doc, {}, { ...FLAGS, highEntropy: true });
  const surrogate = (out.match(/password: (\S+)/) || [])[1];
  const token = ctx.ledger.entries()[0]?.token;
  assert.ok(surrogate && token, "the fixture must produce both representations");
  assert.notEqual(surrogate, token, "they must actually be different strings");

  const plaintext = "cGFzc3dvcmQxMjM0NTY3OA==";
  for (const sink of ["assistant_text", "log_write", "tool_argument", ...SENSITIVE, "unknown_channel"]) {
    for (const trusted of [false, true]) {
      const sinkSpec = trusted ? { kind: sink, trust: "trusted" } : { kind: sink };
      const viaToken = classifyRestore({ ctx, text: token, sink: sinkSpec });
      const viaSurrogate = classifyRestore({ ctx, text: surrogate, sink: sinkSpec });
      const label = `sink=${sink} trusted=${trusted}`;

      assert.equal(
        viaToken.text.includes(plaintext), viaSurrogate.text.includes(plaintext),
        `${label}: representations disagree on whether plaintext may appear (${JSON.stringify(viaToken.text)} vs ${JSON.stringify(viaSurrogate.text)})`
      );
      assert.equal(
        viaToken.action === "block", viaSurrogate.action === "block",
        `${label}: representations disagree on refusal`
      );
      if (!trusted && !["assistant_text", "log_write"].includes(sink)) {
        assert.equal(viaSurrogate.text.includes(plaintext), false, `${label}: no plaintext through the surrogate either`);
      }
    }
  }
});

test("P5: the surrogate is not admitted by shape [GREEN NOW]", async () => {
  // Kept from R1.1 as the guard on the equivalence above: if the policy ever started admitting
  // base64 by shape, equivalence would be satisfied the wrong way round.
  const forged = Buffer.from("CRG_AAAA_AAAA").toString("base64");
  const { ctx } = await redact("x=1");
  const decision = classifyRestore({ ctx, text: forged, sink: { kind: "assistant_text" } });
  assert.equal(decision.text, forged, "a forged blob is delivered unchanged");
  assert.equal(decision.text.includes("CRG_AAAA_AAAA"), false, "and is not decoded into a token");
});

// ================================================= P6: parser failure independence =====

test("P6: a parser failure does not shut a detector down [RED]", async () => {
  // The invariant: coverage measures how well the STRUCTURE was understood, and says nothing
  // about whether a provider rule matched. A secret inside an unparseable line must still go.
  const malformed = [
    (s) => `password: "unterminated ${s}`,
    (s) => `weird: [ broken ${s}`,
    (s) => `\${{ malformed ${s}`,
    (s) => `key: {a: ${s}`,
    (s) => `- ? ${s}`,
    (s) => `password: |\n  ${s}\n  \t mixed`,
  ];
  const cases = generate({
    seed: DEFAULT_SEED + 22,
    count: 180,
    gen: (rng) => ({ shape: rng.pick(malformed), secret: rng.pick([PAT, AWS]) }),
  });

  let exercised = 0;
  for (let i = 0; i < cases.length; i++) {
    const { shape, secret } = cases[i];
    const text = shape(secret);
    const { ctx, out } = await redact(text);

    // Fixture sanity: the secret must actually be claimed by an independent detector, otherwise
    // the case proves nothing about parser independence.
    const spans = findSensitiveSpans(text, FLAGS);
    const claimed = spans.some((sp) => text.slice(sp.start, sp.end).includes(secret));
    if (!claimed) continue;

    assert.equal(out.includes(secret), false, `case ${i}: a parser failure suppressed a detector -> ${JSON.stringify(out)}\n  input: ${JSON.stringify(text)}`);
    assert.equal(ctx.restoreText(out), text, `case ${i}: round trip broke after a parser failure`);
    exercised++;
  }
  assert.ok(exercised > 40, `the property must actually be exercised: only ${exercised} claimed cases`);
});

test("P6: the malformed fixtures really are malformed [GREEN NOW]", async () => {
  // Fixture sanity for P6. If every "malformed" line parsed cleanly, the property above would be
  // testing ordinary inputs and calling it parser independence.
  const { ctx } = await redact("x=1");
  const coverage = ctx.coverage || [];
  void coverage;
  // An unterminated quote must not have its secret treated as a normal assignment value.
  const text = `password: "unterminated ${PAT}`;
  const spans = findSensitiveSpans(text, FLAGS);
  const binding = spans.find((sp) => sp.type === "binding");
  assert.equal(binding, undefined, "the assignment must NOT be parsed as a binding");

  // ...yet the provider detector still fires, which is the point of P6.
  const provider = spans.find((sp) => sp.type === "gitleaks");
  assert.ok(provider, "the provider detector must fire regardless");
});

// ============================================== P7: AMBIGUOUS cannot be exempted ========

test("P7: certainty x profile x detector matrix [RED]", async () => {
  // The middle cell had no coverage: a SOFT/AMBIGUOUS infrastructure value under a profile that
  // asks to PRESERVE it must still be redacted. Driven directly through decideSpanAction, since
  // the question is a policy question and an E2E would only sample it.
  const ambiguous = [
    ["bare 40hex", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"],
    ["bare 32hex", "4bf92f3577b34da6a3ce929d0e0e4736"],
    ["bare 64hex", "7031c1b283388d2c2e09b57badb803c05ebed362dc88d84b480cc47f72a21097"],
  ];
  const verified = [
    ["commit sha", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", "commit "],
    ["oci digest", "sha256:7031c1b283388d2c2e09b57badb803c05ebed362dc88d84b480cc47f72a21097", null],
    ["ec2 id", "i-0a1b2c3d4e5f67890", null],
    ["aws arn", "arn:aws:iam::123456789012:role/eks-nodegroup-role", null],
  ];
  const profiles = [["default", DEFAULT_PROFILE], ["devops", DEVOPS_PROFILE]];

  for (const [label, value] of ambiguous) {
    const infra = recogniseInfra(value);
    assert.equal(infra?.certainty, INFRA_CERTAINTY.AMBIGUOUS, `${label}: fixture must be AMBIGUOUS`);
    for (const [pname, profile] of profiles) {
      for (const detector of ["entropy", "gitleaks"]) {
        const d = decideSpanAction({ detector, ruleId: null, infra, profile });
        assert.equal(d.action, "redact", `${label} + ${pname} + ${detector}: AMBIGUOUS must not be exempted (reason=${d.reason})`);
      }
    }
  }

  // The expectation is READ FROM THE PROFILE rather than written into the test. A first version
  // asserted "DEFAULT redacts every verified value", which is false: DEFAULT_PROFILE itself
  // preserves GIT_SHA and OCI_DIGEST. Hard-coding the matrix here would have made the test a
  // second, drifting copy of the policy instead of a check on it.
  for (const [label, value, context] of verified) {
    const infra = recogniseInfra(value, context);
    assert.equal(infra?.certainty, INFRA_CERTAINTY.VERIFIED, `${label}: fixture must be VERIFIED`);
    for (const [pname, profile] of profiles) {
      const expected = profile[infra.infraType] === INFRA_DISPOSITION.PRESERVE ? "preserve" : "redact";
      const d = decideSpanAction({ detector: "entropy", ruleId: null, infra, profile });
      assert.equal(
        d.action, expected,
        `${label} + ${pname}: the profile says ${profile[infra.infraType]}, so the action must be ${expected} (got ${d.action}, reason=${d.reason})`
      );
    }
    // At least one profile must be willing to preserve it, or the "VERIFIED may preserve" half of
    // the matrix is not actually exercised by these fixtures.
    assert.ok(
      profiles.some(([, profile]) => decideSpanAction({ detector: "entropy", ruleId: null, infra, profile }).action === "preserve"),
      `${label}: no profile preserves this value, so the fixture does not exercise the cell`
    );
  }

  // HARD wins over VERIFIED, in every profile.
  for (const [label, value, context] of verified) {
    const infra = recogniseInfra(value, context);
    for (const [pname, profile] of profiles) {
      const d = decideSpanAction({ detector: "gitleaks", ruleId: "x", infra, profile });
      assert.equal(d.action, "redact", `${label} + ${pname}: a hard secret is never released (reason=${d.reason})`);
      assert.equal(d.hardSecret, true, `${label} + ${pname}: and is reported as hard`);
    }
  }
});

test("P7: AMBIGUOUS x preserve profile stays redacted end to end [RED]", async () => {
  // The same middle cell observed through a real redaction, so the matrix above cannot pass by
  // being disconnected from the pipeline.
  const bare = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
  const { out } = await redact(`blob: ${bare}`, { profile: DEVOPS_PROFILE }, { highEntropy: true });
  assert.equal(out.includes(bare), false, `an AMBIGUOUS value must not ride a preserve profile -> ${JSON.stringify(out)}`);
});

// ================================================ P8: bytes outside the span are fixed ===

test("P8: only the selected span is rewritten [RED]", async () => {
  // The strongest form available without new production surface: the output is RECONSTRUCTED
  // from the input by replacing exactly the spans findSensitiveSpans reported. If any other byte
  // moved -- a swallowed comment, a consumed quote, an offset shift, a half-built token -- the
  // reconstruction cannot match.
  const wraps = [
    (t) => t,
    (t) => `"${t}"`,
    (t) => `'${t}'`,
    (t) => `${t}  # rotate quarterly`,
    (t) => `> ${t}`,
    (t) => `- ${t}`,
    (t) => `${t},`,
    (t) => `x: ${t}`,
    (t) => `x=${t}`,
    (t) => `\t${t}`,
    (t) => `  ${t}  `,
    (t) => `before ${t} after`,
  ];
  const cases = generate({
    seed: DEFAULT_SEED + 23,
    count: 240,
    gen: (rng) => ({
      wrap: rng.pick(wraps),
      secret: rng.pick(SECRETS),
      suffix: rng.pick(["", "\n", "\nnext=value", "  ", "\t"]),
    }),
  });

  let exercised = 0;
  for (let i = 0; i < cases.length; i++) {
    const { wrap, secret, suffix } = cases[i];
    const text = wrap(`DB_PASSWORD=${secret}`) + suffix;
    const { ctx, out } = await redact(text);
    const spans = findSensitiveSpans(text, FLAGS);
    if (spans.length === 0) continue;

    // Rebuild from the input, replacing each span with the token the context minted for it, in
    // order of appearance.
    const ordered = [...spans].sort((a, b) => a.start - b.start);
    const tokens = [];
    for (const span of ordered) {
      const value = text.slice(span.start, span.end);
      tokens.push(ctx.rawToToken.get(value) ?? null);
    }
    let rebuilt = "";
    let cursor = 0;
    for (let k = 0; k < ordered.length; k++) {
      rebuilt += text.slice(cursor, ordered[k].start);
      rebuilt += tokens[k] ?? text.slice(ordered[k].start, ordered[k].end);
      cursor = ordered[k].end;
    }
    rebuilt += text.slice(cursor);

    assert.equal(out, rebuilt, `case ${i}: bytes outside the selected spans changed\n  input:   ${JSON.stringify(text)}\n  output:  ${JSON.stringify(out)}\n  rebuilt: ${JSON.stringify(rebuilt)}`);

    // Spelled out as well, because it is the property's headline: prefix and suffix are intact.
    const first = ordered[0];
    const last = ordered[ordered.length - 1];
    assert.equal(out.slice(0, first.start), text.slice(0, first.start), `case ${i}: prefix changed`);
    assert.equal(out.slice(out.length - (text.length - last.end)), text.slice(last.end), `case ${i}: suffix changed`);
    exercised++;
  }
  assert.ok(exercised > 80, `the property must actually be exercised: only ${exercised}`);
});

test("P8: the span never covers surrounding punctuation [RED]", async () => {
  // A direct reading of the same invariant at the boundary: a quote, a comma, a comment marker
  // or whitespace adjacent to the secret must not be inside the span, or the replacement eats it.
  const cases = generate({
    seed: DEFAULT_SEED + 24,
    count: 180,
    gen: (rng) => ({
      prefix: rng.pick(["", '"', "'", "x=", "x: ", "- ", "> ", "\t", "  "]),
      secret: rng.pick(SECRETS),
      suffix: rng.pick(["", '"', "'", ",", "  # note", "\n", " ;"]),
    }),
  });
  let exercised = 0;
  for (let i = 0; i < cases.length; i++) {
    const { prefix, secret, suffix } = cases[i];
    const text = `${prefix}${secret}${suffix}`;
    const spans = findSensitiveSpans(text, FLAGS);
    if (spans.length === 0) continue;
    for (const span of spans) {
      const covered = text.slice(span.start, span.end);
      assert.equal(
        covered.endsWith(" ") || covered.endsWith('"') || covered.endsWith("'") || covered.endsWith(",") || covered.endsWith("#") || covered.endsWith(";"),
        false,
        `case ${i}: the span swallowed trailing punctuation: ${JSON.stringify(covered)} in ${JSON.stringify(text)}`
      );
      assert.equal(
        covered.startsWith(" ") || covered.startsWith('"') || covered.startsWith("'") || covered.startsWith("\t"),
        false,
        `case ${i}: the span swallowed leading punctuation: ${JSON.stringify(covered)} in ${JSON.stringify(text)}`
      );
    }
    exercised++;
  }
  assert.ok(exercised > 60, `the property must actually be exercised: only ${exercised}`);
});

// ------------------------------------------------------------------ ledger sanity -------

test("R1.2: the surrogate ledger exposes an exact mapping only [GREEN NOW]", () => {
  // The safety argument behind P5 and R1.1 rests on this: the ledger answers exact lookups and
  // nothing else, so admitting surrogates into ownership is not a shape-based admission.
  const ledger = new SurrogateLedger();
  assert.equal(typeof ledger.lookup, "function");
  assert.equal(ledger.lookup("anything"), null, "an unknown value has no entry");
  assert.equal(ledger.lookup(Buffer.from("CRG_AAAA_AAAA").toString("base64")), null, "and a forged blob has none either");
});
