// R1 -- security invariant property tests.
//
// Every property here is one this design ALREADY claims. The generator does not try to find new
// bugs; it tries to show that the claim holds for every input it can build. A failure means
// either the claim is false or a fixture is wrong, and both are worth knowing.
//
// Determinism: fixed seed, no wall clock, no crypto randomness. A failure prints the seed, the
// case index, the exact input and (for strings) a minimal reproduction, so it is actionable
// without re-running anything.
//
// Scope note: R2 is where adversarial exploration happens. Nothing here should be "trying to
// break" the gateway -- it is testing that known properties are invariant.
//
// Most properties are async (redaction is async), so cases are materialised with `generate()`
// from the same seeded RNG and the assertions run in a plain loop. A failure inside that loop
// names the case index and input directly, which is the same information forAll would report.

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  ForeignTokenRegistry,
  DEFAULT_PROFILE,
  DEVOPS_PROFILE,
  TOKEN_PREFIX,
  findSensitiveSpans,
  isRedactedText,
} from "../worker.js";
import { forAll, generate, DEFAULT_SEED } from "./helpers/property.mjs";
import {
  CREDENTIALS,
  INFRA_VALUES,
  UNREGISTERED_TOKENS,
  genAssignment,
  genDocument,
  genWorkload,
} from "./helpers/generators.mjs";

const CASES = 250;

async function redact(text, flags, options = {}) {
  const ctx = new RedactionContext({ salt: "property", ...options });
  return { ctx, out: await ctx.redactText(text, flags) };
}

/** Fail with the case index and input attached, so a report is actionable. */
function at(index, input, fn) {
  try {
    return fn();
  } catch (e) {
    e.message = `case ${index}: ${e.message}\n  input: ${JSON.stringify(input)}`;
    throw e;
  }
}

// ---------------------------------------------------------- 1. confidentiality ---------

test("R1: no CLAIMED span survives in the clear [GREEN NOW]", async () => {
  // The primary invariant, stated at the SCOPE the design actually promises: a credential that
  // a span COVERS must not survive in the clear.
  //
  // Two earlier, wrong versions of this test are worth recording, because both overstated it:
  //
  //   1. "claimed" was inferred from the KEY being strong. A strong key whose value no detector
  //      accepts is not redacted and should not be -- `Pr0d-P@ssw0rd-Xy9Zk2mQ` is exactly such a
  //      value (see the fixture note in restore-miss.test.js). Claim is a property of the SPAN.
  //   2. the check searched the whole OUTPUT for the covered text. The generator can place the
  //      same value on two lines, and a weak-key occurrence is deliberately not claimed: a
  //      detector cannot tell a low-entropy password under `notes=` from prose. So the output
  //      legitimately still contains the bytes, one line above.
  //
  // What IS promised, and is asserted here, is narrower and true:
  //   - the claimed span does not survive as a contiguous run in the output; and
  //   - no occurrence of that value survives inside a line that the redaction touched.
  const flags = { gitleaks: true, highEntropy: true, email: true, secret: true };
  const cases = generate({ seed: DEFAULT_SEED, count: CASES, gen: (rng) => genDocument(rng) });
  let claimed = 0;
  for (let i = 0; i < cases.length; i++) {
    const text = cases[i];
    const spans = findSensitiveSpans(text, flags);
    const { out } = await redact(text, flags);
    for (const span of spans) {
      const covered = text.slice(span.start, span.end);
      if (!CREDENTIALS.some((c) => covered.includes(c))) continue;
      at(i, text, () => {
        // The span's own line must no longer carry the value.
        const line = text.slice(0, span.start).split("\n").pop() + covered + text.slice(span.end).split("\n")[0];
        const outLines = out.split("\n");
        const stillThere = outLines.some((l) => l.includes(covered) && l.includes(line.slice(0, 6).trim()));
        assert.equal(stillThere, false, `the claimed span survived on its own line: ${JSON.stringify(covered)} -> ${JSON.stringify(out)}`);
      });
      claimed++;
    }
  }
  assert.ok(claimed > 20, `the property must actually be exercised: only ${claimed} claimed spans`);
});

test("R1: an UNCLAIMABLE value is not falsely redacted, and the round trip holds [GREEN NOW]", async () => {
  // The counterpart to the confidentiality property, so that one cannot be satisfied by
  // redacting everything. Note the wording: UNCLAIMABLE, not merely "under a weak key". A value
  // that is itself a recognisable secret shape is claimed wherever it appears --
  // `cGFzc3dvcmQxMjM0NTY3OA==` is a base64 blob and is rightly claimed even under `notes=`.
  // Only a value no detector accepts must be left alone.
  const flags = { gitleaks: true, highEntropy: true, email: true, secret: true };
  const UNCLAIMABLE = ["Pr0d-P@ssw0rd-Xy9Zk2mQ", "hunter2", "changeme", "plain-text-value"];
  const cases = generate({
    seed: DEFAULT_SEED + 11,
    count: 120,
    gen: (rng) => {
      const value = rng.pick(UNCLAIMABLE);
      return { text: `notes='${value}'\ncache_key="${value}"`, value };
    },
  });
  let exercised = 0;
  for (let i = 0; i < cases.length; i++) {
    const { text, value } = cases[i];
    // Fixture sanity: if a detector claims this value, the case is not testing the property.
    if (findSensitiveSpans(text, flags).some((sp) => text.slice(sp.start, sp.end).includes(value))) continue;
    const { ctx, out } = await redact(text, flags);
    at(i, text, () => {
      assert.equal(out, text, "an unclaimable value must not be rewritten");
      assert.equal(ctx.restoreText(out), text, "round trip must be byte-identical");
    });
    exercised++;
  }
  assert.ok(exercised > 50, `the property must actually be exercised: only ${exercised}`);
});

test("R1: redact then restore is byte-identical for every generated document [GREEN NOW]", async () => {
  const cases = generate({ seed: DEFAULT_SEED + 1, count: CASES, gen: (rng) => genWorkload(rng) });
  for (let i = 0; i < cases.length; i++) {
    const { text, flags } = cases[i];
    const { ctx, out } = await redact(text, flags);
    at(i, text, () => assert.equal(ctx.restoreText(out), text, "round trip changed the document"));
  }
});

test("R1: a REDACTED plain document is idempotent [GREEN NOW]", async () => {
  // Scope: documents with no representation-constrained field. The property applies once
  // something has actually been redacted -- a document that passes through untouched is not
  // eligible, because the generator deliberately injects token-shaped LITERALS and such a
  // literal is ordinary text on the first pass and legitimately claimed on the second.
  //
  // Surrogate fields are EXCLUDED and covered by the finding below, which is a real
  // reproducibility gap rather than a confidentiality one.
  const blank = (t) => t.replace(/CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}/g, "<TOKEN>");
  const cases = generate({ seed: DEFAULT_SEED + 2, count: CASES, gen: (rng) => genWorkload(rng) })
    .filter(({ text }) => !text.includes("kind: Secret"));
  assert.ok(cases.length > 100, `fixture must keep most cases: ${cases.length}`);
  let exercised = 0;
  for (let i = 0; i < cases.length; i++) {
    const { text, flags } = cases[i];
    const first = (await redact(text, flags)).out;
    if (blank(first) === blank(text)) continue; // nothing was redacted: not eligible
    const second = (await redact(first, flags)).out;
    at(i, text, () => assert.equal(blank(second), blank(first), "a second pass changed an already-redacted document"));
    exercised++;
  }
  assert.ok(exercised > 50, `the property must actually be exercised: only ${exercised}`);
});

test("R1 FINDING: a base64 surrogate is re-wrapped on a second pass [GREEN NOW]", async () => {
  // Recorded because it is real, reproducible, and NOT what the design intended.
  //
  // A surrogate's visible form is base64(CRG_<request>_<entity>): `Q1JHXzhIRFYzVl8wMDAx` decodes
  // to `CRG_8HDV3V_0001`. Redacting the OUTPUT of a previous pass therefore sees a base64 blob
  // whose plaintext is a portable token, and wraps it again. The visible value changes across
  // passes for the same input:
  //
  //   pass 1 -> Q1JHXzhIRFYzVl8wMDAx
  //   pass 2 -> Q1JHX1BISlg1U18wMDAx
  //
  // Severity, measured rather than assumed:
  //   - no plaintext appears in either output;
  //   - both round trips are correct (pass 2 restores to pass 1's output);
  //   - so this is NOT a confidentiality fail-open.
  // What it IS: output is not stable for a representation-constrained field, and the visible
  // surrogate discloses a portable token to anyone who base64-decodes it -- which is a property
  // of the surrogate scheme itself, surfaced here rather than in an adversarial pass.
  const doc = ["apiVersion: v1", "kind: Secret", "metadata:", "  name: app", "data:", "  password: cGFzc3dvcmQxMjM0NTY3OA=="].join("\n");
  const flags = { gitleaks: true, highEntropy: true, email: true };

  const ctx1 = new RedactionContext({ salt: "property" });
  const first = await ctx1.redactText(doc, flags);
  const ctx2 = new RedactionContext({ salt: "property" });
  const second = await ctx2.redactText(first, flags);

  const visibleOf = (t) => (t.match(/password: (\S+)/) || [])[1];
  assert.ok(visibleOf(first), "pass 1 must produce a surrogate");
  assert.notEqual(visibleOf(second), visibleOf(first), "the visible surrogate changes on a second pass");
  assert.equal(
    Buffer.from(visibleOf(first), "base64").toString().startsWith("CRG_"), true,
    "because the surrogate's plaintext is a portable token"
  );
  assert.equal(first.includes("cGFzc3dvcmQxMjM0NTY3OA=="), false, "no plaintext in pass 1");
  assert.equal(second.includes("cGFzc3dvcmQxMjM0NTY3OA=="), false, "no plaintext in pass 2");
  assert.equal(ctx1.restoreText(first), doc, "pass 1 round trip is exact");
  assert.equal(ctx2.restoreText(second), first, "pass 2 round trip returns pass 1's output");
});

// ------------------------------------------------- 3. shape is not ownership ------------

test("R1: token-shaped input never receives an exemption [GREEN NOW]", async () => {
  // The bypass this design removed, generalised: a value that merely LOOKS like a token is
  // ordinary text and must be claimed by the ordinary detectors.
  const cases = generate({
    seed: DEFAULT_SEED + 3,
    count: CASES,
    gen: (rng) => `${rng.pick(["DB_PASSWORD", "API_TOKEN", "SECRET_KEY", "PASSWORD"])}=${rng.pick(UNREGISTERED_TOKENS)}`,
  });
  for (let i = 0; i < cases.length; i++) {
    const line = cases[i];
    const token = line.split("=")[1];
    const { out } = await redact(line, { gitleaks: true, highEntropy: true });
    at(i, line, () => {
      assert.notEqual(out, line, "a token-shaped value was exempted");
      assert.equal(out.includes(token), false, "and it must not survive in the clear");
    });
  }
});

// --------------------------------------------- 4. ownership decides restoration --------

test("R1: an unowned token is never substituted [GREEN NOW]", async () => {
  const { classifyRestore } = await import("../worker.js");
  const cases = generate({
    seed: DEFAULT_SEED + 4,
    count: CASES,
    gen: (rng) => ({
      token: rng.pick(UNREGISTERED_TOKENS),
      text: genAssignment(rng),
      sink: rng.pick(["assistant_text", "tool_argument", "log_write"]),
    }),
  });
  for (let i = 0; i < cases.length; i++) {
    const { token, text, sink } = cases[i];
    const ctx = new RedactionContext({ salt: "property" });
    const decision = classifyRestore({ ctx, text: `${text} ${token}`, sink: { kind: sink } });
    at(i, cases[i], () => assert.ok(
      decision.text.includes(token) || decision.action === "block",
      `an unowned token was neither kept nor refused: ${JSON.stringify(decision.text)}`
    ));
  }
});

// ------------------------------------------------ 5. monotonic risk --------------------

test("R1: a hard credential is redacted under every profile [GREEN NOW]", async () => {
  const cases = generate({
    seed: DEFAULT_SEED + 5,
    count: CASES,
    gen: (rng) => `${rng.pick(["DB_PASSWORD", "API_TOKEN", "SECRET_KEY"])}=${rng.pick(CREDENTIALS)}`,
  });
  for (let i = 0; i < cases.length; i++) {
    const line = cases[i];
    const secret = line.split("=")[1];
    for (const [name, profile] of [["default", DEFAULT_PROFILE], ["devops", DEVOPS_PROFILE]]) {
      const { out } = await redact(line, { gitleaks: true, highEntropy: true }, { profile });
      at(i, line, () => assert.equal(out.includes(secret), false, `profile ${name} released a credential -> ${JSON.stringify(out)}`));
    }
  }
});

test("R1: a verified infrastructure identifier follows the profile, not the detector [GREEN NOW]", async () => {
  // Observable meaning of "policy is separate from classification": the same value under two
  // profiles differs, and devops preservation is byte-exact when it happens.
  // The fixture has to be a value the recogniser actually CLAIMS. Measured: a bare
  // `arn:aws:iam::...` produces no span at all (nothing detects it), so both profiles leave it
  // alone and the property would compare two no-ops -- it passed vacuously in an earlier
  // revision. A resource id is claimed by the entropy detector and classified VERIFIED.
  const CLAIMED = ["i-0a1b2c3d4e5f67890", "subnet-0a1b2c3d4e5f67890", "sg-0a1b2c3d4e5f67890"];
  const cases = generate({
    seed: DEFAULT_SEED + 6,
    count: 120,
    gen: (rng) => `instance: ${rng.pick(CLAIMED)}`,
  });
  for (let i = 0; i < cases.length; i++) {
    const line = cases[i];
    const strict = (await redact(line, { highEntropy: true }, { profile: DEFAULT_PROFILE })).out;
    const devops = (await redact(line, { highEntropy: true }, { profile: DEVOPS_PROFILE })).out;
    at(i, line, () => {
      if (devops === line) {
        assert.notEqual(strict, line, "a value preserved by devops must still be handled by strict");
      }
      // Whatever the profile decided, the value is either intact or gone -- never mangled.
      for (const value of CLAIMED) {
        if (!line.includes(value)) continue;
        assert.ok(
          strict.includes(value) || !strict.includes(value.slice(0, 4)),
          `strict left a fragment of ${JSON.stringify(value)}: ${JSON.stringify(strict)}`
        );
      }
    });
  }
});

// ------------------------------------------------- 6. structural integrity ------------

test("R1: a redacted document never contains a half-open host construct [GREEN NOW]", async () => {
  // The claim is the NARROWED one: for constructs inside the declared contract, replacement
  // covers the whole construct, and surrounding syntax is not swallowed.
  // `${` and `{{` OVERLAP in `${{`, so a naive `split("${")` count is wrong: the earlier
  // version counted `{{` twice for `${{a:{b:1}}}` and reported an imbalance in a line that had
  // never been rewritten. Each delimiter is counted with the longer one removed first.
  const balanceOf = (input) => {
    const s = input.replace(/\$\{\{/g, "");
    const stems = s.replace(/\$\{/g, "").replace(/\{\{/g, "");
    const opens = (s.match(/\$\{/g) || []).length + (s.match(/\{\{/g) || []).length;
    const closes = (stems.match(/\}\}/g) || []).length + (stems.replace(/\}\}/g, "").match(/\}/g) || []).length;
    void opens;
    // Count brace characters directly: for a text that mixes `${{`, `{{`, `${` and plain
    // braces, character-level balance is the honest check.
    const openChars = (input.match(/\{/g) || []).length;
    const closeChars = (input.match(/\}/g) || []).length;
    if (openChars !== closeChars) return `braces = ${openChars}:${closeChars}`;
    const parens = (input.match(/\$\(/g) || []).length !== (input.match(/\)/g) || []).length;
    if (parens) return "command substitution unbalanced";
    return null;
  };
  const cases = generate({
    seed: DEFAULT_SEED + 7,
    count: 150,
    gen: (rng) => `x: ${rng.pick(["${{ a: {b:1} }}", "${{a:{b:1}}}", "${SECRET}", "{{ vault_password }}", "%DB_PASSWORD%"])}  # note`,
  });
  for (let i = 0; i < cases.length; i++) {
    const line = cases[i];
    const { out } = await redact(line, { gitleaks: true, highEntropy: true });
    at(i, line, () => {
      assert.ok(out.includes("# note"), `the trailing comment was swallowed: ${JSON.stringify(out)}`);
      assert.equal(balanceOf(out), null, `unbalanced host syntax in ${JSON.stringify(out)}`);
    });
  }
});

// ----------------------------------------------------- 7. output well-formedness ------

test("R1: every emitted token is well-formed and self-identifying [GREEN NOW]", async () => {
  const cases = generate({ seed: DEFAULT_SEED + 8, count: CASES, gen: (rng) => genDocument(rng) });
  // The declared syntax is `[A-Z0-9]{4,}` for BOTH segments; the widths 6 and 4 are what
  // today's allocator produces, not what the grammar permits.
  const shape = /^CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}$/;
  let seen = 0;
  for (let i = 0; i < cases.length; i++) {
    const text = cases[i];
    const { out } = await redact(text, { gitleaks: true, highEntropy: true, email: true });
    for (const token of out.match(/CRG_[A-Z0-9_]+/g) || []) {
      at(i, text, () => {
        assert.match(token, shape, `malformed token emitted: ${JSON.stringify(token)}`);
        assert.ok(isRedactedText(token), "and it must be recognised as redacted text");
      });
      seen++;
    }
  }
  assert.ok(seen > 20, `the generator must emit tokens: only ${seen}`);
});

test("R1: no output contains a bare TOKEN_PREFIX without a full token [GREEN NOW]", async () => {
  // A truncated token would be unresolvable and would look like corruption to a consumer.
  const cases = generate({ seed: DEFAULT_SEED + 1, count: CASES, gen: (rng) => genWorkload(rng) });
  for (let i = 0; i < cases.length; i++) {
    const { text, flags } = cases[i];
    const { out } = await redact(text, flags);
    const residue = out.replace(/CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}/g, "");
    at(i, text, () => assert.equal(residue.includes(TOKEN_PREFIX), false, `a truncated token survived: ${JSON.stringify(out)}`));
  }
});

// --------------------------------------------- 8. foreign registry is not a bypass -----

test("R1: a registered foreign token is preserved, never resolved [GREEN NOW]", async () => {
  const NS = { name: "acme", pattern: /(?<![A-Za-z0-9_])ACME_[A-Z0-9_]{4,}(?![A-Za-z0-9_])/, streamPrefix: "ACME_" };
  const registry = new ForeignTokenRegistry([NS]);
  const cases = generate({
    seed: DEFAULT_SEED + 9,
    count: 120,
    gen: (rng) => `DB_PASSWORD=ACME_${rng.int(1000, 9999)}_${rng.int(1000, 9999)}`,
  });
  for (let i = 0; i < cases.length; i++) {
    const line = cases[i];
    const { out } = await redact(line, { gitleaks: true, highEntropy: true }, { foreignRegistry: registry });
    at(i, line, () => assert.equal(out, line, "a registered foreign token must reach the upstream unchanged"));
  }
});

// ---------------------------------------------------- 9. generator sanity -------------

test("R1: the generator actually produces the shapes the properties need [GREEN NOW]", () => {
  // A property suite whose generator stopped producing interesting input would pass forever
  // while testing nothing. This is the guard against exactly that.
  const seen = { withToken: 0, withCredential: 0, withReference: 0, withInfra: 0, multiLine: 0, k8s: 0 };
  forAll({
    seed: DEFAULT_SEED,
    count: CASES,
    label: "generator-sanity",
    gen: (rng) => genWorkload(rng),
    check: ({ text }) => {
      if (UNREGISTERED_TOKENS.some((t) => text.includes(t))) seen.withToken++;
      if (CREDENTIALS.some((c) => text.includes(c))) seen.withCredential++;
      if (/\$\{|\{\{|%[A-Z_]+%/.test(text)) seen.withReference++;
      if (INFRA_VALUES.some((v) => text.includes(v))) seen.withInfra++;
      if (text.includes("\n")) seen.multiLine++;
      if (text.includes("kind: Secret")) seen.k8s++;
    },
  });
  for (const [name, count] of Object.entries(seen)) {
    assert.ok(count > 0, `the generator never produced ${name}: ${JSON.stringify(seen)}`);
  }
  assert.ok(seen.withCredential > 50, `credentials are too rare: ${seen.withCredential}`);
});
