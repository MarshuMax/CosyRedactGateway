// R0.1 -- structural / reference envelope closure.
//
// The parser identifies a reference value such as `{{ ... }}` or `${ ... }`, records
// `reference_value` as evidence, and the binding candidate is then filtered out. The inner
// detectors still run, so a detector hit INSIDE the reference produced a span covering only
// that fragment -- the reference syntax around it was left behind:
//
//   DB_PASSWORD={{Redact:<64 hex>}}
//   ->  DB_PASSWORD={{Redact:CRG_...
//
// The rule this file fixes: a parser boundary is not a verdict, but it IS a boundary.
//
//   reference with no detector hit     -> unchanged (it is an indirection, not a secret)
//   reference with a detector hit      -> the WHOLE reference is the mutation boundary,
//                                         with the inner detector's attribution preserved
//
// Nothing here is specific to `{{Redact:`: that string is simply a `{{ ... }}` reference
// whose body happens to contain a 64-hex run.
//
// Assertion tags:
//   [GREEN NOW]  passes against the current tree
//   [RED]        specifies the target

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  referenceEnvelopes,
  recogniseInfra,
  findSensitiveSpans,
  parseBindings,
  parseYamlBindings,
  bindingSpansOf,
} from "../worker.js";

const ALL = { gitleaks: true, highEntropy: true, email: true, phone: true, secret: true, identity: true, bank: true };
const PAT = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
const HEX64 = "a1b2c3d4".repeat(8);

async function redact(text, options = {}) {
  const ctx = new RedactionContext({ salt: "fixture", ...options });
  const out = await ctx.redactText(text, ALL);
  return { ctx, out };
}

// ------------------------------------------------- 1. pure reference is untouched ----

test("R0.1: a reference with no detector hit is unchanged [RED]", async () => {
  const pure = [
    "DB_PASSWORD=\${SECRET}",
    "DB_PASSWORD=${{ secrets.DB_PASSWORD }}",
    "DB_PASSWORD={{ vault_password }}",
    "DB_PASSWORD=%DB_PASSWORD%",
    "DB_PASSWORD=<DB_PASSWORD>",
    "DB_PASSWORD={db_password}",
  ];
  for (const line of pure) {
    const { out } = await redact(line);
    assert.equal(out, line, `${line}: an indirection is not a secret`);
  }
});

test("R0.1.1 fixture sanity: the op:// sample has NO detector hit and stays unchanged [GREEN NOW]", async () => {
  // This sample previously carried a WRITTEN-DOWN attribution ("it is an INTERNAL_HOSTNAME
  // hit") that was never verified. It was wrong. The real chain, asserted here so it cannot
  // drift again:
  //
  //   findSensitiveSpans  -> []            (no detector hit at all)
  //   recogniseInfra      -> null          (op://… is not a dotted hostname ending in
  //                                         .internal/.local/.svc, so the recogniser
  //                                         correctly declines it)
  //   action              -> none          (nothing to act on)
  //
  // The redaction that used to happen had a different cause entirely: the YAML parser split
  // the SHELL assignment on the `op:` of the URL, producing key=DB_PASSWORD with the value
  // `//vault/db/password)`. A strong key made that a binding span, so a REFERENCE to a secret
  // was redacted as if it were the secret. A `:` without following whitespace is not a
  // mapping separator, so the parser no longer claims the line.
  const line = "DB_PASSWORD=$(op read op://vault/db/password)";

  // The recogniser declines it, for the stated reason.
  assert.equal(recogniseInfra("op://vault/db/password"), null, "not a dotted internal hostname");
  assert.equal(recogniseInfra("//vault/db/password)"), null, "nor is the mis-split fragment");
  assert.equal(recogniseInfra("vault.db.local")?.infraType, "INTERNAL_HOSTNAME", "while a real one is recognised");

  // No detector produces a span, so nothing is redacted.
  assert.deepEqual(findSensitiveSpans(line, ALL), [], "no span, no action");

  // The YAML parser must not claim a shell assignment.
  assert.equal(parseYamlBindings(line).length, 0, "a shell assignment is not a YAML mapping");
  assert.equal(bindingSpansOf(line, "binding", parseYamlBindings).length, 0);
  // The shell parser sees the reference and declines it, as designed.
  const shell = parseBindings(line);
  assert.equal(shell.length, 1, "the assignment is recognised structurally");
  assert.ok(shell[0].evidence.includes("reference_value"), "and marked as a reference");
  assert.equal(bindingSpansOf(line, "binding", parseBindings).length, 0, "so it is not a candidate");

  // End to end: a secret REFERENCE is not secret PLAINTEXT.
  const { out } = await redact(line);
  assert.equal(out, line, "unchanged");

  // ...but a compact mapping with the same shape IS a mapping, and is still caught.
  const realMapping = "DB_PASSWORD: op://vault/db/password";
  const yamlRecords = parseYamlBindings(realMapping);
  assert.equal(yamlRecords.length, 1, "whitespace after the colon makes it a mapping");
});

test("R0.1: a reference whose body holds a real credential is replaced whole [RED]", async () => {
  // The counterpart to the sample above: when the body DOES contain a hard detector hit, the
  // construct is the mutation boundary. `$( )` with content other than a bare reference is
  // not a pure reference either, so the binding still reaches the merge.
  const line = `DB_PASSWORD=$(printf ${PAT})`;
  const { out } = await redact(line);
  assert.equal(out.includes(PAT), false, "the credential goes");
  assert.equal(out.includes("$("), false, "and so does the construct");
  assert.equal(out.includes(")"), false, "no half-open command substitution");
  assert.match(out, /^DB_PASSWORD=\S+$/);
});

test("R0.1: a reference is still a reference inside a block scalar [GREEN NOW]", async () => {
  const doc = ["password: |", "  ${{ secrets.DB_PASSWORD }}"].join("\n");
  const { out } = await redact(doc);
  assert.equal(out, doc, "the template must survive");
});

// --------------------------------------- 2. inner hit widens to the whole reference ----

test("R0.1: a reference containing a hard detector is replaced WHOLE [RED]", async () => {
  const line = `token: "{{ wrapper ${PAT} }}"`;
  const { out } = await redact(line);
  assert.equal(out.includes(PAT), false, "the credential must go");
  // The whole value boundary is replaced, so no half-reference is left behind.
  for (const residue of ["{{", "}}", "wrapper"]) {
    assert.equal(out.includes(residue), false, `${residue} must not survive as residue`);
  }
  assert.match(out, /^token: \S+$/, "the key and delimiter survive, the value is one token");
});

test("R0.1: the reported regression, generically [RED]", async () => {
  // `{{Redact:<64 hex>}}` is a `{{ ... }}` reference whose body holds a 64-hex run. No rule
  // mentions the string `Redact`: the envelope is what decides the boundary.
  const line = `DB_PASSWORD={{Redact:${HEX64}}}`;
  const { out } = await redact(line);
  assert.equal(out.includes(HEX64), false, "the hex run is gone");
  assert.equal(out.includes("{{"), false, "and so is the opening syntax");
  assert.equal(out.includes("}}"), false, "and the closing syntax");
  assert.equal(out.includes("Redact"), false, "the whole reference went, not just its inside");
  assert.match(out, /^DB_PASSWORD=\S+$/, "key and delimiter survive");
});

test("R0.1: nested references widen to the outermost boundary [RED]", async () => {
  const line = `x: \${{ secrets.${PAT} }}`;
  const { out } = await redact(line);
  assert.equal(out.includes(PAT), false);
  assert.equal(out.includes("secrets."), false, "the outer reference is the boundary");
});

// --------------------------------------------- 3. policy is unchanged, only the box ----

test("R0.1: an entropy-only hit inside a reference stays redacted [RED]", async () => {
  const line = `blob: "{{ ${HEX64} }}"`;
  const { out } = await redact(line);
  assert.equal(out.includes(HEX64), false, "an entropy hit is still redacted by default");
  assert.equal(out.includes("{{"), false, "and the envelope is the unit of replacement");
});

test("R0.1: a devops-preserved infra value inside a reference is still preserved [RED]", async () => {
  // Envelope resolution decides the BOUNDARY; the profile still decides the action.
  const line = `commit: "{{ ${"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"} }}"`;
  const devops = await redact(line, { profile: undefined });
  void devops;
  const { DEVOPS_PROFILE } = await import("../worker.js");
  const { out } = await redact(line, { profile: DEVOPS_PROFILE });
  assert.equal(out, line, "a preserved value keeps its whole reference: nothing to rewrite");
});

// ------------------------------------- 4/6. syntax hygiene around the boundary -------

test("R0.1: a quote or comment around the value is not swallowed [RED]", async () => {
  const line = `token: "{{ ${PAT} }}"  # rotate quarterly`;
  const { out } = await redact(line);
  assert.ok(out.includes("# rotate quarterly"), "the trailing comment survives");
  assert.equal(out.includes(PAT), false, "the credential does not");
  const quoted = out.match(/^token: ("?)(\S+)\1/);
  assert.ok(quoted, `the quoting must stay balanced: ${out}`);
});

test("R0.1: no half-open host syntax survives [RED]", async () => {
  // The failure mode is a partially replaced construct: the opening delimiter is consumed
  // and the closing one is left, or the reverse. Both are checked on every example.
  const cases = [
    `a: "{{ ${PAT} }}"`,
    `a: \${${PAT}}`,
    `a: \$(${PAT})`,
    `a: "{{Redact:${HEX64}}}"`,
    `a: '%DB_PASSWORD%${PAT}'`,
  ];
  const openers = ["{{", "${", "$(", "%"];
  for (const line of cases) {
    const { out } = await redact(line);
    for (const opener of openers) {
      const opens = out.split(opener).length - 1;
      const closes = opener === "{{" ? out.split("}}").length - 1
        : opener === "${" ? out.split("}").length - 1
          : opener === "$(" ? out.split(")").length - 1
            : out.split("%").length - 1;
      assert.equal(
        opens === closes || opens === 0, true,
        `${line}: unbalanced ${opener} in ${out}`
      );
    }
  }
});

// ------------------------------------------------- 5. round trip stays byte-exact ----

test("R0.1: redact then restore is byte-identical [RED]", async () => {
  const cases = [
    `DB_PASSWORD={{Redact:${HEX64}}}`,
    "DB_PASSWORD=${{ secrets.DB_PASSWORD }}",
    `token: "{{ wrapper ${PAT} }}"`,
    `blob: "{{ ${HEX64} }}"`,
    `a: "{{ ${PAT} }}"  # note`,
  ];
  for (const line of cases) {
    const { ctx, out } = await redact(line);
    assert.equal(ctx.restoreText(out), line, `${line}: round trip must be byte-identical`);
  }
});

// ------------------------------------------------------------- envelope unit tests ----

test("R0.1: referenceEnvelopes finds the construct, not the whole line [GREEN NOW]", () => {
  const line = `token: "{{ ${PAT} }}"  # note`;
  const envelopes = referenceEnvelopes(line);
  assert.equal(envelopes.length, 1, "exactly one reference");
  const env = envelopes[0];
  assert.equal(line.slice(env.start, env.end), `{{ ${PAT} }}`, "the construct only, quotes excluded");

  // A line with no reference yields none.
  assert.deepEqual(referenceEnvelopes("token: plain-value"), []);
  // Two references are two envelopes.
  assert.equal(referenceEnvelopes("a: ${A} and ${B}").length, 2);
});

// ================================================ R0.1.2 scanner hardening ==========

test("R0.1.2: `%` needs a name-only body, so two prose percents do not form an envelope [RED]", async () => {
  // The scanner table declared `{ opener: "%", closer: "%", simple: true }` with NO
  // namePattern, and the simple branch only enforces `if (found.namePattern && ...)` -- so the
  // "simple forms require a name-only body" rule documented for `%` was not in force at all.
  // Two ordinary percent signs therefore opened a region spanning everything between them,
  // and a hard detector hit inside would have replaced the whole prose span.
  // The fixture must not itself contain a DIFFERENT valid construct, or it proves nothing
  // about `%`: an earlier version wrapped the credential in `<...>`, which is a legitimate
  // `<VAR>` reference and produced an envelope for that reason. The body between the two
  // percent signs here is ordinary prose with a bare credential.
  const prose = "50% CPU, token=ghp_16C7e42F292c6912E7710c838347Ae178B4a, 60% memory";
  assert.deepEqual(referenceEnvelopes(prose), [], "prose percents are not a reference construct");

  // Stated separately, because it is a real and benign consequence of `<VAR>` being a form:
  // `<ghp_...>` IS an envelope, so a credential wrapped that way is replaced with its wrapper.
  // The wrapper is harmless host syntax here, so the outcome is still correct.
  const angle = `50% CPU, <ghp_16C7e42F292c6912E7710c838347Ae178B4a>, 60% memory`;
  const angleEnv = referenceEnvelopes(angle);
  assert.equal(angleEnv.length, 1, "the `<...>` form is recognised");
  assert.equal(angle.slice(angleEnv[0].start, angleEnv[0].end), "<ghp_16C7e42F292c6912E7710c838347Ae178B4a>");

  // The construct itself is still recognised.
  assert.equal(referenceEnvelopes("%DB_PASSWORD%").length, 1, "a name-only body is a reference");

  // And the prose is left alone end to end, rather than the whole span being replaced.
  const { out } = await redact(prose);
  assert.ok(out.includes("50% CPU"), "the leading prose survives");
  assert.ok(out.includes("60% memory"), "and the trailing prose survives");
  assert.equal(out.includes("ghp_16C7e42F292c6912E7710c838347Ae178B4a"), false, "the credential goes");
});

test("R0.1.2: `${{ ... }}` counts inner braces, so the construct closes at the right place [RED]", async () => {
  // Only the SAME opener incremented depth, so a lone `{` inside `${{` was invisible and the
  // scan ended at the first `}}` it saw -- which is the inner object's brace plus the first
  // template brace. `${{ a: {b:1}}}` left an orphan `}` outside the envelope.
  const cases = [
    "${{ a: {b:1} }}",
    "${{ a: {b:1}}}",
    "${{a:{b:1}}}",
    "${{a:{b:{c:1}}}}",
  ];
  for (const construct of cases) {
    const line = `x: ${construct}`;
    const envelopes = referenceEnvelopes(line);
    assert.equal(envelopes.length, 1, `${construct}: exactly one envelope`);
    assert.equal(
      line.slice(envelopes[0].start, envelopes[0].end), construct,
      `${construct}: the envelope must cover the whole construct`
    );
  }
});

test("R0.1.2: an orphan brace never survives a replacement [RED]", async () => {
  // The end-to-end consequence of a short envelope: the host syntax is broken.
  const line = "x: ${{ a: {b:1}}}  # note";
  assert.equal(referenceEnvelopes(line)[0] && line.slice(referenceEnvelopes(line)[0].start, referenceEnvelopes(line)[0].end),
    "${{ a: {b:1}}}", "the envelope covers the construct");
  const { out } = await redact(line);
  // No detector hit, so the line is returned unchanged -- which is the point: a correctly
  // sized envelope means nothing is rewritten at all. The property to assert is BALANCE, not
  // the absence of `}`: the construct legitimately contains braces.
  assert.equal(out, line, "an untouched construct comes back byte-identical");
  const opens = out.split("{").length - 1;
  const closes = out.split("}").length - 1;
  assert.equal(opens, closes, `braces must stay balanced: ${out}`);
});

test("R0.1.2: nested braces with a credential inside are replaced whole [RED]", async () => {
  const line = `x: \${{ config: {token: "${"ghp_16C7e42F292c6912E7710c838347Ae178B4a"}"} }}`;
  const { out } = await redact(line);
  assert.equal(out.includes("ghp_16C7e42F292c6912E7710c838347Ae178B4a"), false, "the credential goes");
  assert.equal(out.includes("}"), false, "and the whole construct with it");
  assert.equal(out.includes("config:"), false, "no fragment of the construct survives");
});

test("R0.1.2: an unterminated construct is still not an envelope [GREEN NOW]", () => {
  // The scanner is a scanner, not a template parser: a construct that never closes is
  // ordinary text, and treating it as a boundary would widen a span over unrelated content.
  assert.deepEqual(referenceEnvelopes("x: ${{ a: {b:1}"), [], "no closer, no envelope");
  assert.deepEqual(referenceEnvelopes("x: ${a"), [], "no closer, no envelope");
  assert.deepEqual(referenceEnvelopes("x: %NAME"), [], "no closer, no envelope");
});

test("R0.1.2: the scanner balances BRACES, not string literals -- a stated limit [GREEN NOW]", () => {
  // Stated rather than papered over with a special case. The scan counts braces and delimiter
  // characters; it does not lex quoted strings, so a brace INSIDE a string literal closes the
  // construct early:
  //
  //   x: ${{ a: "}" }}   ->  envelope covers `${{ a: "}" }`, leaving one `}` outside
  //
  // Deciding this correctly needs a real lexical pass for whichever template language is in
  // play, and this scanner deliberately is not one. The contract is therefore:
  //
  //   A reference envelope is a BALANCED-BRACE construct. Braces inside quotes are not
  //   distinguished, so a construct containing an unbalanced brace in a string literal is
  //   NOT reliably recognised.
  //
  // The consequence is bounded and safe: a short envelope can only ever REDACT MORE (it
  // widens a span), never leak. What it can do is damage host syntax, which is why the limit
  // is recorded here and not silently tolerated.
  const line = 'x: ${{ a: "}" }}';
  const env = referenceEnvelopes(line);
  assert.equal(env.length, 1, "an envelope is still produced");
  assert.equal(line.slice(env[0].start, env[0].end), '${{ a: "}" }', "but it closes at the brace in the string");
  assert.notEqual(line.slice(env[0].start, env[0].end), line.slice(3), "which is one character short of the construct");

  // The forms that ARE in contract: every brace-position variant without a quoted brace.
  for (const construct of ["${{ a: {b:1} }}", "${{ a: {b:1}}}", "${{a:{b:1}}}", "${{a:{b:{c:1}}}}", "${{{{{a}}}}}"]) {
    const sample = `x: ${construct}`;
    const found = referenceEnvelopes(sample);
    assert.equal(found.length, 1, `${construct}: one envelope`);
    assert.equal(sample.slice(found[0].start, found[0].end), construct, `${construct}: covered exactly`);
  }
});
