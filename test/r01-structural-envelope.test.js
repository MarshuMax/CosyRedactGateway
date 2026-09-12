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
import { RedactionContext, referenceEnvelopes } from "../worker.js";

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

test("R0.1: a reference whose body a detector recognises is still replaced whole [RED]", async () => {
  // `op://vault/db/password` inside `$( )` is a real INTERNAL_HOSTNAME hit, so this is not a
  // pure reference: the rule is "no detector hit -> unchanged", and this one has a hit. It is
  // listed separately from the pure cases because conflating the two is how the boundary
  // gets confused with the verdict.
  const line = "DB_PASSWORD=$(op read op://vault/db/password)";
  const { out } = await redact(line);
  assert.equal(out.includes("op://vault/db/password"), false, "the recognised value goes");
  assert.equal(out.includes("$("), false, "and the construct goes with it");
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
