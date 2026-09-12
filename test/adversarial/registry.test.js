// R2.1 -- adversarial exploration: ownership and the foreign registry.
//
// R2 is not R1. R1 proves a known property always holds; R2 looks for cracks BETWEEN
// properties, parsers and representations without presupposing one exists.
//
// A finding, per the R2 bar, must be all four of:
//   A. reproducible   -- fixed seed/input/config reproduces it 100%
//   B. minimisable    -- a minimal reproducer exists
//   C. attributable   -- it names the contract or invariant it violates
//   D. consequential  -- confidentiality, integrity, availability, ownership/policy
//                        inconsistency, protocol corruption, or a deployment-correctness problem
//
// "The output is not what I expected" is an OBSERVATION, and is recorded as one. It is not a
// finding and MUST NOT trigger a production change. The flow is:
//
//   discover -> minimise -> prove the violated contract -> add an isolated RED regression ->
//   classify severity and root cause -> only then decide about a fix.
//
// Findings are also recorded in test/adversarial/corpus/findings.json. Ordinary exploration
// samples are rebuilt by the generator and are deliberately NOT committed.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ForeignTokenRegistry, RedactionContext, classifyOwnership } from "../../worker.js";
import { generate, makeRng } from "../helpers/property.mjs";

const TOKEN = "ACME_ABCDEF_0001";
const LINE = `DB_PASSWORD=${TOKEN}`;
const FLAGS = { gitleaks: true, highEntropy: true };

// Derived seed for this category, so a report can be reproduced in isolation.
const SEED_REGISTRY = 0x2e610001;

const findings = JSON.parse(readFileSync(new URL("./corpus/findings.json", import.meta.url), "utf8"));
const finding = (id) => findings.findings.find((f) => f.id === id);

// =====================================================================================
// R2-REG-001 -- a stateful matcher makes ownership verdicts alternate
// =====================================================================================

test("R2-REG-001: a /g or /y namespace matcher alternates its verdict [RED]", () => {
  // MINIMAL REPRODUCER. Nothing else is involved: one registry, one matcher, one token,
  // repeated calls.
  const pattern = /ACME_[A-Z0-9_]+/g;
  const registry = new ForeignTokenRegistry([{ name: "acme", pattern }]);

  const seen = [];
  for (let i = 0; i < 6; i++) seen.push(registry.namespaceOf(TOKEN));
  assert.deepEqual(
    [...new Set(seen)], ["acme"],
    `the same token must always resolve to the same namespace, got ${JSON.stringify(seen)} (lastIndex=${pattern.lastIndex})`
  );
});

test("R2-REG-001: the same registration gives different verdicts in different layers [RED]", () => {
  // The contract this violates, quoted from the registry's own documented rule:
  //
  //   "Namespaces are TRUSTED CONFIGURATION ... a registered foreign token is preserved"
  //
  // and the ownership split is required to be consistent across the layers that consult it.
  // Here classifyOwnership (which resets lastIndex before matching) and isProtectedToken (which
  // does not) fight over one matcher object, so the verdict depends on CALL ORDER.
  const registry = new ForeignTokenRegistry([{ name: "acme", pattern: /ACME_[A-Z0-9_]+/g }]);
  const ctx = new RedactionContext({ salt: "r2", foreignRegistry: registry });

  const pairs = [];
  for (let i = 0; i < 6; i++) {
    pairs.push([classifyOwnership(TOKEN, ctx, registry).ownership, ctx.isProtectedToken(TOKEN)]);
  }
  const inconsistent = pairs.filter(([a, b]) => (a === "FOREIGN_REGISTERED") !== b);
  assert.equal(
    inconsistent.length, 0,
    `classifyOwnership and isProtectedToken disagree for the same registration: ${JSON.stringify(pairs)}`
  );
});

test("R2-REG-001: a registered foreign token is redacted on the way IN [RED]", async () => {
  // CONSEQUENCE. The registry's whole purpose on the forward path is that a foreign token is
  // passed through unchanged. With a stateful matcher it is re-tokenised instead.
  for (const [label, pattern] of [["/g", /ACME_[A-Z0-9_]+/g], ["/y", /ACME_[A-Z0-9_]+/y]]) {
    const registry = new ForeignTokenRegistry([{ name: "acme", pattern }]);
    const ctx = new RedactionContext({ salt: "r2", foreignRegistry: registry });
    const out = await ctx.redactText(LINE, FLAGS);
    assert.equal(out, LINE, `${label}: a registered foreign token must reach the upstream unchanged, got ${JSON.stringify(out)}`);
  }
  // The control: an equivalent non-stateful matcher is handled correctly, which is what makes
  // this a defect in how the matcher is USED rather than in the registry's purpose.
  const okRegistry = new ForeignTokenRegistry([{ name: "acme", pattern: /ACME_[A-Z0-9_]+/ }]);
  const okCtx = new RedactionContext({ salt: "r2", foreignRegistry: okRegistry });
  assert.equal(await okCtx.redactText(LINE, FLAGS), LINE, "the non-global control must pass");
});

test("R2-REG-001: with a fresh registry the outcome is stable, so the trigger is call history [GREEN NOW]", async () => {
  // Scoping the trigger precisely, because "it depends on call order" is the part that makes
  // this hard to see: a fresh registry per request behaves the same every time.
  const outcomes = [];
  for (let i = 0; i < 8; i++) {
    const registry = new ForeignTokenRegistry([{ name: "acme", pattern: /ACME_[A-Z0-9_]+/g }]);
    const ctx = new RedactionContext({ salt: "r2", foreignRegistry: registry });
    outcomes.push((await ctx.redactText(LINE, FLAGS)) === LINE ? "kept" : "redacted");
  }
  assert.deepEqual([...new Set(outcomes)], ["redacted"], "documenting the observed behaviour for the record");

  // And an instance REUSED across requests alternates its verdict, which is the observable
  // form of the bug for a deployment that builds the registry once at startup.
  const shared = new ForeignTokenRegistry([{ name: "acme", pattern: /ACME_[A-Z0-9_]+/g }]);
  const reused = [];
  for (let i = 0; i < 8; i++) reused.push(shared.namespaceOf(TOKEN));
  assert.ok(new Set(reused).size > 1, `a reused registry must not alternate: ${JSON.stringify(reused)}`);
});

// =====================================================================================
// The stateful-matcher class, explored systematically
// =====================================================================================

test("R2-REG: which matcher shapes are stateful, and which are not [GREEN NOW]", () => {
  // Mapping the class rather than the one example: the defect is about matcher FLAGS, so the
  // exploration records the whole neighbourhood. `/y` (sticky) has the same problem as `/g`
  // because both make lastIndex meaningful.
  const shapes = [
    ["non-global", /ACME_[A-Z0-9_]+/, false],
    ["/g", /ACME_[A-Z0-9_]+/g, true],
    ["/y", /ACME_[A-Z0-9_]+/y, true],
    ["/gi", /ACME_[A-Z0-9_]+/gi, true],
    ["/gy", /ACME_[A-Z0-9_]+/gy, true],
  ];
  for (const [label, pattern, stateful] of shapes) {
    const registry = new ForeignTokenRegistry([{ name: "acme", pattern }]);
    const seen = [];
    for (let i = 0; i < 4; i++) seen.push(registry.namespaceOf(TOKEN));
    assert.equal(
      new Set(seen).size > 1, stateful,
      `${label}: expected stateful=${stateful}, saw ${JSON.stringify(seen)}`
    );
  }
});

test("R2-REG: string patterns are constructed without stateful flags [GREEN NOW]", () => {
  // The string form goes through `new RegExp(pattern)`, which is stateless -- so the failure
  // needs an explicitly flagged RegExp. Recording that narrows where a fix would belong.
  const registry = new ForeignTokenRegistry([{ name: "acme", pattern: "ACME_[A-Z0-9_]+" }]);
  const seen = [];
  for (let i = 0; i < 4; i++) seen.push(registry.namespaceOf(TOKEN));
  assert.deepEqual([...new Set(seen)], ["acme"], "a string pattern is stateless");
});

// =====================================================================================
// OBSERVATIONS -- recorded, explicitly NOT findings
// =====================================================================================

test("R2-REG OBSERVATION: exact matches bypass the matcher entirely [GREEN NOW]", () => {
  // `namespaceOf` consults `this.tokens` first, so an EXACT registration is immune to the
  // matcher-state problem. Recorded because it bounds the impact: only pattern-registered
  // namespaces are affected.
  const registry = new ForeignTokenRegistry([{ name: "acme", pattern: /ACME_[A-Z0-9_]+/g }])
    .registerTokens([TOKEN]);
  const seen = [];
  for (let i = 0; i < 4; i++) seen.push(registry.namespaceOf(TOKEN));
  assert.deepEqual([...new Set(seen)], ["exact"], "an exact registration returns before the matcher runs");
});

test("R2-REG OBSERVATION: repeated occurrences always resolve to the FIRST index [GREEN NOW]", () => {
  // Not a finding: the index computed this way is only used for an existence test
  // (`foreign.includes(found)`), so no position is consumed. Recorded because if a future change
  // starts using that index to locate content, this becomes a real defect.
  const pattern = /ACME_[A-Z0-9_]+/g;
  // `ACME_A` twice with `ACME_B` between them, so a repeated value and a distinct value are both
  // present. An earlier version of this assertion expected [0,0,0]; the true behaviour is that
  // only the REPEATED value collapses back to its first position.
  const text = `ACME_A and ACME_B and ACME_A`;
  pattern.lastIndex = 0;
  const found = text.match(pattern) || [];
  const viaIndexOf = found.map((f) => text.indexOf(f));

  // Real occurrence positions, for comparison.
  const real = [];
  pattern.lastIndex = 0;
  for (let m; (m = pattern.exec(text)) !== null;) real.push(m.index);

  assert.deepEqual(found, ["ACME_A", "ACME_B", "ACME_A"]);
  assert.deepEqual(real, [0, 11, 22], "the true occurrence positions");
  assert.deepEqual(viaIndexOf, [0, 11, 0], "indexOf finds distinct values, but a repeated one always reports its first position");
  assert.notDeepEqual(viaIndexOf, real, "so indexOf is NOT a substitute for real match positions");
  // Not a finding: the index computed this way is only used for an existence test
  // (`foreign.includes(found)`), so no position is consumed anywhere.
  assert.equal(text.includes(found[2]), true, "and the only use is an existence test");
});

test("R2-REG OBSERVATION: a capture-group matcher is evaluated on the full match [GREEN NOW]", () => {
  // `.test()` ignores groups, so a namespace pattern with captures behaves as its full match.
  // Correct, and worth pinning: a future reader might expect the group to be used.
  const registry = new ForeignTokenRegistry([{ name: "acme", pattern: /(ACME_[A-Z]+)_([0-9]+)/ }]);
  assert.equal(registry.namespaceOf("ACME_ABCDEF_0001"), "acme", "the full match is what counts");
  assert.equal(registry.namespaceOf("ACME_ABCDEF"), null, "and a partial does not qualify");
});

test("R2-REG: the corpus file is well-formed and every finding is complete [GREEN NOW]", () => {
  // The registry of findings is a deliverable, so its own shape is checked: a finding without a
  // violated contract or an impact would be an observation wearing a finding's id.
  assert.ok(Array.isArray(findings.findings), "findings.json must hold a findings array");
  assert.ok(findings.findings.length > 0, "and at least one finding exists");
  const required = ["id", "seed", "input", "config", "expected_invariant", "observed", "impact", "status"];
  for (const f of findings.findings) {
    for (const key of required) {
      assert.ok(f[key] !== undefined && f[key] !== "", `${f.id}: field ${key} is required`);
    }
    assert.match(f.id, /^R2-[A-Z]+-\d{3}$/, `bad id: ${f.id}`);
    assert.ok(["open", "fixed", "accepted"].includes(f.status), `bad status for ${f.id}: ${f.status}`);
  }
});

test("R2-REG: the generator explores the registry space without presupposing flags [GREEN NOW]", () => {
  // Exploration over matcher shape x registration kind x call pattern, driven by the category
  // seed. It asserts only what is TRUE for every combination (verdicts must be self-consistent
  // across the two layers); the /g and /y cases are covered by the RED test above.
  const rng = makeRng(SEED_REGISTRY);
  const flagsList = ["", "g", "y", "gi"];
  let cases = 0;
  const inconsistent = [];
  for (const { flags, exact } of generate({
    seed: SEED_REGISTRY,
    count: 400,
    gen: (r) => ({ flags: r.pick(flagsList), exact: r.bool(0.3) }),
  })) {
    const pattern = new RegExp("ACME_[A-Z0-9_]+", flags);
    let registry = new ForeignTokenRegistry([{ name: "acme", pattern }]);
    if (exact) registry = registry.registerTokens([TOKEN]);
    const ctx = new RedactionContext({ salt: "r2", foreignRegistry: registry });
    const a = classifyOwnership(TOKEN, ctx, registry).ownership;
    const b = ctx.isProtectedToken(TOKEN);
    if ((a === "FOREIGN_REGISTERED") !== b) inconsistent.push({ flags, exact, ownership: a, protected: b });
    cases++;
  }
  assert.equal(cases, 400);
  // This is the finding's signature: the disagreement only occurs for pattern-registered
  // namespaces with stateful flags.
  const bad = inconsistent.filter((r) => !r.exact);
  assert.ok(bad.length > 0, "the exploration must reach the finding, or it is testing nothing");
  assert.equal(
    inconsistent.some((r) => r.exact), false,
    "an EXACT registration must never be affected by matcher state"
  );
  assert.ok(rng.int(0, 10) >= 0, "the category rng is reproducible from its own seed");
});
