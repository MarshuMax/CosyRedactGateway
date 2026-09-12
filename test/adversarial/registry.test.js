// R2 -- adversarial exploration: ownership and the foreign registry.
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
// "The output is not what I expected" is an OBSERVATION, and is recorded as one. The flow is:
//
//   discover -> minimise -> prove the violated contract -> add an isolated RED regression ->
//   classify severity and root cause -> only then decide about a fix.
//
// R2-REG-001 was found this way and is now FIXED. Its regression tests are asserted as the
// CONTRACT rather than as the old defect: a test that pins a bug has to be rewritten once the bug
// is gone, or it silently becomes a test of nothing.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  ForeignTokenRegistry,
  RedactionContext,
  classifyOwnership,
  applySinkPolicy,
  findSensitiveSpans,
} from "../../worker.js";
import { generate, makeRng } from "../helpers/property.mjs";

const TOKEN = "ACME_ABCDEF_0001";
const OTHER = "ACME_ZZZZZZ_9999";
const LINE = `DB_PASSWORD=${TOKEN}`;
const FLAGS = { gitleaks: true, highEntropy: true };

// Derived seed for this category, so a report can be reproduced in isolation.
const SEED_REGISTRY = 0x2e610001;
const STATEFUL_FLAGS = ["g", "y", "gi", "gy", "gim"];

const findings = JSON.parse(readFileSync(new URL("./corpus/findings.json", import.meta.url), "utf8"));

/** A registry whose namespace matcher carries the given flags. */
const registryWith = (flags) => new ForeignTokenRegistry([{ name: "acme", pattern: new RegExp("ACME_[A-Z0-9_]+", flags) }]);

// =====================================================================================
// R2-REG-001 regression -- namespace matching is a STATELESS MEMBERSHIP PREDICATE
// =====================================================================================

test("R2-REG-001: the same token resolves identically on 100 consecutive calls [GREEN NOW]", () => {
  // The minimal reproducer for the original finding: one registry, one matcher, one token.
  for (const flags of STATEFUL_FLAGS) {
    const registry = registryWith(flags);
    const seen = [];
    for (let i = 0; i < 100; i++) seen.push(registry.namespaceOf(TOKEN));
    assert.deepEqual(
      [...new Set(seen)], ["acme"],
      `flags=${flags}: 100 calls must agree, got ${JSON.stringify([...new Set(seen)])}`
    );
  }
  // A non-matching token must be stable in the other direction too.
  const registry = registryWith("g");
  const misses = [];
  for (let i = 0; i < 100; i++) misses.push(registry.namespaceOf("nope_nothing"));
  assert.deepEqual([...new Set(misses)], [null], "a non-match must stay a non-match");
});

test("R2-REG-001: classifyOwnership and isProtectedToken always agree [GREEN NOW]", () => {
  // The cross-layer half of the finding. Both read the same registration and must give one
  // answer, whatever the call order.
  for (const flags of ["", ...STATEFUL_FLAGS]) {
    const registry = registryWith(flags);
    const ctx = new RedactionContext({ salt: "r2", foreignRegistry: registry });
    const pairs = [];
    for (let i = 0; i < 30; i++) {
      pairs.push([classifyOwnership(TOKEN, ctx, registry).ownership, ctx.isProtectedToken(TOKEN)]);
    }
    const disagreements = pairs.filter(([a, b]) => (a === "FOREIGN_REGISTERED") !== b);
    assert.deepEqual(disagreements, [], `flags=${flags}: the layers disagree: ${JSON.stringify(pairs.slice(0, 4))}`);
  }
});

test("R2-REG-001: a registered foreign token is preserved on the way IN [GREEN NOW]", async () => {
  // The consequence the finding produced: a strong binding must not re-tokenise a value the
  // registry says is foreign.
  for (const flags of ["", ...STATEFUL_FLAGS]) {
    const registry = registryWith(flags);
    const ctx = new RedactionContext({ salt: "r2", foreignRegistry: registry });
    const out = await ctx.redactText(LINE, FLAGS);
    assert.equal(out, LINE, `flags=${flags}: expected the token to pass through, got ${JSON.stringify(out)}`);

    const spans = findSensitiveSpans(LINE, FLAGS, {
      isProtectedToken: ctx.isProtectedToken,
      foreignRegistry: registry,
      coverage: null,
    });
    assert.deepEqual(spans, [], `flags=${flags}: the protected value must not become a span`);
  }
});

test("R2-REG-001: ownership does not depend on call ORDER [GREEN NOW]", () => {
  // The strongest statement of the invariant: interleaving two tokens in different orders must
  // not change either verdict.
  const registry = registryWith("g");
  const interleaved = [];
  for (const t of [TOKEN, OTHER, TOKEN, OTHER, TOKEN]) interleaved.push([t, registry.namespaceOf(t)]);
  const grouped = [];
  for (const t of [TOKEN, TOKEN, TOKEN, OTHER, OTHER]) grouped.push([t, registry.namespaceOf(t)]);

  const verdict = (rows, token) => [...new Set(rows.filter(([t]) => t === token).map(([, ns]) => ns))];
  for (const t of [TOKEN, OTHER]) {
    assert.deepEqual(verdict(interleaved, t), verdict(grouped, t), `${t}: verdict differs by call order`);
    assert.equal(verdict(interleaved, t).length, 1, `${t}: verdict must be single-valued`);
  }
});

test("R2-REG-001: the registry neither reads nor writes the caller's regex state [GREEN NOW]", () => {
  // Both directions, because the fix clones. A caller who is mid-iteration over their own regex
  // must not have it disturbed, and a caller's stray lastIndex must not reach the registry.
  const callerRegex = /ACME_[A-Z0-9_]+/g;

  callerRegex.lastIndex = 7;
  const registry = new ForeignTokenRegistry([{ name: "acme", pattern: callerRegex }]);
  assert.equal(callerRegex.lastIndex, 7, "constructing the registry must not touch the caller's lastIndex");

  const seen = [];
  for (let i = 0; i < 5; i++) seen.push(registry.namespaceOf(TOKEN));
  assert.deepEqual([...new Set(seen)], ["acme"], "a stray caller lastIndex must not change the verdict");
  assert.equal(callerRegex.lastIndex, 7, "and matching must not advance the caller's lastIndex");

  // The caller's own iteration still works after the registry has been used.
  callerRegex.lastIndex = 0;
  assert.deepEqual(
    "ACME_A and ACME_B".match(callerRegex), ["ACME_A", "ACME_B"],
    "the caller's regex is still usable for iteration"
  );
});

test("R2-REG-001: a reusable registry is stable across repeated redactions [GREEN NOW]", async () => {
  // The deployment shape that exposed the finding: one registry built at startup, used for many
  // requests.
  const registry = registryWith("g");
  const outcomes = [];
  for (let i = 0; i < 12; i++) {
    const ctx = new RedactionContext({ salt: "r2", foreignRegistry: registry });
    outcomes.push((await ctx.redactText(LINE, FLAGS)) === LINE ? "kept" : "redacted");
  }
  assert.deepEqual([...new Set(outcomes)], ["kept"], `a shared registry must be stable, saw ${JSON.stringify(outcomes)}`);
});

test("R2-REG-001: an exact registration still bypasses the matcher and is unaffected [GREEN NOW]", () => {
  const registry = registryWith("g").registerTokens([TOKEN]);
  const seen = [];
  for (let i = 0; i < 10; i++) seen.push(registry.namespaceOf(TOKEN));
  assert.deepEqual([...new Set(seen)], ["exact"], "an exact registration returns before the matcher runs");
});

test("R2-REG-001: every matcher shape is now stateless [GREEN NOW]", () => {
  // Mapping the class rather than the one example. Sticky (`y`) keeps its language -- it matches
  // only at index 0 -- but that is now a stable property instead of a cursor artifact.
  const shapes = [
    ["non-global", ""],
    ["/g", "g"],
    ["/y", "y"],
    ["/gi", "gi"],
    ["/gy", "gy"],
  ];
  for (const [label, flags] of shapes) {
    const registry = registryWith(flags);
    const seen = [];
    for (let i = 0; i < 8; i++) seen.push(registry.namespaceOf(TOKEN));
    assert.equal(new Set(seen).size, 1, `${label}: must be stable, saw ${JSON.stringify(seen)}`);
    assert.equal(seen[0], "acme", `${label}: and must match at index 0`);
  }

  // Sticky semantics, recorded deliberately: `y` matches only at lastIndex 0, so a token with a
  // prefix does not qualify. That is the caller's declared meaning and it is preserved.
  const sticky = registryWith("y");
  assert.equal(sticky.namespaceOf(TOKEN), "acme", "at index 0 it matches");
  assert.equal(sticky.namespaceOf(`x${TOKEN}`), null, "with a prefix, no");
});

test("R2-REG-001: string patterns and exact registrations are unchanged [GREEN NOW]", () => {
  const viaString = new ForeignTokenRegistry([{ name: "acme", pattern: "ACME_[A-Z0-9_]+" }]);
  const seen = [];
  for (let i = 0; i < 8; i++) seen.push(viaString.namespaceOf(TOKEN));
  assert.deepEqual([...new Set(seen)], ["acme"], "a string pattern is stateless as before");
});

// =====================================================================================
// The refined invariant, explored systematically
// =====================================================================================

test("R2-REG: no matcher shape or call pattern produces an inconsistent verdict [GREEN NOW]", () => {
  // The exploration now asserts the FIXED contract across the whole neighbourhood: whatever the
  // flags and whatever the call sequence, the two layers agree and the verdict is single-valued.
  let cases = 0;
  const inconsistent = [];
  const multiValued = [];
  for (const { flags, exact, interleave } of generate({
    seed: SEED_REGISTRY,
    count: 600,
    gen: (r) => ({ flags: r.pick(["", "g", "y", "gi", "gy"]), exact: r.bool(0.3), interleave: r.bool(0.5) }),
  })) {
    let registry = registryWith(flags);
    if (exact) registry = registry.registerTokens([TOKEN]);
    const ctx = new RedactionContext({ salt: "r2", foreignRegistry: registry });

    const sequence = interleave ? [TOKEN, OTHER, TOKEN, OTHER, TOKEN] : [TOKEN, TOKEN, TOKEN, OTHER, OTHER];
    const verdicts = [];
    for (const t of sequence) {
      const ownership = classifyOwnership(t, ctx, registry).ownership;
      const isProtected = ctx.isProtectedToken(t);
      if ((ownership === "FOREIGN_REGISTERED") !== isProtected) inconsistent.push({ flags, exact, t, ownership, isProtected });
      verdicts.push([t, ownership, isProtected]);
    }
    for (const t of [TOKEN, OTHER]) {
      const rows = verdicts.filter(([x]) => x === t);
      if (new Set(rows.map(([, o, p]) => `${o}|${p}`)).size > 1) multiValued.push({ flags, exact, t, rows });
    }
    cases++;
  }
  assert.equal(cases, 600);
  assert.deepEqual(inconsistent.slice(0, 3), [], "the layers must agree for every shape");
  assert.deepEqual(multiValued.slice(0, 3), [], "a verdict must not depend on call order");
});

test("R2-REG: sink policy agrees with ownership for every registration shape [GREEN NOW]", () => {
  // Extends the agreement to the consumer: a registered foreign token is refused as an operand
  // and preserved in prose, whatever flags the matcher carries.
  //
  // SCOPE: `g` and plain matchers. `y` is deliberately excluded here and covered as its own
  // observation below -- a sticky matcher only matches at index 0, so it cannot FIND a token that
  // appears later in a document. That is a separate, pre-existing defect, verified to behave
  // identically before and after the R2-REG-001 fix, and folding it into this finding would be
  // exactly the "17 symptoms, 1 root cause" mistake R2 exists to avoid.
  for (const flags of ["", "g"]) {
    const registry = registryWith(flags);
    const ctx = new RedactionContext({ salt: "r2", foreignRegistry: registry });

    const prose = applySinkPolicy(TOKEN, ctx, { kind: "assistant_text" }, null, registry);
    assert.ok(prose.text.includes(TOKEN), `flags=${flags}: prose keeps the token`);

    const operand = applySinkPolicy(`curl x?y=${TOKEN}`, ctx, { kind: "tool_argument" }, null, registry);
    assert.equal(operand.blocked, true, `flags=${flags}: an operand channel refuses an unresolvable foreign token`);
    assert.equal(operand.text.includes(TOKEN), false, `flags=${flags}: and does not deliver it`);
  }
});

// =====================================================================================
// OBSERVATIONS -- recorded, explicitly NOT findings
// =====================================================================================

test("R2-REG OBSERVATION: repeated occurrences always resolve to the FIRST index [GREEN NOW]", () => {
  // Not a finding: the index computed this way is only used for an existence test
  // (`foreign.includes(found)`), so no position is consumed. Recorded because if a future change
  // starts using that index to locate content, this becomes a real defect.
  const pattern = /ACME_[A-Z0-9_]+/g;
  const text = `ACME_A and ACME_B and ACME_A`;
  pattern.lastIndex = 0;
  const found = text.match(pattern) || [];
  const viaIndexOf = found.map((f) => text.indexOf(f));

  const real = [];
  const scanner = /ACME_[A-Z0-9_]+/g;
  for (let m; (m = scanner.exec(text)) !== null;) real.push(m.index);

  assert.deepEqual(found, ["ACME_A", "ACME_B", "ACME_A"]);
  assert.deepEqual(real, [0, 11, 22], "the true occurrence positions");
  assert.deepEqual(viaIndexOf, [0, 11, 0], "a REPEATED value always reports its first position");
  assert.notDeepEqual(viaIndexOf, real, "so indexOf is not a substitute for real match positions");
});

test("R2-REG OBSERVATION: a STICKY matcher cannot find a token mid-document [GREEN NOW]", () => {
  // INDEPENDENT, PRE-EXISTING, and NOT part of R2-REG-001. Verified by stashing the fix and
  // re-running: the behaviour below is identical before and after, so the stateful-matcher fix
  // neither caused nor cured it.
  //
  // The mechanism: `namespaceOf` calls `.test()` with the cursor at 0, so for a sticky matcher it
  // matches only at position 0. `namespaceFindAll` uses `String.match`, which with the `y` flag is
  // likewise anchored at `lastIndex`. Reading a document for foreign tokens is a SEARCH, not a
  // membership test at offset 0, so a sticky registration can never be found once anything
  // precedes it.
  //
  // Consequence, asserted so it cannot drift silently: with `y`, a foreign token is OWNERSHIP-
  // RECOGNISED when it stands alone (prose preserves it) but NOT FOUND when it appears inside a
  // longer string, so an operand carrying it is delivered instead of refused. No plaintext is
  // exposed -- the failure direction is "this layer hands over a token it cannot resolve", which
  // the outer DLP owns -- but the two channels disagree for one registration.
  const sticky = registryWith("y");
  const ctx = new RedactionContext({ salt: "r2", foreignRegistry: sticky });

  // Ownership at offset 0: recognised.
  assert.equal(sticky.namespaceOf(TOKEN), "acme", "sticky matches the token standing alone");
  assert.equal(ctx.isProtectedToken(TOKEN), true, "so it is protected");

  // Inside a longer string: not found.
  const embedded = `curl x?y=${TOKEN}`;
  assert.equal(sticky.namespaceOf(embedded), null, "sticky does not match with a prefix present");
  const operand = applySinkPolicy(embedded, ctx, { kind: "tool_argument" }, null, sticky);
  assert.equal(operand.text.includes(TOKEN), true, "so the operand is delivered rather than refused");

  // The control: the equivalent non-sticky matcher behaves consistently in both channels.
  const normal = registryWith("g");
  const normalCtx = new RedactionContext({ salt: "r2", foreignRegistry: normal });
  assert.equal(normal.namespaceOf(TOKEN), "acme");
  assert.equal(applySinkPolicy(embedded, normalCtx, { kind: "tool_argument" }, null, normal).blocked, true,
    "a non-sticky matcher refuses the operand, which is the expected behaviour");
});

test("R2-REG OBSERVATION: a capture-group matcher is evaluated on the full match [GREEN NOW]", () => {
  // `.test()` ignores groups, so a namespace pattern with captures behaves as its full match.
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
  // The fixed finding must actually be marked fixed, or the registry is lying about the tree.
  assert.equal(findings.findings.find((f) => f.id === "R2-REG-001")?.status, "fixed");
});

test("R2-REG: the category rng is reproducible from its own seed [GREEN NOW]", () => {
  const draw = (r) => [r.int(0, 100), r.pick(["x", "y", "z"]), r.bool()];
  assert.deepEqual(draw(makeRng(SEED_REGISTRY)), draw(makeRng(SEED_REGISTRY)), "the same seed reproduces the same stream");
});
