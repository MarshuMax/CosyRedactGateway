// R2.6 -- nested tool operand.
//
// Scope is JSON-reachable values ONLY: object, array, string, number, boolean, null. Cyclic
// objects, Map/Set/Date, getters and Proxy, sparse arrays and custom prototypes are deliberately
// NOT covered -- those are JS API robustness, not the wire contract, and depth exhaustion is left
// to R3.
//
// The load-bearing oracle is a differential:
//
//   nestedResult(x) === applySinkPolicy(x, TOOL_ARGUMENT, same toolName/trust)
//
// The recursive walker is responsible for TRAVERSAL and must not invent a second copy of the
// policy. Writing out an expected table per authority would be a duplicate policy that drifts, so
// the helper is the single source of truth.
//
// `applyOperandPolicy` passes one toolName down to every string leaf, so the things worth attacking
// are: the same policy must reach every leaf; depth must not change it; non-strings and containers
// must survive untouched; object KEYS are never rewritten; and one sibling must not influence
// another.

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  ForeignTokenRegistry,
  applyOperandPolicy,
  applySinkPolicy,
  applyResponsePolicy,
} from "../../worker.js";
import { generate, makeRng } from "../helpers/property.mjs";

const SEED_OPERAND = 0x2e610006;
const B64 = "cGFzc3dvcmQxMjM0NTY3OA==";
const NS = { name: "acme", pattern: /(?<![A-Za-z0-9_])ACME_[A-Z0-9_]{4,}(?![A-Za-z0-9_])/, streamPrefix: "ACME_" };
const TRUSTED = ["broker"];

const TOKEN_RE = /CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}/g;
const overlaps = () => false;
void overlaps;

/** A context holding one OWN entity, its surrogate, and a registry for foreign values. */
async function fixture() {
  const registry = new ForeignTokenRegistry([NS]);
  const ctx = new RedactionContext({ salt: "r26", requestId: "AAAAAA", foreignRegistry: registry });
  const doc = ["apiVersion: v1", "kind: Secret", "data:", `  password: ${B64}`].join("\n");
  const out = await ctx.redactText(doc, { gitleaks: true, highEntropy: true });
  const surrogate = (out.match(/password: (\S+)/) || [])[1];
  const entry = ctx.ledger.lookup(surrogate);
  assert.ok(entry, "fixture must mint a ledger surrogate");
  return { ctx, registry, surrogate, token: entry.token, plaintext: B64 };
}

/** The leaf kinds the matrix calls for. */
const leafOf = (kind, f) => ({
  "OWN token": f.token,
  "OWN surrogate": f.surrogate,
  "exact FOREIGN": "ACME_ABCDEF_0001",
  "namespace FOREIGN": "ACME_ZZZZZZ_9999",
  "UNKNOWN CRG-shaped": "CRG_AAAA_AAAA",
  "ordinary string": "ordinary text",
  "number": 42,
  "boolean": true,
  "null": null,
}[kind]);

/** Build a tree of `depth` levels with a chosen container kind at each level. */
function buildTree(depth, innerKind, leaf) {
  const wrap = (v) => (innerKind === "object" ? { child: v } : [v]);
  let node = leaf;
  for (let i = 0; i < depth; i++) node = wrap(node);
  return node;
}

/** The single leaf inside a uniform tree, whatever the container kind. */
function leafOfTree(node) {
  let cur = node;
  while (cur && typeof cur === "object" && !Array.isArray(cur)) cur = cur.child;
  while (Array.isArray(cur)) cur = cur[0];
  while (cur && typeof cur === "object" && "child" in cur) cur = cur.child;
  return cur;
}

const KINDS = ["object", "array"];

// =====================================================================================
// The differential oracle
// =====================================================================================

test("R2.6: every string leaf obeys exactly the tool_argument policy [RED]", async () => {
  // The primary oracle. If the walker invented any policy of its own, or skipped a leaf, this
  // diverges.
  const f = await fixture();
  const kinds = ["OWN token", "OWN surrogate", "exact FOREIGN", "namespace FOREIGN", "UNKNOWN CRG-shaped", "ordinary string"];
  const violations = [];

  for (const kind of kinds) {
    const value = leafOf(kind, f);
    for (const trusted of [false, true]) {
      for (const [structure, wrap] of [
        ["object->object", (v) => ({ a: { b: { c: v } } })],
        ["object->array", (v) => ({ a: [{ b: v }] })],
        ["array->object", (v) => [{ a: { b: [v] } }]],
        ["array->array", (v) => [[[v]]]],
        ["mixed tree", (v) => ({ headers: { auth: v }, args: ["plain", { nested: [v] }] })],
      ]) {
        const tree = wrap(value);
        applyOperandPolicy(tree, f.ctx, TRUSTED, f.registry, trusted ? "broker" : "run_shell");
        const direct = applySinkPolicy(
          value, f.ctx, { kind: "tool_argument", toolName: trusted ? "broker" : "run_shell" }, TRUSTED, f.registry
        ).text;

        // Find every string leaf in the walked tree and require the value leaf to match `direct`.
        const seen = [];
        const walk = (v) => {
          if (typeof v === "string") { seen.push(v); return; }
          if (Array.isArray(v)) { v.forEach(walk); return; }
          if (v && typeof v === "object") Object.values(v).forEach(walk);
        };
        walk(tree);
        if (!seen.includes(direct)) violations.push({ kind, trusted, structure, expected: direct, seen });
      }
    }
  }
  assert.deepEqual(violations.slice(0, 3), [], `the walker diverged from the policy: ${JSON.stringify(violations.slice(0, 3))}`);
});

test("R2.6: depth does not change the policy [RED]", async () => {
  const f = await fixture();
  const depths = [1, 2, 5, 10, 20, 50];
  for (const depth of depths) {
    for (const kind of ["OWN token", "OWN surrogate", "exact FOREIGN", "UNKNOWN CRG-shaped"]) {
      const value = leafOf(kind, f);
      for (const innerKind of KINDS) {
        for (const trusted of [false, true]) {
          const toolName = trusted ? "broker" : "run_shell";
          const tree = buildTree(depth, innerKind, value);
          applyOperandPolicy(tree, f.ctx, TRUSTED, f.registry, toolName);
          const direct = applySinkPolicy(value, f.ctx, { kind: "tool_argument", toolName }, TRUSTED, f.registry).text;
          const got = leafOfTree(tree);
          assert.equal(
            got, direct,
            `depth=${depth} kind=${kind} inner=${innerKind} trusted=${trusted}: depth changed the result`
          );
        }
      }
    }
  }
});

// =====================================================================================
// Structure preservation
// =====================================================================================

test("R2.6: non-string values are unchanged value for value [RED]", async () => {
  const f = await fixture();
  const tree = {
    num: 42, zero: 0, neg: -1, float: 1.5, big: 9007199254740991,
    yes: true, no: false, nothing: null,
    str: "ordinary", nested: { n: 7, b: false, z: null },
  };
  const before = JSON.stringify(tree);
  applyOperandPolicy(tree, f.ctx, TRUSTED, f.registry, "run_shell");
  assert.equal(JSON.stringify(tree), before, "a tree of non-strings must be byte-identical");
});

test("R2.6: container shape is preserved [RED]", async () => {
  const f = await fixture();
  // A pure shape descriptor, compared before and after. An earlier version stringified the tree
  // together with its shape from the SAME mutated object, so the two sides could not disagree for
  // the reason the test intended.
  const shapeOf = (v) => {
    if (Array.isArray(v)) return { array: v.length, items: v.map(shapeOf) };
    if (v && typeof v === "object") return { object: Object.keys(v), values: Object.keys(v).map((k) => shapeOf(v[k])) };
    return typeof v;
  };
  const build = () => ({
    obj: { a: 1, b: { c: 2 } },
    arr: [1, "two", { three: 3 }, [4, [5]]],
    emptyArr: [],
    emptyObj: {},
    mixed: [{ x: f.token }, [f.token], "plain"],
  });

  const before = shapeOf(build());
  const tree = build();
  applyOperandPolicy(tree, f.ctx, TRUSTED, f.registry, "run_shell");
  assert.deepEqual(shapeOf(tree), before, "the container shape must not change");

  // Stated explicitly as well, so a shape dump cannot hide a reordering.
  assert.equal(tree.arr.length, 4);
  assert.deepEqual(tree.arr.map((v) => typeof v), ["number", "string", "object", "object"]);
  assert.equal(tree.emptyArr.length, 0);
  assert.deepEqual(Object.keys(tree.emptyObj), []);
  assert.equal(Array.isArray(tree.mixed[1]), true, "an array of one token stays an array");
  assert.equal(tree.mixed[1].length, 1);
});

test("R2.6: object KEYS are never rewritten [RED]", async () => {
  // Deliberate: renaming a JSON key changes the tool schema, which is worse than leaving an opaque
  // token in place. A key that looks like a token stays exactly as it was, and is NOT restored.
  const f = await fixture();
  const tree = {
    [f.token]: "value",
    [f.surrogate]: "value2",
    ACME_ABCDEF_0001: "value3",
    normalKey: f.token,
  };
  const keysBefore = Object.keys(tree);
  applyOperandPolicy(tree, f.ctx, TRUSTED, f.registry, "run_shell");
  assert.deepEqual(Object.keys(tree), keysBefore, "no key may be added, removed or renamed");
  assert.equal(f.plaintext in tree, false, "and no key may be resolved into the plaintext");
  assert.equal(tree.normalKey.includes(f.plaintext), false, "while a token in a VALUE is still policy-governed");
});

// =====================================================================================
// Sibling isolation and traversal order
// =====================================================================================

test("R2.6: one sibling does not influence another [RED]", async () => {
  // The tree the matrix calls for: different authorities side by side, so a walker that carries a
  // verdict forward from one leaf to the next shows up here.
  const f = await fixture();
  const make = () => ({
    headers: { auth: f.token, foreign: "ACME_ABCDEF_0001" },
    args: ["plain", { nested: ["CRG_AAAA_AAAA", f.surrogate] }],
  });

  // Each leaf must equal its own direct result, in both trust modes.
  for (const trusted of [false, true]) {
    const toolName = trusted ? "broker" : "run_shell";
    const tree = make();
    applyOperandPolicy(tree, f.ctx, TRUSTED, f.registry, toolName);
    const pairs = [
      [tree.headers.auth, f.token],
      [tree.headers.foreign, "ACME_ABCDEF_0001"],
      [tree.args[1].nested[0], "CRG_AAAA_AAAA"],
      [tree.args[1].nested[1], f.surrogate],
    ];
    for (const [got, original] of pairs) {
      const direct = applySinkPolicy(original, f.ctx, { kind: "tool_argument", toolName }, TRUSTED, f.registry).text;
      assert.equal(got, direct, `trusted=${trusted}: a leaf did not match its own policy result`);
    }
  }
});

test("R2.6: the security outcome does not depend on traversal order [RED]", async () => {
  // Permutations of property order and array order. The outcome may only depend on the leaf and the
  // tool trust, never on where the leaf sits in the walk.
  //
  // Each tree is freshly BUILT and walked once, then compared field by field. An earlier version
  // reused one mutated object for both sides and compared whole serialisations, which could only
  // ever report a difference in key ORDER, not in outcome.
  const f = await fixture();

  const walked = (tree) => {
    const copy = structuredClone(tree);
    applyOperandPolicy(copy, f.ctx, TRUSTED, f.registry, "run_shell");
    return copy;
  };

  // Property order swapped: the value for a given KEY must be identical either way.
  const forward = { a: f.token, b: "ACME_ABCDEF_0001", c: "CRG_AAAA_AAAA", d: f.surrogate };
  const reversed = { d: f.surrogate, c: "CRG_AAAA_AAAA", b: "ACME_ABCDEF_0001", a: f.token };
  const ofForward = walked(forward);
  const ofReversed = walked(reversed);
  for (const key of Object.keys(forward)) {
    assert.equal(ofForward[key], ofReversed[key], `property order changed the outcome for ${key}`);
  }

  // OWN first versus OWN last: the case that would expose verdict carried between leaves.
  const ownFirst = walked({ first: f.token, last: "plain" });
  const ownLast = walked({ first: "plain", last: f.token });
  assert.equal(ownFirst.first, ownLast.last, "the OWN leaf has the same outcome wherever it sits");
  assert.equal(ownFirst.last, ownLast.first, "and so does the ordinary leaf");

  // Array order: the MULTISET of outcomes must be identical.
  const values = [f.token, "ACME_ABCDEF_0001", "CRG_AAAA_AAAA", f.surrogate, "plain"];
  const arrForward = walked([...values]);
  const arrReversed = walked([...values].reverse());
  assert.deepEqual(
    [...arrForward].sort(), [...arrReversed].sort(),
    "array order must not change the multiset of outcomes"
  );

  // And each element still equals its own direct result, which is the stronger statement.
  values.forEach((original, i) => {
    const direct = applySinkPolicy(original, f.ctx, { kind: "tool_argument", toolName: "run_shell" }, TRUSTED, f.registry).text;
    assert.equal(arrForward[i], direct, `element ${i} must equal its own policy result`);
  });
});

// =====================================================================================
// Anthropic production E2E -- the path that actually calls the walker
// =====================================================================================

test("R2.6 E2E: a nested Anthropic tool_use.input is walked by the PRODUCTION path [RED]", async () => {
  // The helper being correct is not enough: the production route is
  //   content[] -> tool_use -> block.input -> applyOperandPolicy()
  // This drives applyResponsePolicy, which is what a real response goes through.
  const f = await fixture();
  const deep = { l1: { l2: { l3: { l4: { l5: { l6: f.token } } } } } };

  const data = {
    type: "message",
    role: "assistant",
    content: [
      { type: "text", text: "here you go" },
      { type: "tool_use", id: "tu_1", name: "run_shell", input: deep },
    ],
  };
  applyResponsePolicy(data, f.ctx, TRUSTED, f.registry);

  let cur = data.content[1].input;
  for (const key of ["l1", "l2", "l3", "l4", "l5"]) cur = cur[key];
  assert.equal(cur.l6, f.token, "an untrusted operand keeps the token six levels down");
  assert.equal(JSON.stringify(data).includes(f.plaintext), false, "and the plaintext is nowhere in the response");
});

test("R2.6 E2E: a trusted tool name restores six levels down [RED]", async () => {
  const f = await fixture();
  const deep = { l1: { l2: { l3: { l4: { l5: { l6: f.token } } } } } };
  const data = {
    type: "message",
    role: "assistant",
    content: [{ type: "tool_use", id: "tu_1", name: "broker", input: deep }],
  };
  applyResponsePolicy(data, f.ctx, TRUSTED, f.registry);

  let cur = data.content[0].input;
  for (const key of ["l1", "l2", "l3", "l4", "l5"]) cur = cur[key];
  assert.equal(cur.l6, f.plaintext, "a trusted tool restores the value wherever it sits");
});

test("R2.6 E2E: the same response keeps text and operand channels apart [RED]", async () => {
  // A response with both a text block and a nested tool block: the text block restores, the operand
  // block preserves. Traversal must not leak one channel's policy into the other.
  const f = await fixture();
  const data = {
    type: "message",
    role: "assistant",
    content: [
      { type: "text", text: `the value is ${f.token}` },
      { type: "tool_use", id: "tu_1", name: "run_shell", input: { deep: { deeper: f.token } } },
    ],
  };
  applyResponsePolicy(data, f.ctx, TRUSTED, f.registry);

  assert.ok(data.content[0].text.includes(f.plaintext), "assistant text restores");
  assert.equal(data.content[1].input.deep.deeper, f.token, "while the operand preserves");
});

// =====================================================================================
// Seeded exploration
// =====================================================================================

test("R2.6: seeded trees keep the differential [RED]", async () => {
  const f = await fixture();
  const kinds = ["OWN token", "OWN surrogate", "exact FOREIGN", "namespace FOREIGN", "UNKNOWN CRG-shaped", "ordinary string"];
  let cases = 0;
  const violations = [];

  for (const { depth, innerKind, kind, trusted, shape } of generate({
    seed: SEED_OPERAND,
    count: 300,
    gen: (r) => ({
      depth: r.pick([1, 2, 5, 10, 20]),
      innerKind: r.pick(KINDS),
      kind: r.pick(kinds),
      trusted: r.bool(),
      shape: r.pick(["chain", "wide", "mixed"]),
    }),
  })) {
    const value = leafOf(kind, f);
    const toolName = trusted ? "broker" : "run_shell";
    let tree;
    if (shape === "chain") tree = buildTree(depth, innerKind, value);
    else if (shape === "wide") tree = { a: value, b: value, c: [value], d: { e: value } };
    else tree = { arr: [{ deep: [value] }], other: "plain" };

    applyOperandPolicy(tree, f.ctx, TRUSTED, f.registry, toolName);
    const direct = applySinkPolicy(value, f.ctx, { kind: "tool_argument", toolName }, TRUSTED, f.registry).text;
    if (!JSON.stringify(tree).includes(JSON.stringify(direct).slice(1, -1))) {
      violations.push({ depth, innerKind, kind, trusted, shape, direct });
    }
    cases++;
  }
  assert.equal(cases, 300);
  assert.deepEqual(violations.slice(0, 3), [], `seeded trees diverged: ${JSON.stringify(violations.slice(0, 3))}`);
});

test("R2.6: the operand corpus is deterministic [GREEN NOW]", () => {
  const draw = (r) => [r.pick(KINDS), r.int(1, 20), r.bool()];
  assert.deepEqual(draw(makeRng(SEED_OPERAND)), draw(makeRng(SEED_OPERAND)));
});

test("R2.6: token counting sanity on the fixture [GREEN NOW]", async () => {
  // Guard on the fixture: if the plaintext were not really owned, every assertion above would be
  // vacuously true.
  const f = await fixture();
  assert.equal(TOKEN_RE.test(f.token), true, "the fixture token must be token-shaped");
  TOKEN_RE.lastIndex = 0;
  assert.equal(f.surrogate.includes(f.plaintext), false, "the surrogate is not the plaintext");
  const direct = applySinkPolicy(f.token, f.ctx, { kind: "tool_argument", toolName: "broker" }, TRUSTED, f.registry).text;
  assert.equal(direct, f.plaintext, "and a trusted tool resolves it");
});
