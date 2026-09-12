// D2a: simple YAML block-mapping scalars.
//
//   password: xxx
//   password: "xxx"
//   password: 'xxx'
//
// Scope is deliberately narrow. Block scalars (`|`, `>`), sequences, flow style,
// anchors/aliases/tags and multi-document files are NOT modelled; those are D2b
// and D2c. The parser records structural context (indent, pathSegments,
// pathConfidence) as EVIDENCE ONLY -- see the note in parseYamlBindings and the
// "hint, not fact" tests below.
//
// Assertion tags:
//   [GREEN NOW]  passes against the current tree
//   [RED]        target behaviour for a later slice

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  parseYamlBindings,
  PATH_CONFIDENCE,
  TOKEN_PREFIX,
} from "../worker.js";

const SECRET = "Pr0d-P@ssw0rd-Xy9Zk2mQ";

function redact(text, flags = { gitleaks: true }) {
  return new RedactionContext({ salt: "fixture" }).redactText(text, flags);
}

// ----------------------------------------------------------- 1. three forms ---

test("all three scalar forms redact the value and keep the host syntax [GREEN NOW]", async () => {
  const forms = [
    [`password: ${SECRET}`, `password: `],
    [`password: "${SECRET}"`, `password: "`],
    [`password: '${SECRET}'`, `password: '`],
  ];
  for (const [line, prefix] of forms) {
    const out = await redact(line);
    assert.equal(out.includes(SECRET), false, `${line} must not keep the secret`);
    assert.ok(out.startsWith(prefix), `${line}: the key and any quote must survive untouched`);
    assert.ok(out.includes(TOKEN_PREFIX), `${line}: a token must replace the value`);
  }
});

test("quoted values exclude the quotes from the span [GREEN NOW]", () => {
  for (const style of ['"', "'"]) {
    const line = `password: ${style}${SECRET}${style}`;
    const [binding] = parseYamlBindings(line);
    assert.ok(binding, `${style}: must parse`);
    assert.equal(line.slice(binding.valueStart, binding.valueEnd), SECRET, "span is the interior only");
    assert.equal(line.slice(binding.valueStart - 1, binding.valueStart), style, "opening quote is outside the span");
  }
});

test("round-trip is byte-identical for every scalar form [GREEN NOW]", async () => {
  const doc = [
    "# a comment",
    "apiVersion: v1",
    `password: ${SECRET}`,
    `token: "${SECRET}"`,
    `secret: '${SECRET}'`,
    "port: 5432",
  ].join("\n");
  const ctx = new RedactionContext({ salt: "fixture" });
  const out = await ctx.redactText(doc, { gitleaks: true, highEntropy: true });
  assert.notEqual(out, doc, "fixture must actually be redacted");
  assert.equal(ctx.restoreText(out), doc, "restore must reproduce the document byte for byte");
});

// ------------------------------------------------------- 2. structure hints ---

test("indent and path segments are recorded for a simple mapping [GREEN NOW]", () => {
  const doc = ["data:", "  password: abc123", "stringData:", "  PASSWORD: xyz789"].join("\n");
  const bindings = parseYamlBindings(doc);
  const byKey = Object.fromEntries(bindings.map((b) => [b.key, b]));
  assert.equal(byKey.password.indent, 2);
  assert.deepEqual(byKey.password.pathSegments, ["data", "password"]);
  assert.equal(byKey.password.pathConfidence, PATH_CONFIDENCE.SIMPLE_MAPPING);
  assert.deepEqual(byKey.PASSWORD.pathSegments, ["stringData", "PASSWORD"]);
});

test("pathSegments is a hint, not a schema path [GREEN NOW]", () => {
  // The point of this test is the CONTRACT: nothing downstream may treat a
  // matching path as proof of a schema. D2c must require an object-level
  // recogniser (apiVersion == v1 AND kind == Secret AND path under root `data`),
  // because a plain application config can legitimately look like this:
  const doc = ["data:", "  password: not-a-secret-store"].join("\n");
  const [binding] = parseYamlBindings(doc);
  assert.deepEqual(binding.pathSegments, ["data", "password"], "the hint is recorded");
  // ...but the hint carries no schema claim of its own.
  assert.equal(binding.evidence.includes("kubernetes-secret"), false);
});

test("the path degrades to UNKNOWN rather than guessing a parent [GREEN NOW]", () => {
  const cases = [
    ["sequence entry", ["items:", "  - password: abc123"].join("\n"), "password"],
    ["multi-document", ["---", "password: abc123", "---", "password: def456"].join("\n"), "password"],
    ["anchor inside a sequence", ["items:", "  - &a password: abc123"].join("\n"), "password"],
  ];
  for (const [label, doc, key] of cases) {
    const binding = parseYamlBindings(doc).find((b) => b.key === key);
    assert.ok(binding, `${label}: the scalar should still be found`);
    assert.equal(binding.pathConfidence, PATH_CONFIDENCE.UNKNOWN, `${label}: path must degrade`);
    assert.deepEqual(binding.pathSegments, [], `${label}: no invented parent keys`);
    assert.ok(binding.evidence.includes("path_unknown"), `${label}: degradation must be visible`);
  }
});

test("the path survives after a modelled construct, and resets after an unmodelled one [GREEN NOW]", () => {
  const doc = ["outer:", "  password: abc123", "  - not-a-mapping", "  inner: xyz"].join("\n");
  const bindings = parseYamlBindings(doc);
  const pw = bindings.find((b) => b.key === "password");
  const inner = bindings.find((b) => b.key === "inner");
  assert.deepEqual(pw.pathSegments, ["outer", "password"], "before the sequence, the path is known");
  assert.equal(inner.pathConfidence, PATH_CONFIDENCE.UNKNOWN, "after it, the path is not claimed");
});

// --------------------------------------------------------- 3. out of scope ---

test("constructs outside D2a produce no binding, but never suppress detection [GREEN NOW]", async () => {
  const outOfScope = [
    ["block scalar |", ["password: |", "  multi", "  line"].join("\n")],
    ["block scalar >", ["password: >", "  folded"].join("\n")],
    ["flow mapping", "password: {a: 1}"],
    ["flow sequence", "password: [1, 2]"],
    ["empty value", "password:"],
    ["comment line", "# password: abc123"],
  ];
  for (const [label, doc] of outOfScope) {
    assert.deepEqual(parseYamlBindings(doc).filter((b) => b.strength === "strong"), [],
      `${label}: D2a must not claim a strong binding`);
  }
  // Suppression check: a value that another detector catches is still redacted even
  // when the YAML parser declines the line.
  const pat = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
  const line = `password: |\n  ${pat}`;
  const out = await redact(line, { gitleaks: true, highEntropy: true });
  assert.equal(out.includes(pat), false, "the provider rule must still fire");
});

test("weak keys yield no strong binding evidence on YAML [GREEN NOW]", async () => {
  // The assertion is about the BINDING layer, not about the final text: a weak key
  // whose value happens to satisfy a generic Gitleaks rule may legitimately still be
  // redacted by that rule. Asserting "the line is unchanged" would conflate the two
  // layers and make this test fail for the wrong reason.
  for (const key of ["cache_key", "secret_name", "partition_key", "sort_key", "port", "replicas"]) {
    const line = `${key}: abc123def456`;
    const strong = parseYamlBindings(line).filter((b) => b.strength === "strong");
    assert.deepEqual(strong, [], `${key} must not yield strong binding evidence`);
  }
  // And a weak key with a value no other detector cares about stays completely inert.
  const inert = "cache_key: abc123";
  assert.equal(await redact(inert), inert, "no detector should fire here");
});

// -------------------------------------------------------------- 4. D2b/D2c ----

test("D2b: block scalar values are located and redacted [RED]", async () => {
  // `|` and `>` bodies are a different span problem (multi-line, indentation
  // relative to the key). D2a deliberately declines them.
  const doc = ["certificate: |", "  -----BEGIN PRIVATE KEY-----", "  MIIEvQIBADANBgkq", "  -----END PRIVATE KEY-----"].join("\n");
  const out = await redact(doc, { gitleaks: true, highEntropy: true });
  assert.equal(out.includes("MIIEvQIBADANBgkq"), false, "the block body must be redacted");
});

test("D2b: a trailing comment after a plain scalar is not swallowed [RED]", async () => {
  // D2a leaves ` # comment` inside the raw value on purpose: trimming it would be a
  // host-syntax rewrite, which this layer must not do. Recording the target here so
  // the limitation is explicit rather than accidental.
  const line = `password: ${SECRET}  # rotate quarterly`;
  const [binding] = parseYamlBindings(line);
  assert.ok(binding.raw.includes("# rotate quarterly"), "D2a currently keeps the comment inside the raw value");
  // Target: trim it. Pinned so the current limitation is explicit, not accidental.
  assert.equal(binding.raw.includes("# rotate quarterly"), false, "the comment must not be part of the value");
});

test("D2c: representation is decided by object-level schema, not by path [RED]", async () => {
  // Recorded as a placeholder so the requirement is visible in the test tree:
  // a `data:` subtree is only base64 when the OBJECT is a v1 Secret. A generic
  // `data.password` must keep a plain token.
  const generic = ["data:", `  password: ${SECRET}`].join("\n");
  const out = await redact(generic);
  assert.ok(out.includes(`password: ${TOKEN_PREFIX}`), "a generic data.password gets a plain portable token");
});
