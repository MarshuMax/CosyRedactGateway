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
  findSensitiveSpans,
  bindingSpansOf,
  classifyRestore,
  classifyOwnership,
  resolveSurrogate,
  PATH_CONFIDENCE,
  SENSITIVE_SINK_KINDS,
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

// ------------------------------------------------- 4b. D2b-2 block scalars ----

// Unindented on purpose: the fixtures below interpolate these with their own two
// spaces, so carrying indentation here would double it and the assertion on body
// indentation would be testing the fixture instead of the parser.
const PEM_BODY = [
  "-----BEGIN PRIVATE KEY-----",
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj",
  "-----END PRIVATE KEY-----",
].map((line) => `  ${line}`);

// The indicator family that has to be recognised (YAML 9.1.1: chomping and an
// explicit indentation indicator, in either order).
const BLOCK_INDICATORS = ["|", "|-", "|+", ">", ">-", ">+", "|2", "|+2", "|2+"];

test("D2b-2: every block indicator form is recognised [GREEN NOW]", () => {
  for (const indicator of BLOCK_INDICATORS) {
    const doc = [`secret: ${indicator}`, "  body line"].join("\n");
    const binding = parseYamlBindings(doc).find((b) => b.bodyCandidate);
    assert.ok(binding, `${indicator}: the body must be located`);
    assert.equal(binding.raw, "body line", `${indicator}: the span is the body text`);
    assert.ok(binding.evidence.includes("block_scalar_body"));
  }
});

test("D2b-2: only the body is replaced, indentation and indicator survive [GREEN NOW]", async () => {
  for (const indicator of BLOCK_INDICATORS) {
    const doc = [`private_key: ${indicator}`, ...PEM_BODY, "next: value"].join("\n");
    const out = await redact(doc, { gitleaks: true, highEntropy: true });
    assert.ok(out.startsWith(`private_key: ${indicator}\n`), `${indicator}: the indicator line must survive`);
    assert.ok(out.includes("\n  "), `${indicator}: body indentation must survive`);
    assert.ok(out.includes("next: value"), `${indicator}: the following dedented key must survive`);
  }
});

test("D2b-2: a multi-line body is never replaced by a span crossing only part of it [GREEN NOW]", async () => {
  // Measured, and this is the reason the per-line candidates exist: a span that
  // crosses lines CANNOT be replaced without breaking the block's indentation
  // requirement. Replacing a multi-line body with one unindented token produces
  // `ScannerError: while scanning a simple key`.
  //
  // What must hold instead:
  //   - nothing from the body leaks,
  //   - every remaining body line keeps its indentation,
  //   - the block header and the following dedented key survive,
  //   - the document still parses.
  //
  // A provider rule may legitimately cover the whole block (the PEM rule matches
  // BEGIN..END as one unit) -- that is a full-block replacement, which is fine
  // because the indentation of the first body line is preserved.
  const doc = ["private_key: |", ...PEM_BODY, "next: value"].join("\n");
  const out = await redact(doc, { gitleaks: true, highEntropy: true });

  assert.equal(out.startsWith("private_key: |\n"), true, "the indicator line must survive");
  assert.equal(out.includes("next: value"), true, "the following dedented key must survive");
  for (const fragment of ["BEGIN PRIVATE KEY", "MIIEvQIBADANBgkq", "END PRIVATE KEY"]) {
    assert.equal(out.includes(fragment), false, `body content must not leak: ${fragment}`);
  }
  for (const line of out.split("\n").slice(1)) {
    if (line === "next: value") continue;
    assert.equal(line.startsWith("  "), true, `body line must stay indented: ${JSON.stringify(line)}`);
  }
  assert.equal(out.split("\n").length <= doc.split("\n").length, true, "no lines may be added");
});

test("D2b-2: a partial-line span never runs past the end of its line [GREEN NOW]", async () => {
  // Reproduces a real defect: the second body line's end offset was computed from
  // the trimmed length of the whole line rather than the offset of the content, so
  // the span ran into the next line and the three per-line candidates ended up
  // adjacent and mutually overlapping.
  const doc = ["key: |", "  first line", "  second line", "next: v"].join("\n");
  const spans = findSensitiveSpans(doc, { gitleaks: true, structuredContext: true })
    .filter((s) => s.type === "block_scalar");
  for (const span of spans) {
    const slice = doc.slice(span.start, span.end);
    assert.equal(slice.includes("\n"), false, `a per-line span must not contain a newline: ${JSON.stringify(slice)}`);
  }
});

test("D2b-2: the redacted document still parses as YAML [GREEN NOW]", async () => {
  // Structural assertions are not enough; the document has to be re-parseable. This
  // runs a minimal parser over the result and requires a mapping with the expected
  // keys -- a truncated or mis-indented block fails here.
  const doc = ["private_key: |", ...PEM_BODY, "next: value"].join("\n");
  const out = await redact(doc, { gitleaks: true, highEntropy: true });
  const parsed = parseSimpleMappingShape(out);
  assert.deepEqual(parsed, ["private_key", "next"], "the mapping keys must survive");
});

test("D2b-2: round-trip is byte-identical for every indicator [GREEN NOW]", async () => {
  for (const indicator of BLOCK_INDICATORS) {
    const doc = [`private_key: ${indicator}`, ...PEM_BODY, "next: value"].join("\n");
    const ctx = new RedactionContext({ salt: "fixture" });
    const out = await ctx.redactText(doc, { gitleaks: true, highEntropy: true });
    assert.equal(ctx.restoreText(out), doc, `${indicator}: restore must reproduce the document`);
  }
});

test("D2b-3: a block body that is only a reference stays untouched [GREEN NOW]", async () => {
  // The previous version of this test asserted only the evidence layer
  // (`strength === none`) and passed while the final behaviour was wrong: the body
  // candidate was an unconditional redaction span, so the template reference was
  // replaced with a token and the indirection it exists to provide was destroyed.
  const docs = [
    ["password: |", "  ${{ secrets.DB_PASSWORD }}"].join("\n"),
    ["password: |", "  ${{ secrets.A }}", "  ${{ secrets.B }}"].join("\n"),
    ["password: |", "  ${DB_PASSWORD}"].join("\n"),
  ];
  for (const doc of docs) {
    const out = await redact(doc, { gitleaks: true, highEntropy: true });
    assert.equal(out, doc, `a reference-only body must not be rewritten: ${JSON.stringify(doc)}`);
  }
});

// Minimal structural re-parse: returns the top-level keys of a block mapping, and
// throws if the document is not a well-formed block mapping. Deliberately narrow --
// it exists to catch truncated or de-indented blocks, not to be a YAML engine.
function parseSimpleMappingShape(doc) {
  const keys = [];
  let inBlock = false;
  let blockIndent = -1;
  for (const line of doc.split("\n")) {
    if (line.trim() === "") continue;
    const indent = line.match(/^ */)[0].length;
    if (inBlock) {
      if (indent > blockIndent) continue; // still inside the block body
      inBlock = false;
    }
    const m = /^([A-Za-z_][A-Za-z0-9_-]*):(?:[ \t]+(.*))?$/.exec(line);
    if (!m) throw new Error(`not a block-mapping key line: ${JSON.stringify(line)}`);
    keys.push(m[1]);
    if (m[2] !== undefined && /^[|>][0-9+-]*$/.test(m[2].trim())) {
      inBlock = true;
      blockIndent = indent;
    }
  }
  return keys;
}

// ------------------------------------------------- 4c. D2b-3 precision -------

// A block body is a REGION the parser records, not a redaction span. Emitting every
// body line as a span turned each block scalar into a redaction surface: `notes: |`,
// `description: |` and `script: |` are common in README/Helm/K8s annotations and none
// of them are secret. The decision belongs to key strength or to a content detector.

const LONG_PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKjM5bGZkZ2Fh";

test("D2b-3: an ordinary documentation block is untouched [GREEN NOW]", async () => {
  const docs = [
    ["notes: |", "  deployment completed successfully", "  restart the service after upgrade"].join("\n"),
    ["description: |", "  This chart deploys the API.", "  See README for details."].join("\n"),
    ["script: |", "  echo hello", "  echo world"].join("\n"),
    ["message: |", "  Rollback finished at 12:04.", "  No action required."].join("\n"),
  ];
  for (const doc of docs) {
    const out = await redact(doc, { gitleaks: true, highEntropy: true });
    assert.equal(out, doc, `must stay inert: ${JSON.stringify(doc)}`);
  }
});

test("D2b-3: a weak/absent key yields a region record and zero spans [GREEN NOW]", () => {
  const doc = ["notes: |", "  ordinary documentation", "  second line"].join("\n");
  const records = parseYamlBindings(doc);
  assert.equal(records.length, 1, "the region is recorded");
  assert.equal(records[0].regionOnly, true, "and it is marked region-only");
  assert.ok(records[0].evidence.includes("block_scalar_region"));
  assert.equal("strength" in records[0] && records[0].strength, "none");
  // The decisive assertion: a region record contributes no redaction span.
  assert.deepEqual(bindingSpansOf(doc, "binding", parseYamlBindings), []);
});

test("D2b-3: a strong parent key protects every body line [GREEN NOW]", async () => {
  const doc = ["password: |", "  lowentropy", "  anotherline"].join("\n");
  const out = await redact(doc, { gitleaks: true, highEntropy: true });
  assert.equal(out.includes("lowentropy"), false, "first line protected on key evidence");
  assert.equal(out.includes("anotherline"), false, "second line protected on key evidence");
  assert.equal(out.includes("password: |"), true, "the indicator survives");
  const ctx = new RedactionContext({ salt: "fixture" });
  assert.equal(ctx.restoreText(out) === doc || out.split("\n").length === doc.split("\n").length, true);
});

test("D2b-3: a PEM under a weak key is redacted by the provider rule, not the parser [GREEN NOW]", async () => {
  // Attribution guard. Without the second half, an unconditional body candidate
  // would keep this green and hide the fact that the parser was doing the work.
  const doc = ["notes: |", "  -----BEGIN PRIVATE KEY-----", `  ${LONG_PEM_BODY}`, "  -----END PRIVATE KEY-----"].join("\n");

  const withG = await redact(doc, { gitleaks: true, highEntropy: false });
  assert.notEqual(withG, doc, "with the provider rule on, the key material is redacted");

  const withoutG = await redact(doc, { gitleaks: false, highEntropy: false });
  assert.equal(withoutG, doc, "with the provider rule off, the structured layer must NOT redact it");
});

test("D2b-3: the PEM body length matters (fixture legality) [GREEN NOW]", async () => {
  // A control for the guard above: the private-key rule needs >= 64 characters of
  // body, so a short fixture is not detected even with the rule on. Recorded because
  // an illegal fixture previously produced a wrong conclusion about this code path.
  const shortDoc = ["notes: |", "  -----BEGIN PRIVATE KEY-----", "  MIIEvQIBADANBgkq", "  -----END PRIVATE KEY-----"].join("\n");
  assert.equal(await redact(shortDoc, { gitleaks: true, highEntropy: false }), shortDoc,
    "an under-length body does not satisfy the provider rule");
});

// ------------------------------------------------- 5. D2c known gap (base64) ---

const K8S_SECRET_B64 = [
  "apiVersion: v1",
  "kind: Secret",
  "metadata:",
  "  name: db-creds",
  "type: Opaque",
  "data:",
  "  password: YWRtaW4xMjM0NTY3OA==",
].join("\n");

const K8S_SECRET_STRINGDATA = [
  "apiVersion: v1",
  "kind: Secret",
  "metadata:",
  "  name: db-creds",
  "type: Opaque",
  "stringData:",
  "  password: adm1n-p@ssw0rd",
].join("\n");

function isCanonicalBase64(value) {
  if (typeof value !== "string" || value.length === 0) return false;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
  if (value.length % 4 !== 0) return false;
  return Buffer.from(value, "base64").toString("base64") === value;
}

test("D2c: a v1 Secret under root data.* keeps a valid base64 replacement [GREEN NOW]", async () => {
  // Was an executable spec for a known regression; the surrogate ledger and the
  // object-level recogniser now close it.
  const ctx = new RedactionContext({ salt: "fixture" });
  const out = await ctx.redactText(K8S_SECRET_B64, { gitleaks: true });
  const replaced = (out.match(/^\s+password:\s*(\S+)\s*$/m) || [])[1];
  assert.ok(replaced, "a replacement must be present");
  assert.equal(isCanonicalBase64(replaced), true, `Secret.data must keep canonical base64, got: ${replaced}`);
  assert.notEqual(replaced, "YWRtaW4xMjM0NTY3OA==", "the plaintext must actually be replaced");
  // And the representation is recoverable: the original document comes back byte for byte.
  assert.equal(ctx.restoreText(out), K8S_SECRET_B64, "restore must be byte-identical");
});

test("D2c: only a v1 Secret gets the base64 surrogate, and only under root data [GREEN NOW]", async () => {
  const cases = [
    ["ConfigMap", ["apiVersion: v1", "kind: ConfigMap", "data:", "  password: YWRtaW4xMjM0NTY3OA=="].join("\n")],
    ["no apiVersion", ["kind: Secret", "data:", "  password: YWRtaW4xMjM0NTY3OA=="].join("\n")],
    ["v2 apiVersion", ["apiVersion: v2", "kind: Secret", "data:", "  password: YWRtaW4xMjM0NTY3OA=="].join("\n")],
    ["generic data block", ["data:", "  password: YWRtaW4xMjM0NTY3OA=="].join("\n")],
    ["nested data", ["apiVersion: v1", "kind: Secret", "spec:", "  data:", "    password: YWRtaW4xMjM0NTY3OA=="].join("\n")],
  ];
  for (const [label, doc] of cases) {
    const ctx = new RedactionContext({ salt: "fixture" });
    const out = await ctx.redactText(doc, { gitleaks: true });
    const replaced = (out.match(/^\s+password:\s*(\S+)\s*$/m) || [])[1];
    assert.ok(replaced, `${label}: a replacement must be present`);
    assert.equal(
      isCanonicalBase64(replaced),
      false,
      `${label} must NOT be treated as base64: got ${replaced}`
    );
  }
});

test("D2c: a stringData sibling is not given the data encoding [GREEN NOW]", async () => {
  const doc = [
    "apiVersion: v1",
    "kind: Secret",
    "data:",
    "  password: YWRtaW4xMjM0NTY3OA==",
    "stringData:",
    "  token: adm1n-p@ssw0rd",
  ].join("\n");
  const ctx = new RedactionContext({ salt: "fixture" });
  const out = await ctx.redactText(doc, { gitleaks: true });
  const dataValue = (out.match(/^\s+password:\s*(\S+)\s*$/m) || [])[1];
  const stringValue = (out.match(/^\s+token:\s*(\S+)\s*$/m) || [])[1];
  assert.equal(isCanonicalBase64(dataValue), true, "root data keeps base64");
  assert.equal(stringValue.startsWith("CRG_"), true, `stringData keeps a plain token, got ${stringValue}`);
  assert.equal(ctx.restoreText(out), doc, "round-trip is byte-identical across both blocks");
});

test("D2c: the surrogate is registered in the ledger, not derivable by shape [GREEN NOW]", async () => {
  // `restoreText` recognises tokens by SHAPE, so a base64 surrogate is invisible to
  // it. The ledger is what makes the round trip work, and only strings this request
  // minted are eligible -- unrelated base64 must not be decoded and looked up.
  const ctx = new RedactionContext({ salt: "fixture" });
  const out = await ctx.redactText(K8S_SECRET_B64, { gitleaks: true });
  const visible = (out.match(/^\s+password:\s*(\S+)\s*$/m) || [])[1];

  const entries = ctx.ledger.entries();
  assert.equal(entries.length, 1, "exactly one surrogate was minted");
  assert.equal(entries[0].visible, visible);
  assert.equal(entries[0].encodingKind, "base64");
  assert.equal(ctx.tokenToRaw.has(entries[0].token), true, "and it maps back to an owned token");

  // An unrelated base64 string in the same payload is left alone.
  const unrelated = "YWJjZGVmZ2hpams=";
  assert.equal(ctx.restoreText(`x: ${unrelated}`), `x: ${unrelated}`, "only minted surrogates are eligible");
});

test("D2c control: root stringData.* accepts a plain portable token [GREEN NOW]", async () => {
  // The control case. stringData is explicitly arbitrary text, so a portable token
  // is the correct replacement and no surrogate is needed. Asserting both sides
  // keeps the D2c requirement honest: it is about REPRESENTATION, not about
  // detecting that the document is a Secret.
  const ctx = new RedactionContext({ salt: "fixture" });
  const out = await ctx.redactText(K8S_SECRET_STRINGDATA, { gitleaks: true });
  assert.equal(out.includes("adm1n-p@ssw0rd"), false, "the value must be redacted");
  const replaced = (out.match(/^\s+password:\s*(\S+)\s*$/m) || [])[1];
  assert.ok(replaced.startsWith(TOKEN_PREFIX), `stringData gets a plain token, got: ${replaced}`);
  assert.equal(isCanonicalBase64(replaced), false, "and it is deliberately not base64");
  assert.equal(ctx.restoreText(out), K8S_SECRET_STRINGDATA, "round-trip is byte-identical");
});

test("D2c: a generic data.password is NOT base64 [GREEN NOW]", async () => {
  // Guards the other direction. Ordinary application config can have a `data`
  // block; treating every `data.*` as base64 would corrupt unrelated YAML.
  const doc = ["data:", "  password: adm1n-p@ssw0rd"].join("\n");
  const ctx = new RedactionContext({ salt: "fixture" });
  const out = await ctx.redactText(doc, { gitleaks: true });
  const replaced = (out.match(/^\s+password:\s*(\S+)\s*$/m) || [])[1];
  assert.ok(replaced.startsWith(TOKEN_PREFIX), `expected a portable token, got: ${replaced}`);
  assert.equal(isCanonicalBase64(replaced), false, "a non-Secret data block must not get base64");
});

// ------------------------------------------------ 6. D2c.2 policy convergence ---

test("D2c.2: a surrogate is judged exactly like its underlying token [GREEN NOW]", async () => {
  // A shortcut branch here would drift the moment entityClassFor starts returning
  // real classes: an INFRA entity would then behave differently depending on whether
  // its replacement happened to be base64. The surrogate is resolved to its token and
  // the SAME policy runs.
  const ctx = new RedactionContext({ salt: "fixture" });
  const out = await ctx.redactText(K8S_SECRET_B64, { gitleaks: true });
  const visible = (out.match(/^\s+password:\s*(\S+)\s*$/m) || [])[1];
  assert.ok(visible, "a surrogate must have been minted");

  const registry = null;
  const withSurrogate = (kind, trust = "untrusted") =>
    classifyRestore({ ctx, registry, text: `use ${visible}`, sink: { kind, trust } });

  // UNKNOWN/CREDENTIAL surrogate + untrusted sensitive sink -> block.
  for (const kind of SENSITIVE_SINK_KINDS) {
    const d = withSurrogate(kind);
    assert.equal(d.action, "block", `${kind}: blocked`);
    assert.equal(d.telemetry.event, "restore_blocked_untrusted_sink");
    assert.deepEqual(d.blockedTokens, [visible]);
  }
  // assistant text and benign sinks -> restore.
  assert.equal(withSurrogate("assistant_text").action, "restore");
  assert.equal(withSurrogate("log_write").action, "restore");
  // trusted sink -> restore.
  assert.equal(withSurrogate("shell", "trusted").action, "restore");
});

test("D2c.2: the surrogate resolves to its underlying token for ownership [GREEN NOW]", async () => {
  const ctx = new RedactionContext({ salt: "fixture" });
  const out = await ctx.redactText(K8S_SECRET_B64, { gitleaks: true });
  const visible = (out.match(/^\s+password:\s*(\S+)\s*$/m) || [])[1];

  const resolved = resolveSurrogate(visible, ctx);
  assert.notEqual(resolved, visible, "a surrogate resolves to something else");
  assert.equal(resolved.startsWith("CRG_"), true, "and that something is the underlying token");
  assert.equal(ctx.tokenToRaw.has(resolved), true, "which this request owns");

  const classified = classifyOwnership(visible, ctx);
  assert.equal(classified.ownership, "OWN", "ownership is decided on the entity, not the representation");
  assert.equal(classified.token, resolved, "and the underlying token is reported");
  // A non-surrogate is returned unchanged.
  assert.equal(resolveSurrogate("CRG_AAAA_AAAA", ctx), "CRG_AAAA_AAAA");
});

test("D2c.2: an INFRA-classed surrogate follows the entity policy, not a shortcut [GREEN NOW]", async () => {
  // Proves there is no separate surrogate branch left. With entityClassFor returning
  // INFRA, the credential-risk test is false, so the surrogate is NOT blocked in an
  // untrusted sensitive sink -- exactly as a plain INFRA token would not be.
  const ctx = new RedactionContext({ salt: "fixture" });
  const out = await ctx.redactText(K8S_SECRET_B64, { gitleaks: true });
  const visible = (out.match(/^\s+password:\s*(\S+)\s*$/m) || [])[1];

  const before = classifyRestore({ ctx, text: visible, sink: { kind: "shell" } }).action;
  assert.equal(before, "block", "baseline: UNKNOWN is treated as credential-grade risk");

  const original = ctx.entityClassFor;
  ctx.entityClassFor = () => "INFRA";
  try {
    const after = classifyRestore({ ctx, text: visible, sink: { kind: "shell" } }).action;
    assert.equal(after, "restore", "an INFRA entity is not credential-grade, so no block");
    // The same must hold for a plain token with the same class, or the two paths diverge.
    const plain = Object.keys(Object.fromEntries(ctx.tokenToRaw))[0];
    const plainResult = classifyRestore({ ctx, text: plain, sink: { kind: "shell" } }).action;
    assert.equal(plainResult, after, "surrogate and plain token must agree under the same entity class");
  } finally {
    ctx.entityClassFor = original;
  }
});
