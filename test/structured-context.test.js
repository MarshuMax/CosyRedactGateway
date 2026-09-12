// Structured context extraction tests.
//
// This group owns the `.env` / YAML / shell / HTTP header / URL query detection
// gap. It is deliberately separate from test/token-syntax.test.js, which owns the
// token format contract: token work must be able to go green without waiting for
// detector work, and detector work must be able to go green without touching the
// token format.
//
// Measured against current main (flags: {gitleaks:true}, and identically under
// the full flag set):
//
//   DB_PASSWORD=Pr0d-P@ssw0rd-Xy9Zk2mQ   MISS      (@ not in the value class)
//   DB_PASSWORD=hello123!                MISS      (! not in the value class)
//   password: Pr0d-P@ssw0rd-Xy9Zk2mQ     MISS
//   export TOKEN=Pr0d-P@ssw0rd-Xy9Zk2mQ  MISS
//   Authorization: Bearer Pr0d-P@ssw0r…  MISS
//   ?access_token=Pr0d-P@ssw0rd-Xy9Zk2mQ MISS
//
// Control cases that DO hit, which localise the defect precisely:
//
//   DB_PASSWORD=Pr0d-Passw0rdXy9Zk2mQ   HIT
//   DB_PASSWORD=SuperSecret123           HIT
//   DB_PASSWORD=cGFzc3dvcmQxMjM0NTY3OA== HIT
//   password: Pr0d-Passw0rdXy9Zk2mQ      HIT
//
// The left-hand keyword gate is therefore already satisfied in every failing
// case: `DB_PASSWORD` and `password` both match the generic-api-key keyword set.
// The defect is the value character class, which is
//
//   (?:[\w.=-]{10,150} | [a-z0-9][a-z0-9+/]{11,}={0,3})
//
// and rejects `@` and `!`. Real passwords overwhelmingly contain such symbols,
// so this is a systematic miss, not an edge case. Fixing it needs the surrounding
// binding form to be parsed (so the value can be taken as "everything up to the
// delimiter" rather than "a run of [\w.=-]"), which is the job of the structured
// context extractor.
//
// Assertion tags:
//   [GREEN NOW]  pins measured current behaviour
//   [RED]        target behaviour, currently failing

import test from "node:test";
import assert from "node:assert/strict";
import { RedactionContext, findSensitiveSpans, isRedactedText } from "../worker.js";

const GITLEAKS = { gitleaks: true };
const ALL = { highEntropy: true, phone: true, secret: true, identity: true, bank: true, email: true, gitleaks: true };

// A real-shaped production password: mixed case, digits, and two symbols.
const SECRET = "Pr0d-P@ssw0rd-Xy9Zk2mQ";

// Each case carries the binding form, the host syntax, and the exact byte range
// that must be redacted. `key` is the field name the surrounding syntax exposes;
// a structured extractor is expected to surface it as evidence.
const BINDING_FORMS = [
  { name: ".env assignment", syntax: "env", key: "DB_PASSWORD", line: `DB_PASSWORD=${SECRET}` },
  { name: "YAML mapping", syntax: "yaml", key: "password", line: `password: ${SECRET}` },
  { name: "shell export", syntax: "shell", key: "TOKEN", line: `export TOKEN=${SECRET}` },
  { name: "HTTP header", syntax: "http-header", key: "Authorization", line: `Authorization: Bearer ${SECRET}` },
  { name: "URL query", syntax: "url", key: "access_token", line: `https://api.example.com/v1?access_token=${SECRET}` },
  { name: "YAML base64 field", syntax: "yaml", key: "password", line: `data:\n  password: ${SECRET}` },
  { name: "spaced assignment", syntax: "env", key: "API_SECRET", line: `API_SECRET = ${SECRET}` },
];

// Values the current detector already catches, used as controls so a failure
// cannot be blamed on the binding form itself.
const DETECTED_VALUES = [
  ["alnum + dash", "Pr0d-Passw0rdXy9Zk2mQ"],
  ["plain alnum", "SuperSecret123"],
  ["base64 shape", "cGFzc3dvcmQxMjM0NTY3OA=="],
];

function redact(line, flags = GITLEAKS) {
  return new RedactionContext({ salt: "fixture" }).redactText(line, flags);
}

// ------------------------------------------------- 1. the measured defect ---

test("a dotted password in an .env assignment is redacted (D1 fixed the miss) [GREEN NOW]", async () => {
  // This used to pin the defect: the value class rejected `@`, so the secret was
  // forwarded verbatim. D1 structured context now supplies the span from the
  // binding itself, and the assertion is inverted to match.
  const line = `DB_PASSWORD=${SECRET}`;
  const out = await redact(line);
  assert.notEqual(out, line, "the value must no longer be forwarded verbatim");
  assert.equal(out.includes(SECRET), false, "the secret must not survive in the output");
});

test("key-name evidence is what closes the value-class gap [GREEN NOW]", async () => {
  // Localises the defect: same key name, only the value's character set differs.
  for (const [label, value] of DETECTED_VALUES) {
    const line = `DB_PASSWORD=${value}`;
    const out = await redact(line);
    assert.equal(isRedactedText(out), true, `${label} must be detected, proving the key gate passes`);
  }
  // Same key name, `@` in the value: now covered, because the binding supplies the
  // span instead of the value character class having to match.
  const dotted = `DB_PASSWORD=${SECRET}`;
  assert.equal((await redact(dotted)).includes(SECRET), false, "structured binding covers it");
});

test("D1+D2a cover the assignment and YAML-scalar families; header/URL remain [GREEN NOW]", async () => {
  // Slice baseline. D1 closed env/shell, D2a closed the simple YAML scalar
  // mapping (`password: xxx` and both quote styles). What is left is D2b (block
  // scalar), D2c (K8s Secret schema), and D3 (header + URL).
  const missed = [];
  for (const form of BINDING_FORMS) {
    const out = await redact(form.line);
    if (!out.includes(SECRET)) continue; // covered
    missed.push(form.name);
  }
  // The nested `data:\n  password: x` form is ALSO covered by D2a -- not because
  // base64 semantics are understood (that is D2c), but because a nested key is
  // still a simple scalar mapping and its span is the plain value. The base64
  // question is about the replacement FORMAT, not about whether the span is found.
  assert.deepEqual(missed, ["HTTP header", "URL query"]);
});

test("the fix is attributable to structured context, not another detector [GREEN NOW]", async () => {
  // Turning the structured detector off reproduces the old behaviour on the same
  // fixture, which is what makes D1 the attributable cause rather than, say, a
  // widened entropy threshold.
  const line = `DB_PASSWORD=${SECRET}`;
  const withStructured = await redact(line, { gitleaks: true, structuredContext: true });
  const without = await redact(line, { gitleaks: true, structuredContext: false });
  assert.equal(withStructured.includes(SECRET), false, "structured context covers it");
  assert.equal(without, line, "without structured context the value class still misses it");
});

// --------------------------------------------------- 2. target behaviour -----

const D1_FORMS = BINDING_FORMS.filter((f) => ["env", "shell"].includes(f.syntax) && !f.line.includes("\n"));
const D2A_FORMS = BINDING_FORMS.filter((f) => f.name === "YAML mapping");
const COVERED_FORMS = [...D1_FORMS, ...D2A_FORMS];
const D2_D3_FORMS = BINDING_FORMS.filter((f) => !D1_FORMS.includes(f));

test("D1: assignment-family bindings are redacted [GREEN NOW]", async () => {
  for (const form of D1_FORMS) {
    const out = await redact(form.line);
    assert.equal(out.includes(SECRET), false, `${form.name} must not forward the secret verbatim`);
  }
  assert.equal(D1_FORMS.length, 3, "fixture must cover .env, shell export and spaced assignment");
});

test("D3: header and URL bindings are not covered yet [RED]", async () => {
  // Baseline for the remaining slice. YAML scalar mapping moved to the D2a test
  // above when it landed; D2b (block scalar) and D2c (Secret schema) are about
  // span kinds and replacement FORMAT rather than key detection, and are tracked in
  // test/d2a-yaml.test.js.
  const pending = D2_D3_FORMS.filter((f) => !["YAML mapping", "YAML base64 field"].includes(f.name));
  assert.ok(pending.length >= 3, "fixture must still hold the pending forms");
  for (const form of pending) {
    const out = await redact(form.line);
    assert.equal(out.includes(SECRET), false, `${form.name} must not forward the secret verbatim`);
  }
});

test("redaction covers exactly the value, not the binding syntax [GREEN NOW]", async () => {
  for (const form of COVERED_FORMS) {
    const out = await redact(form.line);
    // Guard: without this the prefix/suffix assertions below pass vacuously
    // whenever the value was not redacted at all, which is the current state.
    assert.equal(isRedactedText(out), true, `${form.name}: value must be redacted before bounds can be checked`);
    const before = form.line.slice(0, form.line.indexOf(SECRET));
    assert.ok(out.startsWith(before), `${form.name}: the key/binding prefix must survive untouched`);
    assert.ok(out.endsWith(form.line.slice(form.line.indexOf(SECRET) + SECRET.length)), `${form.name}: the suffix must survive`);
  }
});

test("round-trip is byte-identical once the value is redacted [GREEN NOW]", async () => {
  const ctx = new RedactionContext({ salt: "fixture" });
  for (const form of COVERED_FORMS) {
    const out = await ctx.redactText(form.line, GITLEAKS);
    assert.equal(isRedactedText(out), true, `${form.name}: value must be redacted before round-trip is meaningful`);
    assert.equal(ctx.restoreText(out), form.line, `${form.name}: round-trip must be byte-identical`);
  }
});

test("structured extraction exposes the key name as evidence [GREEN NOW]", () => {
  // The D1 interface: a binding span carries the enclosing field name and the
  // evidence that produced it, so a low-entropy value is protected on key evidence
  // alone. YAML/header/URL forms are D2/D3 and are excluded here.
  for (const form of COVERED_FORMS) {
    const spans = findSensitiveSpans(form.line, GITLEAKS);
    const hit = spans.find((x) => x.type === "binding" && x.key);
    assert.ok(hit, `${form.name}: expected a binding span`);
    assert.equal(hit.key, form.key, `${form.name}: span must carry the enclosing key name`);
    assert.equal(hit.syntax, form.syntax, `${form.name}: span must carry the syntax`);
    assert.ok(hit.evidence.includes("strong_secret_key"), `${form.name}: strong key evidence`);
  }
});

test("an unquoted low-entropy password is protected by key evidence [RED]", async () => {
  // Entropy cannot help here; only the key name can. This is the case that
  // justifies structured extraction over widening the value character class.
  const line = "DB_PASSWORD=hello123!";
  const out = await redact(line, ALL);
  assert.equal(isRedactedText(out), true, "a low-entropy password must be redacted on key evidence");
});

// --------------------------------------------- 5. keyword gate coverage gaps ---

test("strong vs weak key tiers, measured after D1 [GREEN NOW]", async () => {
  // What the tiers actually buy, asserted against the implementation:
  //   - strong names (password / secret / token / api_key) protect any value shape
  //   - weak names (bare `key`, `cache_key`, metadata suffixes) stay inert
  //   - a reference value is never treated as a literal secret
  //
  // Corrected fixture: `keystore_path` is NOT a strong name (it is a path), so it is
  // asserted with the inert group rather than the strong one.
  const changed = async (line) => (await redact(line)) !== line;

  assert.equal(await changed("DB_PASSWORD=SuperSecret123"), true, "password tier");
  assert.equal(await changed("API_KEY=SuperSecret123"), true, "api_key is in the strong tier");
  assert.equal(await changed("API_SECRET = valued"), true, "spaces around `=` are allowed");

  for (const key of ["cache_key", "partition_key", "SORT_KEY", "secret_name", "private_key_path", "keystore_path"]) {
    const line = `${key}=not-a-secret-value`;
    assert.equal(await changed(line), false, `${key} must stay inert`);
  }
  for (const line of ["PASSWORD=${PASSWORD}", "PASSWORD=$PASSWORD", "PASSWORD={{ some_template }}"]) {
    assert.equal(await changed(line), false, `${line} is a reference, not a literal secret`);
  }
});
