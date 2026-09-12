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

test("dotted password in an .env assignment is missed today [GREEN NOW]", async () => {
  const line = `DB_PASSWORD=${SECRET}`;
  assert.equal(await redact(line), line, "current behaviour: the value is forwarded verbatim");
});

test("the keyword gate is already satisfied, the value class is what fails [GREEN NOW]", async () => {
  // Localises the defect: same key name, only the value's character set differs.
  for (const [label, value] of DETECTED_VALUES) {
    const line = `DB_PASSWORD=${value}`;
    const out = await redact(line);
    assert.equal(isRedactedText(out), true, `${label} must be detected, proving the key gate passes`);
  }
  // Same key name, `@` in the value: missed.
  const dotted = `DB_PASSWORD=${SECRET}`;
  assert.equal(isRedactedText(await redact(dotted)), false, "a symbol-bearing value is still missed");

  // And the same holds without any surrounding syntax at all: the value class is
  // the discriminator, so the binding form adds no protection either.
  assert.notEqual((await redact(`DB_PASSWORD=${SECRET}`)).length, (await redact(`DB_PASSWORD=Pr0d-Passw0rdXy9Zk2mQ`)).length);
});

test("every binding form misses a symbol-bearing password [GREEN NOW]", async () => {
  const missed = [];
  for (const form of BINDING_FORMS) {
    const out = await redact(form.line);
    if (!isRedactedText(out)) missed.push(form.name);
  }
  assert.deepEqual(missed, BINDING_FORMS.map((f) => f.name), "all six forms currently miss");
});

test("the miss is identical under the full flag set [GREEN NOW]", async () => {
  // Rules out the possibility that some other detector (secret, entropy) is
  // supposed to cover this and only the `G` flag was missing.
  for (const form of BINDING_FORMS) {
    const out = await redact(form.line, ALL);
    assert.equal(out, form.line, `${form.name} is missed with every detector enabled`);
  }
});

// --------------------------------------------------- 2. target behaviour -----

test("a symbol-bearing password is redacted in every binding form [RED]", async () => {
  for (const form of BINDING_FORMS) {
    const out = await redact(form.line);
    assert.equal(isRedactedText(out), true, `${form.name} must be redacted`);
    assert.equal(out.includes(SECRET), false, `${form.name} must not forward the secret verbatim`);
  }
});

test("redaction covers exactly the value, not the binding syntax [RED]", async () => {
  for (const form of BINDING_FORMS) {
    const out = await redact(form.line);
    // Guard: without this the prefix/suffix assertions below pass vacuously
    // whenever the value was not redacted at all, which is the current state.
    assert.equal(isRedactedText(out), true, `${form.name}: value must be redacted before bounds can be checked`);
    const before = form.line.slice(0, form.line.indexOf(SECRET));
    assert.ok(out.startsWith(before), `${form.name}: the key/binding prefix must survive untouched`);
    assert.ok(out.endsWith(form.line.slice(form.line.indexOf(SECRET) + SECRET.length)), `${form.name}: the suffix must survive`);
  }
});

test("round-trip is byte-identical once the value is redacted [RED]", async () => {
  const ctx = new RedactionContext({ salt: "fixture" });
  for (const form of BINDING_FORMS) {
    const out = await ctx.redactText(form.line, GITLEAKS);
    assert.equal(isRedactedText(out), true, `${form.name}: value must be redacted before round-trip is meaningful`);
    assert.equal(ctx.restoreText(out), form.line, `${form.name}: round-trip must be byte-identical`);
  }
});

test("structured extraction exposes the key name as evidence [RED]", () => {
  // The target interface: span detection should surface the enclosing field name
  // so that a low-entropy value is still protected on key evidence alone.
  for (const form of BINDING_FORMS) {
    const spans = findSensitiveSpans(form.line, GITLEAKS);
    const hit = spans.find((s) => form.line.slice(s.start, s.end).includes(SECRET));
    assert.ok(hit, `${form.name}: expected a span covering the value`);
    assert.equal(hit.key, form.key, `${form.name}: span should carry the enclosing key name`);
  }
});

test("an unquoted low-entropy password is protected by key evidence [RED]", async () => {
  // Entropy cannot help here; only the key name can. This is the case that
  // justifies structured extraction over widening the value character class.
  const line = "DB_PASSWORD=hello123!";
  const out = await redact(line, ALL);
  assert.equal(isRedactedText(out), true, "a low-entropy password must be redacted on key evidence");
});
