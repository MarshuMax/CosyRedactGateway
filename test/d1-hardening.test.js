// D1.1 hardening: shared evidence-layer invariants that the D2 YAML adapter and
// everything after it will depend on.
//
// Three problems, all reproduced before being fixed:
//
//  1. Key classification was a substring match, so `secret_name`,
//     `private_key_path` and `client_secret_ref` escalated to hard secrets. In
//     Kubernetes those are ordinary fields whose values are names and references;
//     upgrading them would redact identifiers and corrupt manifests. This matters
//     more once YAML parsing lands, so it is pinned before D2 rather than after.
//
//  2. The span merge was priority-then-drop, which lost redaction BOUNDS:
//
//       DB_PASSWORD="prefix <PAT> suffix"
//                    └──── binding span (whole value) ────┘
//                          └── narrower provider hit ──┘
//
//     The narrow hit won on priority and the enclosing binding span was discarded
//     for overlapping it, so only the PAT was masked and the rest of the password
//     stayed in the clear. A strong binding now decides the bounds and inherits the
//     inner hit's evidence, so attribution survives too.
//
//  3. GitHub Actions `${{ secrets.X }}` was not recognised as a reference, so the
//     leading `${{` was treated as a literal secret.
//
// Assertion tags:
//   [GREEN NOW]  passes against the current tree

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  findSensitiveSpans,
  parseBindings,
  classifyKeyStrength,
  KEY_STRENGTH,
} from "../worker.js";

const PAT = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
const FLAGS = { gitleaks: true };

function redact(line, flags = FLAGS) {
  return new RedactionContext({ salt: "fixture" }).redactText(line, flags);
}

// ------------------------------------------- 1. key semantic boundaries ------

test("metadata/name/path/ref fields are not upgraded on a substring match [GREEN NOW]", () => {
  // Weak: names a location, a reference or derived data rather than the secret.
  for (const key of [
    "secret_name", "secretName", "secret_key_ref", "private_key_path",
    "password_file", "password_file_path", "client_secret_ref", "token_id",
    "token_type", "password_hash", "secret_dir", "api_key_file", "keystore_path",
  ]) {
    assert.notEqual(
      classifyKeyStrength(key),
      KEY_STRENGTH.STRONG,
      `${key} must not be strong: its value is metadata, not the secret`
    );
  }
  // Strong: the secret word is the head noun.
  for (const key of [
    "password", "db_password", "secret", "client_secret", "token", "api_key",
    "access_key", "private_key", "signing_key", "access_token", "password_value",
  ]) {
    assert.equal(classifyKeyStrength(key), KEY_STRENGTH.STRONG, `${key} must stay strong`);
  }
});

test("canonical credential names survive their own metadata-looking suffix [GREEN NOW]", () => {
  // `api_key` ends in `_key`, which is a metadata suffix. An explicit canonical
  // list has to win, otherwise the most common field name on earth is demoted.
  for (const key of [
    "api_key", "access_key", "secret_key", "private_key",
    "signing_key", "encryption_key", "session_key", "master_key", "client_key",
    "consumer_key", "secret_access_key",
  ]) {
    assert.equal(classifyKeyStrength(key), KEY_STRENGTH.STRONG, `${key} is a credential name`);
  }
  // The one deliberate omission from the same naming family: a public key is not a
  // secret, and treating it as one would only widen the false-positive surface.
  assert.notEqual(classifyKeyStrength("public_key"), KEY_STRENGTH.STRONG, "public_key is not a secret");
});

test("a metadata-named field is left alone end to end [GREEN NOW]", async () => {
  const line = `secret_name=${PAT}`;
  const out = await redact(line, { gitleaks: true, highEntropy: true });
  // The PAT itself is still a detectable secret, so it may be redacted; the point
  // is that the binding layer does not independently escalate the field.
  const binding = parseBindings(line).find((b) => b.strength === KEY_STRENGTH.STRONG);
  assert.equal(binding, undefined, "secret_name must not yield strong binding evidence");
  void out;
});

// ------------------------------------------- 2. containment merge -------------

test("a strong binding wins the redaction bounds over a narrower hit [GREEN NOW]", async () => {
  // The regression: the enclosing value must be redacted in full, not just the
  // provider-shaped fragment inside it.
  const cases = [
    ["unterminated quote", `DB_PASSWORD="prefix ` + PAT + ` suffix`],
    ["closed quote", `DB_PASSWORD="prefix ${PAT} suffix"`],
    ["bare with spaces", `DB_PASSWORD=correct horse battery staple`],
    ["export form", `export API_KEY=before ${PAT} after`],
  ];
  for (const [label, line] of cases) {
    const out = await redact(line);
    assert.equal(out.includes(PAT), false, `${label}: the provider-shaped fragment must be gone`);
    assert.equal(out.includes("prefix"), false, `${label}: the leading remainder must be gone`);
    assert.equal(out.includes("suffix"), false, `${label}: the trailing remainder must be gone`);
    assert.equal(out.includes("correct horse"), false, `${label}: the whole value must be gone`);
  }
});

test("the surviving span covers exactly the full binding value [GREEN NOW]", () => {
  const line = `DB_PASSWORD="prefix ${PAT} suffix"`;
  const binding = parseBindings(line)[0];
  const spans = findSensitiveSpans(line, FLAGS);
  const covering = spans.find((s) => s.start <= binding.valueStart && s.end >= binding.valueEnd);
  assert.ok(covering, "a span must cover the whole binding value");
  assert.equal(covering.start, binding.valueStart, "span starts at the value, not inside it");
  assert.equal(covering.end, binding.valueEnd, "span ends at the value, not inside it");
  // Bounds come from the binding; attribution stays with the provider rule.
  assert.equal(covering.providerType, "binding");
  assert.equal(covering.type, "gitleaks");
  assert.ok(covering.evidence.includes("strong_secret_key"), "binding evidence is retained");
  assert.ok(covering.evidence.includes("gitleaks"), "provider evidence is retained");
});

test("a provider hit outside any binding is unaffected [GREEN NOW]", async () => {
  const line = `the token is ${PAT} here`;
  const out = await redact(line);
  assert.equal(out.includes(PAT), false);
  assert.ok(out.includes("the token is"), "surrounding prose is untouched");
  assert.ok(out.includes("here"), "surrounding prose is untouched");
});

test("absorbed spans are not emitted twice with the same priority [GREEN NOW]", () => {
  // Both entries would inherit the same priority after absorption, and the narrow
  // one could win the overlap race, restoring the bounds bug.
  const line = `DB_PASSWORD="${PAT}"`;
  const spans = findSensitiveSpans(line, FLAGS);
  const identicalPairs = spans.filter((a, i) => spans.some((b, j) => j > i && a.start === b.start && a.end === b.end));
  assert.deepEqual(identicalPairs, [], "no duplicate spans at identical bounds");
  assert.equal(spans.length, 1, "exactly one surviving span for a fully contained value");
});

// ------------------------------------------- 3. reference forms ---------------

test("GitHub Actions and command-substitution references are inert [GREEN NOW]", async () => {
  // Each of these REFERS to a secret. Substituting a token would replace a template
  // or a command substitution with a literal, corrupting the file and, in the $( )
  // case, removing the indirection that keeps the secret off disk.
  for (const value of [
    "${{ secrets.DB_PASSWORD }}",
    "${{secrets.DB_PASSWORD}}",
    "${{ secrets['DB_PASSWORD'] }}",
    "${DB_PASSWORD}",
    "$DB_PASSWORD",
    "$(cat /run/secrets/db_password)",
    "$(vault kv get -field=password secret/db)",
    "{{ .Values.dbPassword }}",
    "%DB_PASSWORD%",
    "<DB_PASSWORD>",
  ]) {
    const line = `DB_PASSWORD=${value}`;
    const binding = parseBindings(line)[0];
    assert.ok(binding, `${value}: fixture must parse as a binding`);
    assert.ok(
      binding.evidence.includes("reference_value"),
      `${value}: must be classified as a reference`
    );
    assert.equal(await redact(line), line, `${value}: must not be rewritten`);
  }
});

test("a literal secret is still redacted, references are not over-matched [GREEN NOW]", async () => {
  for (const value of ["correct horse battery staple", "Pr0d-P@ssw0rd-Xy9Zk2mQ", "a1b2c3d4e5f6"]) {
    const line = `DB_PASSWORD=${value}`;
    const binding = parseBindings(line)[0];
    assert.equal(binding.evidence.includes("reference_value"), false, `${value} is a literal`);
    const out = await redact(line);
    assert.equal(out.includes(value), false, `${value} must be redacted`);
  }
});
