// E0 + E1: entity class semantics, and a classifier that only keeps books.
//
// E0 -- sink-policy semantics for entity classes. The predicate was renamed from
// `isCredentialRisk` because it was never about credentials alone, and its old body
// returned false for PII. That was a latent hazard: the moment the classifier labels an
// email, a phone number, a national id or a bank card as PII, those entities would have
// been RELEASED into a sensitive sink *because they were classified correctly*.
//
// E1 -- the classifier records, it does not decide. Classification happens at emit time,
// where the span still carries its detector, ruleId, evidence, syntax, key and path.
// `entityClassFor()` is a ledger lookup, never a re-run of the classifier.
//
// Assertion tags:
//   [GREEN NOW]  passes against the current tree

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  requiresSinkProtection,
  classifyRestore,
  ENTITY_CLASS,
  SENSITIVE_SINK_KINDS,
} from "../worker.js";

const ALL = { highEntropy: true, phone: true, secret: true, identity: true, bank: true, email: true, gitleaks: true };
const PAT = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
const PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKjM5bGZkZ2Fh";

function ctx() {
  return new RedactionContext({ salt: "fixture" });
}

async function ledgerFor(text) {
  const context = ctx();
  await context.redactText(text, ALL);
  return context.entityLedger.entries();
}

// ---------------------------------------------------------------- E0 ----------

test("E0: PII requires sink protection, exactly like CREDENTIAL and UNKNOWN [GREEN NOW]", () => {
  // The regression this pins: PII used to return false, so a correctly classified email
  // would have been allowed into a sensitive sink.
  for (const cls of [ENTITY_CLASS.CREDENTIAL, ENTITY_CLASS.PII, ENTITY_CLASS.UNKNOWN, undefined, null]) {
    assert.equal(requiresSinkProtection(cls), true, `${String(cls)} must require protection`);
  }
  // INFRA keeps its existing policy; this slice deliberately does not change it, and the
  // infra recogniser is a separate piece of work.
  assert.equal(requiresSinkProtection(ENTITY_CLASS.INFRA), false, "INFRA policy is unchanged here");
});

test("E0: `isCredentialRisk` is gone, not merely unused [GREEN NOW]", async () => {
  const module = await import("../worker.js");
  assert.equal("requiresSinkProtection" in module, true);
  assert.equal("isCredentialRisk" in module, false, "the old name must not linger");
});

test("E0: a PII entity is blocked at an untrusted sensitive sink [GREEN NOW]", async () => {
  const context = ctx();
  await context.redactText("contact: a@example.com", ALL);
  const token = context.entityLedger.entries()[0].token;
  assert.equal(context.entityClassFor(token), ENTITY_CLASS.PII, "fixture must be PII");

  for (const kind of SENSITIVE_SINK_KINDS) {
    const decision = classifyRestore({ ctx: context, text: `use ${token}`, sink: { kind } });
    // The contract is "not resolved into a sensitive sink". The action is `preserve`:
    // the token is delivered rather than the plaintext. (An earlier revision named this
    // action `block`; the security property is the same either way, and asserting the
    // name would hide a regression in the property.)
    assert.notEqual(decision.action, "restore", `${kind}: PII must not be resolved here`);
    assert.equal(decision.text.includes("a@example.com"), false, `${kind}: no plaintext`);
  }
  // ...and still restorable where it is safe.
  assert.equal(classifyRestore({ ctx: context, text: `use ${token}`, sink: { kind: "assistant_text" } }).action, "restore");
});

// ---------------------------------------------------------------- E1 ----------

test("E1: a password binding classifies as CREDENTIAL [GREEN NOW]", async () => {
  const entries = await ledgerFor("DB_PASSWORD=Pr0d-P@ssw0rd-Xy9Zk2mQ");
  assert.equal(entries.length, 1);
  assert.equal(entries[0].entityClass, ENTITY_CLASS.CREDENTIAL);
  assert.equal(entries[0].detector, "binding");
  assert.equal(entries[0].key, "DB_PASSWORD");
  assert.ok(entries[0].evidence.includes("strong_secret_key"));
});

test("E1: an Authorization header classifies as CREDENTIAL [GREEN NOW]", async () => {
  const entries = await ledgerFor(`Authorization: Bearer ${PAT}`);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].entityClass, ENTITY_CLASS.CREDENTIAL);
  // Attribution goes to the most specific detector: the provider rule recognises the
  // token shape, so it wins over the header binding and `syntax` is not the header one.
  // Both routes end in CREDENTIAL; what matters is that the class is justified.
  assert.ok(
    entries[0].ruleId === "github-classic-token" || entries[0].syntax === "http-header",
    "CREDENTIAL must come from a provider rule or the header binding"
  );
});

test("E1: the header binding alone also classifies as CREDENTIAL [GREEN NOW]", async () => {
  // A value no provider rule recognises, so the header binding is the only evidence.
  const entries = await ledgerFor("Authorization: Bearer Pr0d-P@ssw0rd-Xy9Zk2mQ");
  assert.equal(entries.length, 1);
  assert.equal(entries[0].entityClass, ENTITY_CLASS.CREDENTIAL);
  assert.equal(entries[0].syntax, "http-header");
  assert.equal(entries[0].detector, "binding");
});

test("E1: provider rules and private keys classify as CREDENTIAL [GREEN NOW]", async () => {
  const entries = await ledgerFor([
    "token = " + PAT,
    "private_key: |",
    "  -----BEGIN PRIVATE KEY-----",
    `  ${PEM_BODY}`,
    "  -----END PRIVATE KEY-----",
  ].join("\n"));
  for (const entry of entries) {
    assert.equal(entry.entityClass, ENTITY_CLASS.CREDENTIAL, `${entry.key ?? entry.detector} must be CREDENTIAL`);
  }
});

test("E1: PII detectors classify as PII [GREEN NOW]", async () => {
  const entries = await ledgerFor([
    "contact: a@example.com",
    "phone: 13812345678",
    "id: 110101199003077758",
    "card: 4111111111111111",
  ].join("\n"));
  const byDetector = Object.fromEntries(entries.map((e) => [e.detector, e.entityClass]));
  assert.equal(byDetector.email, ENTITY_CLASS.PII);
  assert.equal(byDetector.phone, ENTITY_CLASS.PII);
  assert.equal(byDetector.identity, ENTITY_CLASS.PII);
  assert.equal(byDetector.bank, ENTITY_CLASS.PII);
});

test("E1: an entropy-only hit stays UNKNOWN, not CREDENTIAL [GREEN NOW]", async () => {
  // "Looks random" is compatible with a secret, a git SHA, a Docker digest and a trace
  // id alike. Mapping it to CREDENTIAL would manufacture confidence the evidence does
  // not support; that disentangling is the infra recogniser's job.
  // The fixture must NOT be infrastructure-shaped, or it tests the other branch: a 32-hex
  // run is the trace-id shape, so the recogniser legitimately claims it (see the infra
  // suite). This is a random-looking alphanumeric block with no recognisable shape, which
  // is what "entropy-only" actually means.
  const entries = await ledgerFor("blob: 9fK2mXq7Lp4Rt8Wz3Vb6Nc1Yd5Hs0Jg");
  assert.equal(entries.length, 1);
  assert.equal(entries[0].detector, "entropy");
  assert.equal(entries[0].entityClass, ENTITY_CLASS.UNKNOWN, "shape-free entropy is not a class");
  assert.equal(entries[0].infraType, null, "and no infra type is claimed");
});

test("E1: a weak key name confers nothing by itself [GREEN NOW]", async () => {
  // Two distinct claims, and the distinction is the whole point of the slice:
  //
  //   1. the KEY NAME alone must not confer a class. `cache_key: abc123` produces no
  //      binding span and no other detector fires, so no entity exists at all;
  //   2. a CREDENTIAL class must be justified by EVIDENCE. `cache_key: <base64>` IS
  //      classified CREDENTIAL -- but by the generic provider rule matching the VALUE,
  //      not by the key name. That is correct behaviour, not a leak of key-name
  //      inference, and the attribution proves which route it took.
  assert.deepEqual(await ledgerFor("cache_key: abc123"), [], "no entity, so nothing to misclassify");

  const byValue = await ledgerFor("cache_key: cGFzc3dvcmQxMjM0NTY3OA==");
  assert.equal(byValue.length, 1);
  assert.equal(byValue[0].entityClass, ENTITY_CLASS.CREDENTIAL, "the value matched a provider rule");
  assert.ok(byValue[0].detector === "gitleaks" || byValue[0].detector === "secret",
    `CREDENTIAL must be value-evidenced, got detector=${byValue[0].detector}`);
  assert.equal(byValue[0].key, null, "and no strong binding contributed: the key name is not the reason");
});

test("E1: `entityClassFor` is a ledger lookup, not a re-run [GREEN NOW]", async () => {
  const context = ctx();
  await context.redactText("DB_PASSWORD=Pr0d-P@ssw0rd-Xy9Zk2mQ", ALL);
  const token = context.entityLedger.entries()[0].token;

  assert.equal(context.entityClassFor(token), ENTITY_CLASS.CREDENTIAL);
  // An unknown token is UNKNOWN rather than a classifier invocation.
  assert.equal(context.entityClassFor("CRG_ZZZZ_9999"), ENTITY_CLASS.UNKNOWN);
});

test("E1: the same entity has the same class as a plain token and as a base64 surrogate [GREEN NOW]", async () => {
  // Representation must not change classification, exactly as it must not change the
  // sink policy.
  const doc = [
    "apiVersion: v1",
    "kind: Secret",
    "data:",
    "  password: YWRtaW4xMjM0NTY3OA==",
  ].join("\n");
  const context = ctx();
  const out = await context.redactText(doc, ALL);
  const visible = (out.match(/^\s+password:\s*(\S+)\s*$/m) || [])[1];
  assert.ok(visible, "a surrogate must be minted");

  const entry = context.entityLedger.entries()[0];
  assert.equal(entry.encodingKind, "base64", "the ledger records the representation");
  assert.equal(context.entityClassFor(entry.token), entry.entityClass, "class is looked up on the entity");
  // And the surrogate itself is not a separate entity with a different class.
  assert.equal(context.entityLedger.entries().length, 1, "one entity, one record");

  // The same secret under the same key WITHOUT base64 gets the same class.
  const plain = ctx();
  await plain.redactText("db_password: YWRtaW4xMjM0NTY3OA==", ALL);
  const plainEntry = plain.entityLedger.entries()[0];
  assert.equal(plainEntry.entityClass, entry.entityClass, "plain and base64 forms must agree");
  assert.equal(plainEntry.encodingKind, "plain");
});

// ------------------------------------------- coverage is a separate dimension -----

test("coverage is recorded as its own dimension, never folded into the class [GREEN NOW]", async () => {
  const context = ctx();
  // A degraded YAML region: the parser cannot track the path, so coverage is PARTIAL.
  await context.redactText("containers:\n  - name: app\n    value: cGFzc3dvcmQxMjM0NTY3OA==", ALL);
  const entries = context.entityLedger.entries();
  assert.ok(entries.length >= 1, "something must be recorded");
  for (const entry of entries) {
    assert.ok("coverageStatus" in entry, "coverage is recorded alongside the class");
    assert.ok("entityClass" in entry, "and both are present as separate fields");
  }
});

test("a FAILED region does not downgrade a deterministic detector [GREEN NOW]", async () => {
  // Correcting an earlier claim of mine: "the entity came from a FAILED region, so the
  // classification is untrustworthy" does NOT generalise. Parser coverage measures how
  // well the STRUCTURE was understood; it says nothing about whether a provider rule
  // matched. A GitHub PAT inside an unlocatable region is still a PAT.
  const context = ctx();
  // `X-Custom-Header:` produces a FAILED attempt, and the PAT on the next line is a
  // deterministic provider match.
  await context.redactText(["X-Custom-Header:", `token = ${PAT}`].join("\n"), ALL);
  const entries = context.entityLedger.entries();
  const pat = entries.find((e) => e.ruleId === "github-classic-token");
  assert.ok(pat, "the PAT must be recorded");
  assert.equal(pat.entityClass, ENTITY_CLASS.CREDENTIAL, "deterministic evidence is not downgraded by coverage");

  // Conversely, an entropy-only hit in a FAILED region is UNKNOWN for its own reason:
  // entropy was never class evidence to begin with.
  const entropyOnly = await ledgerFor("X-Custom-Header:\nvalue: 9fK2mXq7Lp4Rt8Wz3Vb6Nc1Yd5Hs0Jg");
  for (const entry of entropyOnly) {
    if (entry.detector === "entropy") assert.equal(entry.entityClass, ENTITY_CLASS.UNKNOWN);
  }
});
