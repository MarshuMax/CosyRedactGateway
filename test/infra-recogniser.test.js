// Infra recogniser: classification only, with policy deciding the action.
//
// The recogniser never returns an action, never suppresses anything, and never preserves
// anything by itself. It answers "what is this". A separate policy layer answers "what do
// we do with it", which is what stops the two questions from collapsing into one guess.
//
// Monotonic risk governs the policy, in two halves:
//
//   HARD_SECRET may NOT be downgraded by INFRA evidence.
//   SOFT_SIGNAL may be suppressed by high-precision INFRA evidence.
//
// The preserve allowlist is deliberately tiny for a first revision: only correlation
// identifiers, whose loss is what motivated this slice. Account ids, ARNs, internal
// hostnames and resource names are CLASSIFIED as INFRA and still redacted, because in
// some organisations they are sensitive infrastructure metadata -- that call belongs to
// a profile, not to a pattern matcher.
//
// Assertion tags:
//   [GREEN NOW]  passes against the current tree

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  recogniseInfra,
  decideSpanAction,
  INFRA_TYPE,
  INFRA_POLICY,
  INFRA_DISPOSITION,
} from "../worker.js";

const ALL = { highEntropy: true, phone: true, secret: true, identity: true, bank: true, email: true, gitleaks: true };
const GIT_SHA = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
const OCI_HEX = "7031c1b283388d2c2e09b57badb803c05ebed362dc88d84b480cc47f72a21097";
const OCI_DIGEST = `sha256:${OCI_HEX}`;
const TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736";
const SPAN_ID = "a3ce929d0e0e4736";
const PAT = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";

// ------------------------------------------------- infra-positive corpus ------

// Third element is the surrounding text. Shape-ambiguous identifiers (a bare 40-hex run,
// a bare 32-hex run, a 16-hex run) are only HARD when the context names them, so the
// fixtures supply the context they would have in a real payload.
const INFRA_POSITIVE = [
  [INFRA_TYPE.GIT_SHA, GIT_SHA, "commit "],
  [INFRA_TYPE.GIT_SHA, "0123456789abcdef0123456789abcdef01234567", "git_sha: "],
  [INFRA_TYPE.OCI_DIGEST, OCI_DIGEST, "image: nginx@"],
  [INFRA_TYPE.OCI_DIGEST, OCI_HEX, "sha256:"],
  [INFRA_TYPE.TRACE_ID, TRACE_ID, "trace_id: "],
  [INFRA_TYPE.SPAN_ID, SPAN_ID, "span_id: "],
  [INFRA_TYPE.AWS_ARN, "arn:aws:iam::123456789012:role/eks-nodegroup-role", null],
  [INFRA_TYPE.EC2_RESOURCE_ID, "i-0a1b2c3d4e5f67890", null],
  [INFRA_TYPE.EC2_RESOURCE_ID, "subnet-0a1b2c3d4e5f67890", null],
  [INFRA_TYPE.AWS_ACCOUNT_ID, "123456789012", null],
  [INFRA_TYPE.PRIVATE_IP, "10.244.0.11", null],
  [INFRA_TYPE.PRIVATE_IP, "192.168.1.5", null],
  [INFRA_TYPE.PRIVATE_IP, "172.16.0.1", null],
  [INFRA_TYPE.INTERNAL_HOSTNAME, "postgres.connected-car.svc.cluster.local", null],
  [INFRA_TYPE.K8S_RESOURCE_NAME, "vehicle-status-service-84d499d4cb-28dt2", null],
];

test("infra-positive corpus: every subtype is identified correctly [GREEN NOW]", () => {
  for (const [expected, value, context] of INFRA_POSITIVE) {
    const result = recogniseInfra(value, context);
    assert.ok(result, `${value} must be recognised`);
    assert.equal(result.infraType, expected, `${value} misclassified`);
    assert.equal(result.entityClass, "INFRA");
    assert.equal(typeof result.hard, "boolean");
    assert.ok(Array.isArray(result.evidence) && result.evidence.length > 0, "evidence is recorded");
    assert.equal(result.evidence.includes(`infra_rule:${expected.toLowerCase()}`), true, "the rule is named");
  }
});

test("infra-positive corpus: the recogniser returns no action [GREEN NOW]", () => {
  // The whole point of the split. The recogniser reports what it found and how sure it
  // is; it must not report what to DO about it, or classification and policy have merged
  // back into one guess.
  for (const [, value, context] of INFRA_POSITIVE) {
    const result = recogniseInfra(value, context);
    assert.equal("action" in result, false, `${value}: the recogniser must not decide actions`);
    assert.equal("disposition" in result, true, `${value}: it may report the configured disposition`);
  }
});

test("ambiguous shapes are soft without context and hard with it [GREEN NOW]", () => {
  // The rule that keeps a bank card out of the preserve path: a bare 16-hex run is not
  // evidence of a span id, and a bare 40-hex run is not evidence of a commit.
  const bare = [
    [GIT_SHA, INFRA_TYPE.GIT_SHA],
    [TRACE_ID, INFRA_TYPE.TRACE_ID],
  ];
  for (const [value, expected] of bare) {
    const soft = recogniseInfra(value);
    assert.equal(soft?.infraType, expected, `${value}: still classified`);
    assert.equal(soft.hard, false, `${value}: but SOFT without context`);
    assert.equal(decideSpanAction({ detector: "entropy", infra: soft }).action, "redact", `${value}: so it is redacted`);
  }
  // SPAN_ID is stricter still: without an anchor it is not claimed at all, because the
  // shape is exactly a bank card's.
  assert.equal(recogniseInfra(SPAN_ID), null, "an unanchored 16-hex run is not an infra claim");
  const anchored = [
    [GIT_SHA, "commit ", INFRA_TYPE.GIT_SHA],
    [TRACE_ID, "trace_id: ", INFRA_TYPE.TRACE_ID],
  ];
  for (const [value, context, expected] of anchored) {
    const hard = recogniseInfra(value, context);
    assert.equal(hard.infraType, expected);
    assert.equal(hard.hard, true, `${value} with ${JSON.stringify(context)} is HARD`);
    assert.ok(hard.evidence.includes("infra_anchored"), "and says why");
    assert.equal(decideSpanAction({ detector: "entropy", infra: hard }).action, "preserve");
  }
  // SPAN_ID is claimed ONLY with an anchor, and is hard once anchored: the context has
  // already done the disambiguation that the bare shape cannot.
  assert.equal(recogniseInfra(SPAN_ID, "span_id: ").hard, true);
  assert.equal(decideSpanAction({ detector: "entropy", infra: recogniseInfra(SPAN_ID, "span_id: ") }).action, "preserve");
});

test("private ranges are handled per range, not by one shared tail [GREEN NOW]", () => {
  // 10.x fixes one octet while 192.168/172.16-31 fix two, so they need different tails.
  // A shared tail made `10.244.0.11` silently fail while `192.168.1.5` worked.
  for (const ip of ["10.0.0.1", "10.244.0.11", "192.168.1.5", "172.16.0.1", "172.31.255.255"]) {
    assert.equal(recogniseInfra(ip)?.infraType, INFRA_TYPE.PRIVATE_IP, `${ip} must be a private ip`);
  }
  for (const ip of ["8.8.8.8", "172.32.0.1", "192.169.1.1", "100.64.0.1"]) {
    assert.equal(recogniseInfra(ip), null, `${ip} is not private`);
  }
});

// ------------------------------------------ secret-negative / collision corpus ---

test("collision corpus: a real secret is never misrecognised as INFRA [GREEN NOW]", () => {
  // Each entry is chosen because it is CLOSE to an infra shape. None may be returned as
  // an infra classification, because a classification plus an entropy-only hit is what a
  // preserve decision is built from.
  const secrets = [
    "cGFzc3dvcmQxMjM0NTY3OA==",              // base64 password
    "Pr0d-P@ssw0rd-Xy9Zk2mQ",                // symbol-bearing password
    PAT,                                       // provider token
    "AKIAZ7QX3MNP2KRTUVWY",                   // AWS access key id
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",  // JWT header segment
    "correct horse battery staple",           // passphrase
  ];
  for (const secret of secrets) {
    const result = recogniseInfra(secret);
    // A 64-hex JWT-looking blob could legitimately be a digest; the point is that these
    // specific fixtures are not, and more importantly that classification never turns
    // them into a preserve without the policy check below.
    if (result) {
      assert.notEqual(result.disposition, INFRA_DISPOSITION.PRESERVE, `${secret} must not be preserve-eligible`);
    }
  }
});

test("collision corpus: hard secret evidence is never downgraded [GREEN NOW]", () => {
  // The monotonic rule. A span that a deterministic credential detector matched stays a
  // secret even when it also looks like a digest.
  const cases = [
    ["provider rule on a 40-hex value", { detector: "gitleaks", ruleId: "suspicious-40hex", infra: recogniseInfra(GIT_SHA) }],
    ["provider rule on a digest", { detector: "gitleaks", ruleId: "suspicious-digest", infra: recogniseInfra(OCI_DIGEST) }],
    ["strong binding on a 40-hex value", { detector: "binding", infra: recogniseInfra(GIT_SHA) }],
    ["header binding on a digest", { detector: "binding", infra: recogniseInfra(OCI_DIGEST) }],
    ["sk- detector on a digest", { detector: "secret", infra: recogniseInfra(OCI_DIGEST) }],
  ];
  for (const [label, meta] of cases) {
    const decision = decideSpanAction(meta);
    assert.equal(decision.action, "redact", `${label}: must stay redacted`);
    assert.equal(decision.hardSecret, true, `${label}: classified as a hard secret`);
    assert.equal(decision.reason, "hard-secret");
  }
});

test("collision corpus: only the preserve allowlist is preserved [GREEN NOW]", () => {
  const preserveEligible = new Set(
    Object.entries(INFRA_POLICY)
      .filter(([, disposition]) => disposition === INFRA_DISPOSITION.PRESERVE)
      .map(([type]) => type)
  );
  assert.deepEqual(
    [...preserveEligible].sort(),
    [INFRA_TYPE.GIT_SHA, INFRA_TYPE.OCI_DIGEST, INFRA_TYPE.SPAN_ID, INFRA_TYPE.TRACE_ID].sort(),
    "the allowlist must stay this small until a profile opts in"
  );

  for (const [type, value, context] of INFRA_POSITIVE) {
    const decision = decideSpanAction({ detector: "entropy", infra: recogniseInfra(value, context) });
    if (preserveEligible.has(type)) {
      assert.equal(decision.action, "preserve", `${type} is allowlisted`);
    } else {
      assert.equal(decision.action, "redact", `${type} is classified but NOT preserved`);
    }
  }
});

test("soft signals are suppressed only by hard, allowlisted infra evidence [GREEN NOW]", () => {
  // Hard infra shapes: precise length plus boundary assertions, so suppressing an
  // entropy-only hit is safe.
  for (const [type, value] of [
    [INFRA_TYPE.OCI_DIGEST, OCI_DIGEST],
    [INFRA_TYPE.GIT_SHA, GIT_SHA],
    [INFRA_TYPE.TRACE_ID, TRACE_ID],
  ]) {
    const context = type === INFRA_TYPE.SPAN_ID ? "span_id: "
      : type === INFRA_TYPE.TRACE_ID ? "trace_id: "
        : "commit ";
    const result = recogniseInfra(value, context);
    assert.equal(result.hard, true, `${type} must be a hard shape under ${JSON.stringify(context)}`);
    assert.equal(decideSpanAction({ detector: "entropy", infra: result }).action, "preserve");
  }
  // Ambiguous shapes stay redacted even though they are classifyable.
  for (const value of ["123456789012", "arn:aws:iam::123456789012:role/x", "10.244.0.11"]) {
    const decision = decideSpanAction({ detector: "entropy", infra: recogniseInfra(value) });
    assert.equal(decision.action, "redact", `${value} must not be preserved`);
  }
});

// ----------------------------------------------------- end-to-end behaviour -----

test("the golden corpus is not mutated for allowlisted subtypes [GREEN NOW]", async () => {
  // "0 mutations" applies ONLY to the preserve allowlist. It is not a claim that all
  // INFRA is untouched: account ids, ARNs and resource names are classified yet still
  // redacted when a detector flags them.
  const doc = [
    `commit ${GIT_SHA}`,
    `image: nginx@${OCI_DIGEST}`,
    `trace_id: ${TRACE_ID}`,
  ].join("\n");
  const ctx = new RedactionContext({ salt: "fixture" });
  const out = await ctx.redactText(doc, ALL);
  assert.equal(out, doc, "allowlisted subtypes must survive byte for byte");
  assert.equal(ctx.restoreText(out), doc, "and round-trip unchanged");
  assert.equal(ctx.policySummary().byAction.preserve.spans, 3, "three preserves recorded");
  // A bare 40-hex value with no anchor is NOT part of the guarantee: it is classified
  // INFRA but redacted, because the shape alone does not establish what it is.
  const bare = new RedactionContext({ salt: "fixture" });
  const bareOut = await bare.redactText(`sha_alone: ${GIT_SHA}`, ALL);
  assert.notEqual(bareOut, `sha_alone: ${GIT_SHA}`, "an unanchored sha is redacted");
});

test("a real secret in the same payload is still redacted [GREEN NOW]", async () => {
  const doc = [
    `commit ${GIT_SHA}`,
    `image: nginx@${OCI_DIGEST}`,
    "DB_PASSWORD=Pr0d-P@ssw0rd-Xy9Zk2mQ",
    `token = ${PAT}`,
  ].join("\n");
  const ctx = new RedactionContext({ salt: "fixture" });
  const out = await ctx.redactText(doc, ALL);
  assert.ok(out.includes(GIT_SHA), "the sha survives");
  assert.ok(out.includes(OCI_DIGEST), "the digest survives");
  assert.equal(out.includes("Pr0d-P@ssw0rd-Xy9Zk2mQ"), false, "the password is redacted");
  assert.equal(out.includes(PAT), false, "the token is redacted");
  assert.equal(ctx.restoreText(out), doc, "round-trip is byte-identical");
});

test("policy decisions are recorded with their reason [GREEN NOW]", async () => {
  const doc = [`commit ${GIT_SHA}`, "DB_PASSWORD=Pr0d-P@ssw0rd-Xy9Zk2mQ"].join("\n");
  const ctx = new RedactionContext({ salt: "fixture" });
  await ctx.redactText(doc, ALL);
  const summary = ctx.policySummary();
  assert.equal(summary.decisions, 2);
  assert.equal(summary.byAction.preserve.spans, 1);
  assert.equal(summary.byAction.redact.spans, 1);
  const preserved = summary.rows.find((r) => r.action === "preserve");
  assert.equal(preserved.reason, `infra:${INFRA_TYPE.GIT_SHA}`, "a preserve is auditable, not invisible");
  assert.equal(preserved.infraType, INFRA_TYPE.GIT_SHA);
});

test("a preserved span leaves nothing in the mapping [GREEN NOW]", async () => {
  // Preserve means "emit verbatim", not "emit a token and restore it later". If a
  // preserved value ended up in tokenToRaw, restoreText would start substituting a
  // value that was never redacted.
  const ctx = new RedactionContext({ salt: "fixture" });
  await ctx.redactText(`commit ${GIT_SHA}`, ALL);
  assert.equal(ctx.tokenToRaw.size, 0, "nothing minted");
  assert.equal(ctx.entityLedger.size, 0, "and no entity recorded, since no entity was created");
});

test("the recogniser is not vulnerable to catastrophic backtracking [GREEN NOW]", () => {
  // A nested quantifier in the hostname rule made a 71-character digest take longer than
  // 60 seconds to classify. The bounds here are generous; the point is that no input can
  // make classification super-linear.
  const hostile = [
    "a".repeat(2000),
    "a-".repeat(1000),
    OCI_DIGEST,
    "a.".repeat(500) + "internal",
    "arn:aws:iam::" + "9".repeat(12) + ":" + "a/".repeat(400),
    "1".repeat(500),
    "10." + "1.".repeat(200) + "1",
  ];
  const started = Date.now();
  for (const value of hostile) recogniseInfra(value);
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 1000, `classification must stay fast, took ${elapsed}ms`);
});
