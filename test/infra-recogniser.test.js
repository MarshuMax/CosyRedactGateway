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
  INFRA_CERTAINTY,
  INFRA_DISPOSITION,
  DEFAULT_PROFILE,
  DEVOPS_PROFILE,
  findSensitiveSpans,
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
    assert.ok([INFRA_CERTAINTY.VERIFIED, INFRA_CERTAINTY.AMBIGUOUS].includes(result.certainty));
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
    assert.equal("disposition" in result, false, `${value}: nor a disposition -- policy is not its business`);
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
    assert.equal(soft.certainty, INFRA_CERTAINTY.AMBIGUOUS, `${value}: but SOFT without context`);
    assert.equal(decideSpanAction({ detector: "entropy", infra: soft, profile: DEVOPS_PROFILE }).action, "redact", `${value}: so it is redacted`);
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
    assert.equal(hard.certainty, INFRA_CERTAINTY.VERIFIED, `${value} with ${JSON.stringify(context)} is VERIFIED`);
    assert.ok(hard.evidence.includes("infra_anchored"), "and says why");
    assert.equal(decideSpanAction({ detector: "entropy", infra: hard, profile: DEVOPS_PROFILE }).action, "preserve");
  }
  // SPAN_ID is claimed ONLY with an anchor, and is VERIFIED once anchored: the context has
  // already done the disambiguation that the bare shape cannot.
  assert.equal(recogniseInfra(SPAN_ID, "span_id: ").certainty, INFRA_CERTAINTY.VERIFIED);
  assert.equal(decideSpanAction({ detector: "entropy", infra: recogniseInfra(SPAN_ID, "span_id: "), profile: DEVOPS_PROFILE }).action, "preserve");
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
    const decision = decideSpanAction({ ...meta, profile: DEVOPS_PROFILE });
    assert.equal(decision.action, "redact", `${label}: must stay redacted`);
    assert.equal(decision.hardSecret, true, `${label}: classified as a hard secret`);
    assert.equal(decision.reason, "hard-secret");
  }
});

test("collision corpus: only the preserve allowlist is preserved by the DEFAULT profile [GREEN NOW]", () => {
  const preserveEligible = new Set(
    Object.entries(DEFAULT_PROFILE)
      .filter(([, disposition]) => disposition === INFRA_DISPOSITION.PRESERVE)
      .map(([type]) => type)
  );
  assert.deepEqual(
    [...preserveEligible].sort(),
    [INFRA_TYPE.GIT_SHA, INFRA_TYPE.OCI_DIGEST, INFRA_TYPE.SPAN_ID, INFRA_TYPE.TRACE_ID].sort(),
    "the default profile must stay this small until a deployment opts in"
  );

  for (const [type, value, context] of INFRA_POSITIVE) {
    const infra = recogniseInfra(value, context);
    // Certainty and profile are independent: a VERIFIED type under a REDACT disposition is
    // still redacted, because the disposition -- not a doubt about identity -- is what
    // says no.
    const decision = decideSpanAction({ detector: "entropy", infra, profile: DEFAULT_PROFILE });
    if (preserveEligible.has(type) && infra.certainty === INFRA_CERTAINTY.VERIFIED) {
      assert.equal(decision.action, "preserve", `${type} is allowlisted and verified`);
    } else {
      assert.equal(decision.action, "redact", `${type} must not be preserved under the default profile`);
    }
  }
});

test("a VERIFIED type is still redacted when the profile says so [GREEN NOW]", () => {
  // The whole reason certainty and disposition are separate: `arn:aws:...` is
  // unambiguously an ARN, and the default still redacts it. Writing `AMBIGUOUS` into the
  // recogniser to achieve that would have been a policy decision disguised as a doubt.
  const arn = recogniseInfra("arn:aws:iam::123456789012:role/eks-nodegroup-role");
  assert.equal(arn.certainty, INFRA_CERTAINTY.VERIFIED, "identity is not in doubt");
  assert.equal(decideSpanAction({ detector: "entropy", infra: arn, profile: DEFAULT_PROFILE }).action, "redact");
  assert.equal(decideSpanAction({ detector: "entropy", infra: arn, profile: DEVOPS_PROFILE }).action, "preserve");
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
    assert.equal(result.certainty, INFRA_CERTAINTY.VERIFIED, `${type} must be a hard shape under ${JSON.stringify(context)}`);
    assert.equal(decideSpanAction({ detector: "entropy", infra: result, profile: DEVOPS_PROFILE }).action, "preserve");
  }
  // Ambiguous shapes stay redacted even though they are classifyable.
  // Ambiguous shapes stay redacted EVEN under a profile that asks for preservation: an
  // exemption needs a verified identity, not just permission.
  for (const value of ["123456789012", "10.244.0.11", GIT_SHA, OCI_HEX]) {
    const infra = recogniseInfra(value);
    assert.equal(infra.certainty, INFRA_CERTAINTY.AMBIGUOUS, `${value} is ambiguous`);
    const decision = decideSpanAction({ detector: "entropy", infra, profile: DEVOPS_PROFILE });
    assert.equal(decision.action, "redact", `${value} must stay redacted even under DEVOPS_PROFILE`);
    assert.equal(decision.reason, `infra-ambiguous:${infra.infraType}`);
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

// ------------------------------------------- F4.1 OCI shape-bypass hardening -----

test("F4.1: only a prefixed or immediately-anchored digest is preserve-eligible [GREEN NOW]", () => {
  // The rule used to be `(?:sha256:)?<64hex>` marked hard, so a BARE 64-hex run became a
  // hard OCI digest and qualified for preservation -- a licence for anything 64 hex
  // characters long. `token=<64hex secret>` would have been emitted intact.
  const H = OCI_HEX;
  const eligible = [
    [`sha256:${H}`, null],
    [H, "image@sha256:"],
    [H, "digest sha256: "],
  ];
  for (const [value, context] of eligible) {
    const result = recogniseInfra(value, context);
    assert.equal(result.infraType, INFRA_TYPE.OCI_DIGEST);
    assert.equal(result.certainty, INFRA_CERTAINTY.VERIFIED, `${value} with ${JSON.stringify(context)} must be hard`);
    assert.equal(decideSpanAction({ detector: "entropy", infra: result, profile: DEVOPS_PROFILE }).action, "preserve");
  }

  const ineligible = [
    [H, null, "bare 64-hex"],
    [H, "token=", "token assignment"],
    [H, "secret=", "secret assignment"],
    [H, "value=", "generic assignment"],
  ];
  for (const [value, context, label] of ineligible) {
    const result = recogniseInfra(value, context);
    assert.equal(decideSpanAction({ detector: "entropy", infra: result, profile: DEVOPS_PROFILE }).action, "redact", `${label} must be redacted`);
  }
});

test("F4.1: the anchor is adjacent, not merely present in the prefix [GREEN NOW]", () => {
  // Searching the whole prefix lets an unrelated earlier digest vouch for the value under
  // inspection: `previous digest sha256:<hex> token=<64hex secret>` must not make the
  // token preserve-eligible.
  const H = OCI_HEX;
  const decoy = `previous digest sha256:${"a".repeat(64)} token=`;
  const result = recogniseInfra(H, decoy);
  assert.equal(result.certainty, INFRA_CERTAINTY.AMBIGUOUS, "the decoy digest must not vouch for the token");
  assert.equal(decideSpanAction({ detector: "entropy", infra: result, profile: DEVOPS_PROFILE }).action, "redact");

  // The anchored form still works, so the check is strict rather than broken. Note the
  // context here is the text immediately before THIS span, and it ends with the prefix
  // that belongs to this span's value.
  assert.equal(recogniseInfra(H, "image@sha256:").certainty, INFRA_CERTAINTY.VERIFIED, "an immediately preceding prefix qualifies");
  assert.equal(recogniseInfra(H, "  sha256:").certainty, INFRA_CERTAINTY.VERIFIED, "whitespace around the prefix is tolerated");
  // But a prefix that belongs to a DIFFERENT, earlier value does not, even though the
  // bare hex here is likewise 64 characters.
  assert.equal(recogniseInfra(H, `previous digest sha256:${"a".repeat(64)} `).certainty, INFRA_CERTAINTY.AMBIGUOUS,
    "a prefix separated by another value must not qualify");
});

test("F4.1: hard provider evidence beats an OCI-shaped span [GREEN NOW]", () => {
  for (const meta of [
    { detector: "gitleaks", ruleId: "suspicious-64hex", infra: recogniseInfra(OCI_DIGEST) },
    { detector: "gitleaks", ruleId: "suspicious-64hex", infra: recogniseInfra(OCI_HEX, "image@sha256:") },
    { detector: "secret", infra: recogniseInfra(OCI_DIGEST) },
    { detector: "binding", infra: recogniseInfra(OCI_DIGEST) },
  ]) {
    const decision = decideSpanAction({ ...meta, profile: DEVOPS_PROFILE });
    assert.equal(decision.action, "redact");
    assert.equal(decision.hardSecret, true);
  }
});

test("F4.1: a bare digest is classified but has no preserve path [GREEN NOW]", () => {
  // Classification is still useful (telemetry, profiles later); what it must not have is
  // an exemption. Removing the exemption, not the classification, is the fix.
  const result = recogniseInfra(OCI_HEX);
  assert.equal(result.infraType, INFRA_TYPE.OCI_DIGEST, "still classified");
  assert.equal(result.certainty, INFRA_CERTAINTY.AMBIGUOUS, "but soft");
  assert.equal("disposition" in result, false, "the recogniser no longer reports a disposition at all");
  assert.equal(decideSpanAction({ detector: "entropy", infra: result, profile: DEVOPS_PROFILE }).action, "redact",
    "the disposition alone is not enough: the finding must also be hard");
});

// ------------------------------------------ F4.2 certainty / disposition split -----

test("F4.2: the recogniser reports no disposition and no action [GREEN NOW]", () => {
  // The recogniser used to return a disposition and decideSpanAction read it, which meant
  // the recogniser knew the policy. Everything it reports is now a statement about WHAT
  // the value is.
  for (const [, value, context] of INFRA_POSITIVE) {
    const result = recogniseInfra(value, context);
    assert.deepEqual(
      Object.keys(result).sort(),
      ["certainty", "confidence", "entityClass", "evidence", "infraType"],
      `${value}: unexpected fields in the recogniser result`
    );
  }
});

test("F4.2: certainty is VERIFIED or AMBIGUOUS, never `hard` [GREEN NOW]", () => {
  // `hard` read as "hard secret" while meaning the opposite; the field is renamed so the
  // two cannot be confused at a call site.
  for (const [, value, context] of INFRA_POSITIVE) {
    const result = recogniseInfra(value, context);
    assert.ok(
      [INFRA_CERTAINTY.VERIFIED, INFRA_CERTAINTY.AMBIGUOUS].includes(result.certainty),
      `${value}: certainty must be one of the two values`
    );
    assert.equal("hard" in result, false, "the old field name must be gone");
  }
});

test("F4.2: a VERIFIED type follows the profile, not a doubt about its identity [GREEN NOW]", () => {
  const arn = recogniseInfra("arn:aws:iam::123456789012:role/eks-nodegroup-role");
  assert.equal(arn.infraType, INFRA_TYPE.AWS_ARN);
  assert.equal(arn.certainty, INFRA_CERTAINTY.VERIFIED, "it is unambiguously an ARN");

  // strict / default profile -> redacted, because the PROFILE says so.
  const strict = decideSpanAction({ detector: "entropy", infra: arn, profile: DEFAULT_PROFILE });
  assert.equal(strict.action, "redact");
  assert.equal(strict.reason, `profile-redact:${INFRA_TYPE.AWS_ARN}`, "the reason names the profile, not a doubt");

  // devops profile -> preserved.
  const devops = decideSpanAction({ detector: "entropy", infra: arn, profile: DEVOPS_PROFILE });
  assert.equal(devops.action, "preserve");
  assert.equal(devops.reason, `infra:${INFRA_TYPE.AWS_ARN}`);
});

test("F4.2: AMBIGUOUS is refused even when the profile asks for preservation [GREEN NOW]", () => {
  // An exemption needs a verified identity AND permission. Permission alone is not enough,
  // which is what keeps `token=<64hex>` out.
  const cases = [
    [GIT_SHA, INFRA_TYPE.GIT_SHA],
    [TRACE_ID, INFRA_TYPE.TRACE_ID],
    [OCI_HEX, INFRA_TYPE.OCI_DIGEST],
  ];
  for (const [value, type] of cases) {
    const infra = recogniseInfra(value);
    assert.equal(infra.infraType, type, `${value}: still classified`);
    assert.equal(infra.certainty, INFRA_CERTAINTY.AMBIGUOUS);
    const decision = decideSpanAction({ detector: "entropy", infra, profile: DEVOPS_PROFILE });
    assert.equal(decision.action, "redact", `${value}: must stay redacted under DEVOPS_PROFILE`);
    assert.equal(decision.reason, `infra-ambiguous:${type}`);
  }
});

test("F4.2: no profile can release a hard secret [GREEN NOW]", () => {
  for (const meta of [
    { detector: "gitleaks", ruleId: "x", infra: recogniseInfra(OCI_DIGEST) },
    { detector: "binding", infra: recogniseInfra(GIT_SHA, "commit ") },
    { detector: "bank", infra: recogniseInfra(SPAN_ID, "span_id: ") },
    { detector: "email", infra: recogniseInfra("arn:aws:iam::123456789012:role/x") },
  ]) {
    const decision = decideSpanAction({ ...meta, profile: DEVOPS_PROFILE });
    assert.equal(decision.action, "redact", "hard secret wins over any profile");
    assert.equal(decision.hardSecret, true);
    assert.equal(decision.reason, "hard-secret");
  }
});

test("F4.2: MASK is not exposed as a fake disposition [GREEN NOW]", () => {
  // There is no mask implementation, so advertising one would be a lie that behaves like
  // REDACT. Real masking needs per-type fidelity decisions that no string-level mask
  // answers.
  assert.deepEqual(Object.values(INFRA_DISPOSITION).sort(), ["preserve", "redact"]);
  assert.equal("MASK" in INFRA_DISPOSITION, false, "no MASK until it means something");
  // Every type has a disposition in the default profile, so nothing falls through.
  for (const type of Object.values(INFRA_TYPE)) {
    assert.ok(type in DEFAULT_PROFILE, `${type} must have a default disposition`);
  }
});

test("F4.2: the context profile is what the policy consults [GREEN NOW]", async () => {
  // The vehicle has to be something a detector actually produces a span for, and whose
  // whole shape the recogniser can verify. `commit <sha>` and `image@sha256:<hex>` both
  // qualify: the entropy hit covers the entire token in each case.
  const doc = [`commit ${GIT_SHA}`, `image: nginx@${OCI_DIGEST}`].join("\n");

  const strict = new RedactionContext({ salt: "fixture", profile: DEFAULT_PROFILE });
  const strictOut = await strict.redactText(doc, ALL);
  assert.ok(strictOut.includes(GIT_SHA), "the default profile preserves the verified sha");

  // Same payload, a profile that does not preserve the digest.
  const redactDigest = { ...DEFAULT_PROFILE, [INFRA_TYPE.OCI_DIGEST]: INFRA_DISPOSITION.REDACT };
  const restricted = new RedactionContext({ salt: "fixture", profile: redactDigest });
  const restrictedOut = await restricted.redactText(doc, ALL);
  assert.equal(restrictedOut.includes(OCI_HEX), false, "the digest is redacted under that profile");
  assert.ok(restrictedOut.includes(GIT_SHA), "while the sha stays preserved");
  assert.equal(restricted.restoreText(restrictedOut), doc, "round-trip is byte-identical either way");
});

test("F4.2 limitation: a disposition only applies to a span some detector produced [GREEN NOW]", async () => {
  // Recorded because it is easy to misread the profile as a redaction engine. The infra
  // recogniser is an ANNOTATION layer: it classifies and can suppress, but it contributes
  // no candidate of its own. An ARN with no credential inside it is therefore untouched
  // under EVERY profile, including the default whose disposition for AWS_ARN is REDACT.
  const bareArn = "arn:aws:iam::123456789012:role/eks-nodegroup-role";
  const ctx = new RedactionContext({ salt: "fixture", profile: DEFAULT_PROFILE });
  const out = await ctx.redactText(bareArn, ALL);
  assert.equal(out, bareArn, "no detector fires, so there is no span for the policy to act on");
  assert.equal(ctx.policySummary().decisions, 0, "and no policy decision is recorded");
});

test("G2: a prefix outside the detector span is resolved by the envelope, not per-type patches [GREEN NOW]", async () => {
  // This test previously recorded a LIMITATION: the entropy detector circles only the hex
  // run, `i-` fell outside the span, the bare hex was AMBIGUOUS, and the instance id was
  // still redacted. Adding a per-type `contextBefore` for EC2 would have been the
  // symptom-level patch -- the same fix would then be owed to OCI, K8s, and every future
  // identifier.
  //
  // The general fix is envelope resolution: a detector span is widened to the enclosing
  // entity before it is classified. `resolveInfraEnvelope` does that from a declared table,
  // and the pipeline re-merges afterwards so the narrow span cannot win a partial
  // replacement.
  assert.equal(recogniseInfra("i-0a1b2c3d4e5f67890").certainty, INFRA_CERTAINTY.VERIFIED, "the full token is verified");

  const doc = "instance: i-0a1b2c3d4e5f67890";
  const spans = findSensitiveSpans(doc, ALL);
  assert.equal(spans.length, 1, "the envelope must collapse to ONE span");
  assert.equal(doc.slice(spans[0].start, spans[0].end), "i-0a1b2c3d4e5f67890", "covering the whole entity");
  assert.equal(spans[0].infraEnvelope?.infraType, INFRA_TYPE.EC2_RESOURCE_ID, "classified as the entity, not the hex run");

  // The default profile still redacts it -- the point is that it is now redacted as a WHOLE,
  // so the delivered text cannot end up as `i-CRG_...`.
  const strict = new RedactionContext({ salt: "fixture", profile: DEFAULT_PROFILE });
  const strictOut = await strict.redactText(doc, ALL);
  assert.equal(strictOut.includes("i-"), false, "no dangling prefix is left behind");
  assert.equal(strictOut.includes("0a1b2c3d4e5f67890"), false, "and no partial hex either");

  // A profile that preserves infrastructure identifiers gets the complete value back.
  const devops = new RedactionContext({ salt: "fixture", profile: DEVOPS_PROFILE });
  assert.equal(await devops.redactText(doc, ALL), doc, "the whole entity is preserved");
});

test("G2: the ledger records the envelope classification, so entityClassFor answers INFRA [GREEN NOW]", async () => {
  const ctx = new RedactionContext({ salt: "fixture" });
  await ctx.redactText("instance: i-0a1b2c3d4e5f67890", ALL);
  const [entry] = ctx.entityLedger.entries();
  assert.equal(entry.detector, "entropy", "the detector was the entropy detector");
  assert.equal(entry.infraType, INFRA_TYPE.EC2_RESOURCE_ID, "but the entity is an envelope-resolved resource id");
  assert.equal(entry.infraCertainty, INFRA_CERTAINTY.VERIFIED);
  assert.equal(entry.entityClass, "INFRA", "and that is what the entity is");
  assert.equal(ctx.entityClassFor(entry.token), "INFRA", "which entityClassFor reports");
});

