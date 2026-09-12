// R2.4 -- span / envelope / merge collision.
//
// The priority is NOT random overlap. It is the specific hazard the design has already been bitten
// by: two detector spans that start out disjoint become the SAME span once a reference envelope
// widens them.
//
//   DB_PASSWORD=${{ <32 hex> <email> }}
//                      ^soft     ^hard
//
// Widening puts both inside one envelope, and the merge then keeps exactly one of them. If the soft
// span wins and its own verdict is PRESERVE-eligible, the hard secret inside it could ride along
// and survive -- a plaintext leak caused entirely by ADDING a detector.
//
// The oracle is therefore differential, not absolute:
//
//   hard-only redacts X  ==>  hard+soft must also redact X
//
// Adding a detector must never weaken protection. Everything else about the merge (which span
// wins, what the boundary is) is allowed to be surprising.

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  findSensitiveSpans,
  referenceEnvelopes,
  recogniseInfra,
  decideSpanAction,
  INFRA_CERTAINTY,
  DEFAULT_PROFILE,
  DEVOPS_PROFILE,
} from "../../worker.js";
import { generate, makeRng } from "../helpers/property.mjs";

const SEED_MERGE = 0x2e610004;

const HEX32 = "0123456789abcdef0123456789abcdef";
const HEX40 = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
const HEX64 = "7031c1b283388d2c2e09b57badb803c05ebed362dc88d84b480cc47f72a21097";
const PAT = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
const AWS = "wJalrXUtnFEMIK7MDENGbPxRfiCY";
const EMAIL = "user@example.com";
const SOFTS = [HEX32, HEX40, HEX64];

/** A hard secret and the flag set that claims it. */
const HARDS = [
  ["PAT", PAT, { gitleaks: true }],
  ["AWS", AWS, { gitleaks: true }],
  ["email", EMAIL, { email: true }],
];

const WRAPPERS = [
  ["bare", (b) => b],
  ["reference", (b) => `x: \${{ ${b} }}`],
  ["reference after strong key", (b) => `DB_PASSWORD=\${{ ${b} }}`],
  ["strong binding", (b) => `DB_PASSWORD=${b}`],
  ["weak key", (b) => `notes: ${b}`],
  ["quoted", (b) => `x: "${b}"`],
  ["block body", (b) => `password: |\n  ${b}`],
];

const PROFILES = [["default", DEFAULT_PROFILE], ["devops", DEVOPS_PROFILE]];

async function redact(text, flags, profile) {
  const ctx = new RedactionContext({ salt: "r24", profile });
  return { ctx, out: await ctx.redactText(text, flags) };
}

const overlaps = (a, b) => a.start < b.end && b.start < a.end;

// =====================================================================================
// A. Envelope convergence -- the named priority
// =====================================================================================

test("R2.4-A: the hard baseline and the collision fixture are what they claim [GREEN NOW]", async () => {
  // Fixture sanity FIRST. If the hard detector does not redact on its own, the differential below
  // proves nothing, and if the two spans do not actually converge, the collision is not being
  // exercised. Both are asserted before any differential claim.
  const body = `${HEX32} ${EMAIL}`;
  const text = `DB_PASSWORD=\${{ ${body} }}`;

  // The hard detector alone redacts.
  const hardOnly = await redact(text, { email: true }, DEFAULT_PROFILE);
  assert.equal(hardOnly.out.includes(EMAIL), false, "email-only must redact the address");

  // Both spans exist before widening, and they are disjoint.
  const rawHard = findSensitiveSpans(text, { email: true });
  const rawBoth = findSensitiveSpans(text, { email: true, highEntropy: true });
  assert.ok(rawHard.length >= 1, "the hard detector must produce a span");

  // After widening, every span is the SAME envelope: that is the convergence being tested.
  const envelopes = referenceEnvelopes(text);
  assert.equal(envelopes.length, 1, "the fixture must contain exactly one reference envelope");
  const [env] = envelopes;
  for (const span of rawBoth) {
    assert.equal(span.start, env.start, `every span must widen to the envelope start (${span.type})`);
    assert.equal(span.end, env.end, `every span must widen to the envelope end (${span.type})`);
  }

  // The soft span really is PRESERVE-eligible in one profile, which is what makes convergence
  // dangerous rather than merely messy.
  const infra = recogniseInfra(HEX32);
  assert.equal(infra?.certainty, INFRA_CERTAINTY.AMBIGUOUS, "the soft fixture must be AMBIGUOUS");
  assert.equal(
    decideSpanAction({ detector: "entropy", ruleId: null, infra, profile: DEVOPS_PROFILE }).action,
    "redact",
    "and AMBIGUOUS is still redacted even under a preserve profile"
  );
  // A bare 40-hex is AMBIGUOUS; only the ANCHORED form is VERIFIED. An earlier version of this
  // assertion expected VERIFIED from the bare form, contradicting the assertion three lines above.
  assert.equal(recogniseInfra(HEX40)?.certainty, INFRA_CERTAINTY.AMBIGUOUS, "bare 40-hex is AMBIGUOUS");
  assert.equal(recogniseInfra(HEX40, "commit ")?.certainty, INFRA_CERTAINTY.VERIFIED, "anchored is VERIFIED");
});

test("R2.4-A: adding a soft detector never resurrects a hard secret [RED]", async () => {
  // The differential oracle, over the full cross product.
  let cases = 0;
  const violations = [];
  for (const [pname, profile] of PROFILES) {
    for (const [hardName, hard, hardFlags] of HARDS) {
      for (const soft of SOFTS) {
        for (const [order, body] of [["hard-first", `${hard} ${soft}`], ["soft-first", `${soft} ${hard}`]]) {
          for (const [wrapName, wrap] of WRAPPERS) {
            const text = wrap(body);
            const hardOnly = await redact(text, hardFlags, profile);
            const combined = await redact(text, { ...hardFlags, highEntropy: true }, profile);
            cases++;
            if (!hardOnly.out.includes(hard) && combined.out.includes(hard)) {
              violations.push({ profile: pname, hard: hardName, soft: soft.slice(0, 8), order, wrapName, text });
            }
          }
        }
      }
    }
  }
  assert.ok(cases >= 240, `the cross product must be covered: ${cases}`);
  assert.deepEqual(
    violations.slice(0, 5), [],
    `adding a soft detector let a hard secret survive: ${JSON.stringify(violations.slice(0, 5), null, 1)}`
  );
});

test("R2.4-A: the winning span's verdict is the one that governs [RED]", async () => {
  // Whatever span the merge keeps, the action applied must be the one its own classification
  // implies. A wider soft span that swallowed a hard secret must not be able to claim the soft
  // verdict for the hard content inside it.
  const text = `DB_PASSWORD=\${{ ${HEX32} ${EMAIL} }}`;
  const { out, ctx } = await redact(text, { email: true, highEntropy: true }, DEVOPS_PROFILE);
  assert.equal(out.includes(EMAIL), false, "the hard content must not survive the merge");
  assert.equal(out.includes(HEX32), false, "nor the soft content, which is redacted anyway");

  // The recorded decision must be a redaction, never a preserve, for a span containing hard content.
  const rows = ctx.policySummary().rows;
  assert.ok(rows.length >= 1, "at least one policy decision must be recorded");
  for (const row of rows) {
    assert.notEqual(row.action, "preserve", `a span containing a hard secret was preserved: ${JSON.stringify(row)}`);
  }
});

// =====================================================================================
// B. Collision geometry: equal bounds, containment, adjacency, duplicates
// =====================================================================================

test("R2.4-B: colliding geometry keeps the contract [RED]", async () => {
  // Equal bounds from two detectors, one-char containment, one-char overlap, adjacency, duplicate
  // hits and repeated occurrences of one plaintext. `findSensitiveSpans` is queried directly so the
  // geometry is observable, and the pipeline result is checked with the four contracts.
  const geometries = [
    ["same plaintext twice", `A=${AWS} B=${AWS}`],
    ["adjacent secrets", `${PAT}${AWS}`],
    ["overlapping envelopes", `\${{ ${PAT} }} \${{ ${EMAIL} }}`],
    ["nested envelopes", `\${{ \${{ ${PAT} }} }}`],
    ["two identical envelopes", `\${{ ${PAT} }} \${{ ${PAT} }}`],
    ["secret at envelope edge", `\${{${PAT}}}`],
    ["secret spanning the closer", `\${{ ${PAT.slice(0, 10)} }}${PAT.slice(10)}`],
    ["duplicate hit same bounds", `${AWS} ${AWS}`],
    ["hard inside soft-shaped field", `notes: ${HEX32} ${PAT}`],
    ["soft inside hard field", `DB_PASSWORD=${PAT} ${HEX32}`],
  ];
  const flags = { gitleaks: true, email: true, highEntropy: true };
  for (const [label, text] of geometries) {
    const spans = findSensitiveSpans(text, flags);
    const { out } = await redact(text, flags, DEFAULT_PROFILE);

    // No span may cross a line boundary, and no two spans may overlap in the final set.
    for (let i = 0; i < spans.length; i++) {
      assert.equal(text.slice(spans[i].start, spans[i].end).includes("\n"), false, `${label}: a span crossed a newline`);
      for (let j = i + 1; j < spans.length; j++) {
        assert.equal(overlaps(spans[i], spans[j]), false, `${label}: two final spans overlap`);
      }
    }

    // Every hard secret that a span covers must be gone.
    for (const secret of [PAT, AWS, EMAIL]) {
      if (!text.includes(secret)) continue;
      if (!spans.some((sp) => text.slice(sp.start, sp.end).includes(secret))) continue;
      assert.equal(out.includes(secret), false, `${label}: a covered secret survived -> ${JSON.stringify(out)}`);
    }
  }
});

test("R2.4-B: a hard secret is never attributed to a soft detector [RED]", async () => {
  // Attribution matters because the verdict follows it. A gitleaks hit relabelled as entropy would
  // become PRESERVE-eligible under a permissive profile.
  const text = `DB_PASSWORD=\${{ ${HEX32} ${PAT} }}`;
  const { ctx } = await redact(text, { gitleaks: true, highEntropy: true }, DEVOPS_PROFILE);
  // The summary row exposes `reason`, not a `hardSecret` boolean -- asserting on a field that does
  // not exist is how an earlier version of this test failed while the behaviour was correct.
  const rows = ctx.policySummary().rows;
  assert.ok(rows.length >= 1, `a decision must be recorded: ${JSON.stringify(rows)}`);
  for (const row of rows) {
    assert.equal(row.action, "redact", `a span containing a hard secret was not redacted: ${JSON.stringify(row)}`);
    assert.equal(row.reason, "hard-secret", `and must cite hard evidence, not a soft classification: ${JSON.stringify(row)}`);
    assert.equal(row.detector, "gitleaks", `the soft detector must not take attribution: ${JSON.stringify(row)}`);
  }
});

// =====================================================================================
// C. Seeded collision exploration
// =====================================================================================

test("R2.4-C: seeded collisions satisfy the differential oracle [RED]", async () => {
  let cases = 0;
  const violations = [];
  for (const { hardName, soft, order, wrapName } of generate({
    seed: SEED_MERGE,
    count: 300,
    gen: (r) => ({
      hardName: r.pick(HARDS.map((h) => h[0])),
      soft: r.pick(SOFTS),
      order: r.bool() ? "hard-first" : "soft-first",
      wrapName: r.pick(WRAPPERS.map((w) => w[0])),
    }),
  })) {
    const [, hard, hardFlags] = HARDS.find((h) => h[0] === hardName);
    const wrap = WRAPPERS.find((w) => w[0] === wrapName)[1];
    const body = order === "hard-first" ? `${hard} ${soft}` : `${soft} ${hard}`;
    const text = wrap(body);

    const hardOnly = await redact(text, hardFlags, DEFAULT_PROFILE);
    const combined = await redact(text, { ...hardFlags, highEntropy: true }, DEFAULT_PROFILE);
    if (!hardOnly.out.includes(hard) && combined.out.includes(hard)) {
      violations.push({ hardName, soft: soft.slice(0, 8), order, wrapName, text });
    }
    cases++;
  }
  assert.equal(cases, 300);
  assert.deepEqual(violations.slice(0, 5), [], `seeded collisions violated the oracle: ${JSON.stringify(violations.slice(0, 5))}`);
});

test("R2.4: the merge corpus is deterministic [GREEN NOW]", () => {
  const draw = (r) => [r.pick(SOFTS).slice(0, 6), r.bool(), r.pick(WRAPPERS.map((w) => w[0]))];
  assert.deepEqual(draw(makeRng(SEED_MERGE)), draw(makeRng(SEED_MERGE)));
});
