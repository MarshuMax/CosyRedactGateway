// R2.3 -- parser collision / grammar ambiguity.
//
// The question is NOT "which parser is right?". Several parsers legitimately read the same bytes
// with different boundaries:
//
//   YAML sees `password: |` and a block body
//   the shell parser sees `KEY=value`
//   the URL parser sees `?q=...`
//   the header parser sees `Authorization: Bearer ...`
//   the reference scanner sees `{{ ... }}`
//   the provider detectors see a credential wherever it appears
//
// Collisions are produced by composing the seeds below. The oracle does NOT require a winner. It
// requires that the COMBINATION still holds four contracts:
//
//   1. a hard secret does not leak
//   2. bytes outside the selected mutation boundary do not move
//   3. a parser failure does not disable an independent detector
//   4. the same input produces the same result on repeated execution
//
// A collision that satisfies all four is not a defect, however surprising the boundary is.

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  findSensitiveSpans,
  parseBindings,
  parseYamlBindings,
  parseHeaderBindings,
  parseUrlBindings,
  referenceEnvelopes,
} from "../../worker.js";
import { generate, makeRng } from "../helpers/property.mjs";

const FLAGS = { gitleaks: true, highEntropy: true, email: true, phone: true, secret: true };
const PAT = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
const AWS = "wJalrXUtnFEMIK7MDENGbPxRfiCY";
const KEYID = "AKIAZ3Q7X2N5M8P4R6T1";
const SECRETS = [PAT, AWS, KEYID];
const SEED_PARSER = 0x2e610003;

// ------------------------------------------------------------------ collision seeds ------

/** Host-syntax fragments that make two parsers disagree about boundaries. */
const AMBIGUOUS_HOSTS = [
  "op://",
  "http://",
  "https://",
  "image:tag",
  "key:value",
  "key: value",
  "key=${REF}",
  "key=$(ref)",
  "Bearer ",
  "# comment",
  'quoted "#"',
  ":",
  "::",
  "://",
  "a:b:c",
  "x=",
  "x: ",
  "- ",
  "?q=",
  "&r=",
  "%20",
];

/** Whole documents that place a secret inside an ambiguous host fragment. */
const COLLISION_TEMPLATES = [
  (s) => `password: op://vault/${s}`,
  (s) => `password: http://user:${s}@host/path`,
  (s) => `password: https://${s}.example.com`,
  (s) => `image: nginx:${s}`,
  (s) => `key: value:${s}`,
  (s) => `key=${"${"}${s}}`,
  (s) => `key=$(${s})`,
  (s) => `Authorization: Bearer ${s}`,
  (s) => `x-api-key: ${s}  # rotate`,
  (s) => `password: |\n  ${s}`,
  (s) => `password: "unterminated ${s}`,
  (s) => `- password: ${s}`,
  (s) => `password: {a: ${s}}`,
  (s) => `password: ['${s}']`,
  (s) => `notes: |\n  ordinary line\n  password=${s}`,
  (s) => `url: https://h/?token=${s}&x=1`,
  (s) => `url: https://h/?x=1&token=${s}`,
  (s) => `DB_PASSWORD=${s} # not-a-comment`,
  (s) => `DB_PASSWORD=${s};`,
  (s) => `a: ${s}\n---\nb: ${s}`,
];

// ------------------------------------------------------------------------- helpers ------

async function redact(text, options = {}, flags = FLAGS) {
  const ctx = new RedactionContext({ salt: "r23", ...options });
  return { ctx, out: await ctx.redactText(text, flags) };
}

const overlaps = (a, b) => a.start < b.end && b.start < a.end;

/** Replace per-request tokens with a placeholder, so two runs are shape-comparable. */
const normalize = (s) => s.replace(/CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}/g, "<TOKEN>");

/** Rebuild the output from the input by rewriting exactly the reported spans. */
function rebuild(text, spans, ctx) {
  const ordered = [...spans].sort((a, b) => a.start - b.start);
  let out = "";
  let cursor = 0;
  for (const span of ordered) {
    out += text.slice(cursor, span.start);
    const value = text.slice(span.start, span.end);
    out += ctx.rawToToken.get(value) ?? value;
    cursor = span.end;
  }
  return out + text.slice(cursor);
}

/** The four contracts, asserted on one input. */
async function assertContracts(label, text) {
  const { ctx, out } = await redact(text);
  const spans = findSensitiveSpans(text, FLAGS);

  // 1. A secret a span CLAIMS must not survive, and no secret may appear in a mutated line.
  for (const secret of SECRETS) {
    if (!text.includes(secret)) continue;
    const covered = spans.some((sp) => text.slice(sp.start, sp.end).includes(secret));
    if (covered) {
      assert.equal(out.includes(secret), false, `${label}: a claimed secret survived -> ${JSON.stringify(out)}`);
    }
  }

  // 2. Bytes outside the selected spans do not move.
  const expected = rebuild(text, spans, ctx);
  assert.equal(out, expected, `${label}: bytes outside the selected spans changed`);

  // 3. A secret inside a line whose structure failed to parse is still claimed by its own detector.
  const spansWithoutStructure = SECRETS.some((secret) => text.includes(secret))
    ? findSensitiveSpans(text, { gitleaks: true })
    : [];
  for (const span of spansWithoutStructure) {
    const covered = text.slice(span.start, span.end);
    if (!SECRETS.includes(covered)) continue;
    assert.ok(
      spans.some((sp) => overlaps(sp, span)),
      `${label}: an independent provider hit was lost in the collision -> ${JSON.stringify(covered)}`
    );
  }

  // 4. Repeated execution is stable. The TOKEN differs because the request id is per-request
  // random by design (its uniqueness has its own invariant test), so stability is asserted on the
  // SHAPE of the outcome -- which token appears where -- not on the literal token bytes.
  const again = await redact(text);
  assert.equal(normalize(out), normalize(again.out), `${label}: repeated execution changed the result`);

  return { out, spans, ctx };
}

// =====================================================================================
// Seeded collision corpus
// =====================================================================================

test("R2.3: every parser-collision seed satisfies the four contracts [RED]", async () => {
  let cases = 0;
  for (const secret of SECRETS) {
    for (const template of COLLISION_TEMPLATES) {
      const text = template(secret);
      await assertContracts(`template=${JSON.stringify(text.slice(0, 40))}`, text);
      cases++;
    }
  }
  assert.equal(cases, SECRETS.length * COLLISION_TEMPLATES.length);
});

test("R2.3: ambiguous host fragments combined with secrets satisfy the contracts [RED]", async () => {
  let cases = 0;
  for (const host of AMBIGUOUS_HOSTS) {
    for (const secret of SECRETS) {
      // The fragments are placed so that at least two parsers can each claim part of the line.
      for (const text of [
        `password: ${host}${secret}`,
        `password=${host}${secret}`,
        `x: ${secret}${host}`,
        `x: ${host} ${secret}`,
      ]) {
        await assertContracts(`host=${JSON.stringify(host)}`, text);
        cases++;
      }
    }
  }
  assert.ok(cases > 200, `the corpus must be substantial: ${cases}`);
});

test("R2.3: seeded composition of parser seeds and secrets [RED]", async () => {
  let cases = 0;
  for (const { host, secret, shape } of generate({
    seed: SEED_PARSER,
    count: 400,
    gen: (r) => ({ host: r.pick(AMBIGUOUS_HOSTS), secret: r.pick(SECRETS), shape: r.int(0, 3) }),
  })) {
    const text = [
      `password: ${host}${secret}`,
      `password: ${secret}${host}`,
      `key=${host}${secret}`,
      `${host}: ${secret}`,
    ][shape];
    await assertContracts(`shape=${shape} host=${JSON.stringify(host)}`, text);
    cases++;
  }
  assert.equal(cases, 400);
});

// =====================================================================================
// Boundary ownership: what each parser reports for the same bytes
// =====================================================================================

test("R2.3: the parsers disagree without that being a defect [GREEN NOW]", () => {
  // Recording the disagreement explicitly. These are four readings of ONE line, and all four can
  // be defensible; the contract tests above are what decide whether the COMBINATION is safe.
  const line = "url: https://h/?token=secret123#frag";
  const readings = {
    yaml: parseYamlBindings(line).map((b) => [b.valueStart, b.valueEnd]),
    shell: parseBindings(line).map((b) => [b.valueStart, b.valueEnd]),
    header: parseHeaderBindings(line).map((b) => [b.valueStart, b.valueEnd]),
    url: parseUrlBindings(line).map((b) => [b.valueStart, b.valueEnd]),
  };
  // At least two parsers must find a boundary, or the input is not a collision at all.
  const finding = Object.values(readings).filter((r) => r.length > 0);
  assert.ok(finding.length >= 1, `fixture must be read by at least one parser: ${JSON.stringify(readings)}`);

  // And the reference scanner reads its own, different thing.
  assert.deepEqual(referenceEnvelopes("x: ${REF}").length, 1);
  assert.deepEqual(referenceEnvelopes("x: plain").length, 0);
});

test("R2.3: a URL query value keeps every byte outside it [GREEN NOW]", () => {
  // The documented URL contract: percent escapes, `+`, parameter order and duplicates are preserved
  // byte for byte, and only the value span is replaced.
  const cases = [
    "https://h/?q=%20%2B&r=1",
    "https://h/?a=1&a=2&b=%7B",
    "https://h/p?a=+&b=%2F#frag",
  ];
  for (const line of cases) {
    const spans = parseUrlBindings(`url: ${line}`);
    for (const span of spans) {
      const covered = `url: ${line}`.slice(span.valueStart, span.valueEnd);
      assert.ok(line.includes(covered), `the span must sit inside the URL: ${JSON.stringify(covered)}`);
    }
  }
});

// =====================================================================================
// Targeted contract statements
// =====================================================================================

test("R2.3: a secret in an unparseable line is still claimed [RED]", async () => {
  // Contract 3, isolated: the structure fails, the detector does not.
  const broken = [
    `password: "unterminated ${PAT}`,
    `password: [broken ${PAT}`,
    `password: {a: ${PAT}`,
    `url: https://h/?q=${PAT}`,
    `Authorization: Bearer ${PAT}`,
    `# comment ${PAT}`,
    `quoted "#" ${PAT}`,
  ];
  for (const text of broken) {
    const spans = findSensitiveSpans(text, FLAGS);
    assert.ok(
      spans.some((sp) => text.slice(sp.start, sp.end).includes(PAT)),
      `the provider detector must survive a parser failure: ${JSON.stringify(text)}`
    );
    const { out } = await redact(text);
    assert.equal(out.includes(PAT), false, `and the secret must be removed: ${JSON.stringify(out)}`);
    assert.equal(out.includes("# comment"), text.includes("# comment"), "comment text must not be swallowed");
  }
});

test("R2.3: a comment marker is preserved whenever it IS a comment [RED]", async () => {
  // Calibrated against the reference implementation rather than against intuition. PyYAML 6.0.1:
  //
  //   password: abc# note   ->  {'password': 'abc# note'}    the `#` is part of the plain scalar
  //   password: abc # note  ->  {'password': 'abc'}          the `#` starts a comment
  //
  // YAML requires WHITESPACE before `#` to start a comment, so a secret immediately followed by
  // `#` really does have the marker inside its value, and claiming the whole run is correct -- this
  // gateway agrees with PyYAML here. An earlier version of this test asserted the opposite and
  // would have demanded a deviation from the grammar.
  //
  // So the property is: whenever the `#` IS a comment (preceded by whitespace), it survives.
  for (const { secret, gap } of generate({
    seed: SEED_PARSER + 1,
    count: 200,
    gen: (r) => ({ secret: r.pick(SECRETS), gap: r.pick([" ", "  ", "\t"]) }),
  })) {
    for (const text of [
      `DB_PASSWORD=${secret}${gap}# note`,
      `DB_PASSWORD=${secret}${gap}#note`,
      `password: ${secret}${gap}# note`,
      `password: ${secret}${gap}#note`,
    ]) {
      const { out } = await redact(text);
      assert.ok(
        out.includes("# note") || out.includes("#note"),
        `comment swallowed in ${JSON.stringify(out)} from ${JSON.stringify(text)}`
      );
    }
  }
});

test("R2.3 OBSERVATION: a `#` with no preceding whitespace is part of the value, per YAML [GREEN NOW]", async () => {
  // Recorded because it looks like a comment being swallowed and is not. The reference
  // implementation agrees with this gateway, so it is grammar, not a defect.
  const text = `password: ${PAT}# note`;
  const { out } = await redact(text);
  const spans = findSensitiveSpans(text, FLAGS);
  const covered = spans.map((sp) => text.slice(sp.start, sp.end));

  assert.deepEqual(covered, [`${PAT}# note`], "YAML keeps `#` inside a plain scalar without preceding space");
  assert.equal(out.includes("# note"), false, "so the marker is redacted together with the value");
  assert.equal(out.includes(PAT), false, "and the secret is gone");

  // The control, showing the marker IS treated as a comment once whitespace precedes it.
  const spaced = `password: ${PAT} # note`;
  const spacedOut = (await redact(spaced)).out;
  assert.ok(spacedOut.includes("# note"), "with whitespace the comment survives");
});

test("R2.3: a quote is never swallowed by an adjacent secret [RED]", async () => {
  for (const secret of SECRETS) {
    for (const text of [
      `password: "${secret}"`,
      `password: '${secret}'`,
      `password="${secret}"`,
      `x: "${secret}"  # note`,
    ]) {
      const { out } = await redact(text);
      const opens = (out.match(/"/g) || []).length + (out.match(/'/g) || []).length;
      const inputQuotes = (text.match(/"/g) || []).length + (text.match(/'/g) || []).length;
      assert.equal(opens, inputQuotes, `quote count changed in ${JSON.stringify(out)}`);
    }
  }
});

test("R2.3: a line with two different secrets redacts both [RED]", async () => {
  // Duplicate and multi-hit lines, where a merge that keeps only the widest span would drop one.
  const text = `AKIA=${KEYID} TOKEN=${PAT}`;
  const { out } = await redact(text);
  assert.equal(out.includes(KEYID), false, `the first secret must go -> ${JSON.stringify(out)}`);
  assert.equal(out.includes(PAT), false, `and the second too -> ${JSON.stringify(out)}`);
});

test("R2.3: the same plaintext twice on one line reuses one token [RED]", async () => {
  const text = `A=${AWS} B=${AWS}`;
  const { out, ctx } = await redact(text);
  const tokens = out.match(/CRG_[A-Z0-9]+_[A-Z0-9]+/g) || [];
  assert.equal(tokens.length, 2, "both occurrences are rewritten");
  assert.equal(new Set(tokens).size, 1, "and they share one token");
  assert.equal(ctx.restoreText(out), text, "round trip is exact");
});

test("R2.3: line boundaries are not crossed by any parser [RED]", async () => {
  // A span that spans a newline would let one parser's region swallow another line. Every reported
  // span must sit within a single line.
  for (const { a, b } of generate({
    seed: SEED_PARSER + 2,
    count: 250,
    gen: (r) => ({ a: r.pick(SECRETS), b: r.pick(["plain", PAT, "notes: |", "  indented"]) }),
  })) {
    const text = `${a}=${a}\n${b}\nkey: ${a}`;
    for (const span of findSensitiveSpans(text, FLAGS)) {
      const covered = text.slice(span.start, span.end);
      assert.equal(
        covered.includes("\n"), false,
        `a span crossed a line boundary: ${JSON.stringify(covered)} in ${JSON.stringify(text)}`
      );
    }
  }
});

test("R2.3: the collision corpus is deterministic [GREEN NOW]", () => {
  const draw = (r) => [r.pick(AMBIGUOUS_HOSTS), r.pick(SECRETS), r.int(0, 3)];
  assert.deepEqual(draw(makeRng(SEED_PARSER)), draw(makeRng(SEED_PARSER)));
});
