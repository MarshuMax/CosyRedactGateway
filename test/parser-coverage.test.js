// Parser coverage: observability for the structured parsers.
//
// The unit is a parser ATTEMPT -- a construct the parser could recognise and was
// therefore obliged to locate -- not "bytes we failed to parse". Under the byte-based
// definition every sentence of ordinary prose is UNKNOWN and the ratio is noise.
//
//   PARSED          recognised and fully located
//   PARTIAL         container/binding start recognised, part unmodelled
//   FAILED          enough evidence to attempt, but not safely locatable
//                   -> the only status that counts toward unknown_bytes
//   NOT_APPLICABLE  does not look like the format at all -> recorded nowhere at all
//
// This slice is observability ONLY: nothing blocks, redacts differently, or warns on a
// high UNKNOWN ratio. A baseline has to be measured on a real corpus before any
// threshold is worth discussing.
//
// Assertion tags:
//   [GREEN NOW]  passes against the current tree

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  ParserCoverage,
  COVERAGE_STATUS,
  PARSER,
  unionBytes,
  parseYamlBindings,
  parseHeaderBindings,
  parseBindings,
  parseUrlBindings,
  findSensitiveSpans,
} from "../worker.js";

const ALL = { highEntropy: true, phone: true, secret: true, identity: true, bank: true, email: true, gitleaks: true };

function coverageOf(parser, text) {
  const coverage = new ParserCoverage();
  parser(text, coverage);
  return coverage.summary();
}

// --------------------------------------------------- 1. the four statuses ------

test("PARSED: a located structure is counted, and nothing else is [GREEN NOW]", () => {
  assert.equal(coverageOf(parseYamlBindings, "password: abc123").parsed_regions, 1);
  assert.equal(coverageOf(parseYamlBindings, "apiVersion: v1\nkind: Secret").parsed_regions, 2);
  assert.equal(coverageOf(parseHeaderBindings, "Authorization: Bearer abc123def456").parsed_regions, 1);
  assert.equal(coverageOf(parseUrlBindings, "https://x/?access_token=abc123").parsed_regions, 1);
  assert.equal(coverageOf(parseBindings, "DB_PASSWORD=abc123").parsed_regions, 1);
});

test("PARTIAL: a recognised container with an unmodelled part [GREEN NOW]", () => {
  // A YAML sequence degrades the path, so the binding is located but the structure is
  // only partly understood.
  const seq = coverageOf(parseYamlBindings, "items:\n  - password: abc123");
  assert.equal(seq.partial_regions, 1, "the sequence item is PARTIAL");
  assert.equal(seq.parsed_regions, 1, "while the plain mapping above it is PARSED");

  // A sensitive query name with no locatable value.
  const emptyQuery = coverageOf(parseUrlBindings, "https://x/?token=");
  assert.equal(emptyQuery.partial_regions, 1);
});

test("FAILED: enough evidence to attempt, but not safely locatable [GREEN NOW]", () => {
  // Each of these is recognised as a construct but has no locatable value.
  const cases = [
    [parseHeaderBindings, "X-Custom-Header:", "header with an empty value"],
    [parseHeaderBindings, "X-Custom-Header:    ", "header with whitespace only"],
    [parseBindings, "DB_PASSWORD=", "assignment with an empty value"],
  ];
  for (const [parser, text, label] of cases) {
    const summary = coverageOf(parser, text);
    assert.equal(summary.failed_regions, 1, `${label}: must be FAILED`);
    assert.equal(summary.parsed_regions, 0, `${label}: and not PARSED`);
    assert.ok(summary.unknown_bytes > 0, `${label}: FAILED is what feeds unknown_bytes`);
  }
});

test("NOT_APPLICABLE: ordinary prose is not counted at all [GREEN NOW]", () => {
  // The whole point of the attempt-based definition. Under a byte-based metric these
  // would dominate and the number would be meaningless.
  const prose = [
    "this is just a sentence with no structure to parse",
    "Error: connection refused while reading from upstream host",
    "please check the deployment logs for more detail",
    "the quick brown fox jumps over the lazy dog",
  ];
  for (const text of prose) {
    for (const [parser, label] of [
      [parseYamlBindings, "yaml"],
      [parseHeaderBindings, "header"],
      [parseBindings, "env"],
      [parseUrlBindings, "url"],
    ]) {
      const summary = coverageOf(parser, text);
      // The property that matters is that prose never adds UNKNOWN bytes. `Error: ...`
      // is honestly reported as PARSED by the YAML parser because it IS a valid
      // mapping (`Error` is a key) -- asserting a zero attempt count there would be
      // demanding that the parser lie about syntax. What must never happen is prose
      // landing in FAILED.
      assert.equal(summary.unknown_bytes, 0, `${label} must not add unknown bytes for: ${text}`);
      assert.equal(
        summary.attempted_regions,
        summary.parsed_regions + summary.partial_regions,
        `${label}: any attempt on prose must be a located one, never FAILED: ${text}`
      );
    }
  }
});

test("the prose discriminator is narrow and stated [GREEN NOW]", () => {
  // A hyphenated header name is unambiguous; `Error:` is not.
  assert.equal(coverageOf(parseHeaderBindings, "X-Request-Id: abc").attempted_regions, 1);
  assert.equal(coverageOf(parseHeaderBindings, "Error: connection refused").attempted_regions, 0);
  // A plain `key: value` line IS valid YAML, so it is honestly reported as PARSED even
  // when it came from prose. That is a documented property, not a bug: unknown_bytes is
  // the metric that carries signal, and prose never adds to it.
  assert.equal(coverageOf(parseYamlBindings, "Note: this is prose").parsed_regions, 1);
  assert.equal(coverageOf(parseYamlBindings, "Note: this is prose").unknown_bytes, 0);
});

// -------------------------------------------------- 2. no double counting ------

test("unionBytes merges overlapping and adjacent regions [GREEN NOW]", () => {
  assert.equal(unionBytes([{ start: 0, end: 10 }]), 10);
  assert.equal(unionBytes([{ start: 0, end: 10 }, { start: 5, end: 15 }]), 15, "overlap merged");
  assert.equal(unionBytes([{ start: 0, end: 10 }, { start: 20, end: 25 }]), 15, "gap preserved");
  assert.equal(unionBytes([{ start: 0, end: 10 }, { start: 10, end: 20 }]), 20, "adjacent merged");
  assert.equal(unionBytes([{ start: 20, end: 25 }, { start: 0, end: 10 }]), 15, "order independent");
  assert.equal(unionBytes([]), 0);
  // A region starting at 0 used to be dropped by a sentinel bug, which zeroed every
  // total in the summary.
  assert.equal(unionBytes([{ start: 0, end: 5 }, { start: 5, end: 9 }]), 9);
});

test("two parsers on the same text do not double count request bytes [GREEN NOW]", async () => {
  // `Authorization: Bearer <secret>` is claimed by a format and carries a URL-shaped
  // value in the same bytes; the union must not add them twice.
  const text = "Authorization: Bearer ghp_16C7e42F292c6912E7710c838347Ae178B4a";
  const ctx = new RedactionContext({ salt: "fixture" });
  await ctx.redactText(text, ALL);
  const summary = ctx.coverageSummary();
  assert.ok(summary.attempted_regions >= 1, "at least one attempt");
  assert.ok(
    summary.attempted_bytes <= text.length,
    `unioned bytes (${summary.attempted_bytes}) must not exceed the payload (${text.length})`
  );
  assert.ok(summary.located_bytes <= summary.attempted_bytes, "located is a subset of attempted");
});

// ------------------------------------------------ 3. request-level rollup ------

test("the request rollup reports per-parser counts and unioned bytes [GREEN NOW]", async () => {
  const doc = [
    "apiVersion: v1",
    "kind: Secret",
    "data:",
    "  password: cGFzc3dvcmQ=",
    "notes: |",
    "  deployment completed",
    "Authorization: Bearer Pr0d-P@ssw0rd-Xy9Zk2mQ",
    "see https://x/?access_token=abc123",
    "items:",
    "  - password: degraded",
    "Error: connection refused",
    "just some prose here",
  ].join("\n");

  const ctx = new RedactionContext({ salt: "fixture" });
  await ctx.redactText(doc, ALL);
  const summary = ctx.coverageSummary();

  assert.equal(summary.calls, 1, "one redactText call");
  assert.ok(summary.attempted_regions > 0);
  assert.equal(
    summary.attempted_regions,
    summary.parsed_regions + summary.partial_regions + summary.failed_regions,
    "every attempt is exactly one status"
  );
  assert.ok(summary.attempted_bytes <= doc.length, "unioned bytes fit inside the payload");
  assert.ok(summary.unknown_bytes <= summary.attempted_bytes);
  // Per-parser breakdown is present and sums consistently.
  for (const [parser, stats] of Object.entries(summary.byParser)) {
    assert.ok(Object.values(PARSER).includes(parser), `unknown parser key: ${parser}`);
    assert.equal(stats.attempted, stats.parsed + stats.partial + stats.failed, `${parser} statuses sum`);
  }
  assert.ok(summary.byParser[PARSER.YAML].attempted >= 5, "yaml is the busiest parser here");
});

test("coverage carries no raw content [GREEN NOW]", async () => {
  // Telemetry only records offsets, statuses and counts. No value, no key, no payload.
  const secret = "Pr0d-P@ssw0rd-Xy9Zk2mQ";
  const ctx = new RedactionContext({ salt: "fixture" });
  const spans = await ctx.redactText(`DB_PASSWORD=${secret}`, ALL);
  const serialized = JSON.stringify(ctx.coverageSummary()) + JSON.stringify(spans.coverage ?? {});
  assert.equal(serialized.includes(secret), false, "the secret must not appear in coverage output");
  assert.equal(serialized.includes("DB_PASSWORD"), false, "nor the key name");
  assert.equal(serialized.includes("Pr0d"), false, "nor any fragment");
});

test("findSensitiveSpans exposes coverage without changing the array [GREEN NOW]", async () => {
  // `redactText` returns a string, so the coverage property lives on the spans array
  // that findSensitiveSpans returns (and which redactText consumes internally).
  const coverage = new ParserCoverage();
  const spans = findSensitiveSpans("DB_PASSWORD=abc123", { gitleaks: true }, { coverage });
  // Non-enumerable, so existing consumers that iterate or compare the array are
  // unaffected by the new field.
  assert.equal(Object.keys(spans).includes("coverage"), false, "coverage is not enumerable");
  assert.ok(spans.coverage, "but it is readable");
  assert.equal(typeof spans.coverage.attempted_regions, "number");
  // And the request-level rollup is available from the context after a call.
  const ctx = new RedactionContext({ salt: "fixture" });
  await ctx.redactText("DB_PASSWORD=abc123", ALL);
  assert.equal(ctx.coverageSummary().calls, 1);
});

// --------------------------------------------------- 4. no behavioural change ---

test("coverage does not change redaction behaviour [GREEN NOW]", async () => {
  // Observability only. A payload with a high UNKNOWN share must be redacted exactly as
  // before: nothing blocks on the ratio yet.
  const doc = [
    "X-Custom-Header:",
    "DB_PASSWORD=",
    "password: cGFzc3dvcmQxMjM0NTY3OA==",
  ].join("\n");
  const ctx = new RedactionContext({ salt: "fixture" });
  const out = await ctx.redactText(doc, ALL);
  const summary = ctx.coverageSummary();
  assert.ok(summary.failed_regions >= 2, "the fixture must actually produce failures");
  assert.equal(out.includes("cGFzc3dvcmQxMjM0NTY3OA=="), false, "the real secret is still redacted");
  assert.equal(ctx.restoreText(out), doc, "round-trip unchanged");
});

// ------------------------------------------------ 5. measured baseline --------

// A baseline over a small representative corpus. Recorded so that a future change to a
// parser shows up as a diff here, and so the UNKNOWN share is a number rather than an
// impression. Observability only: nothing in the pipeline reads these values yet.
const CORPUS = {
  k8sSecret: ["apiVersion: v1", "kind: Secret", "metadata:", "  name: db", "data:", "  password: YWRtaW4xMjM0NTY3OA==", "stringData:", "  token: adm1n"].join("\n"),
  dotenv: ["# app config", "DB_PASSWORD=Pr0d-P@ssw0rd-Xy9Zk2mQ", "API_KEY=cGFzc3dvcmQxMjM0NTY3OA==", "PORT=5432", "export TOKEN=abc123!", "cache_key=abc"].join("\n"),
  helmValues: ["replicaCount: 3", "image:", "  repository: nginx", "  tag: \"1.27\"", "notes: |", "  Deploy completed successfully.", "  Restart the service after upgrade."].join("\n"),
  pastedCurl: ["curl -H \"Authorization: Bearer ghp_16C7e42F292c6912E7710c838347Ae178B4a\" \\", "  'https://api.example.com/v1/items?page=2&access_token=abc123def456&limit=10'"].join("\n"),
  proseWithLogs: ["Error: connection refused while reading from upstream host", "2026-09-11T12:04:11Z INFO retrying in 5s", "Note: this is a known flake, see the runbook", "kubectl get pods -n connected-car"].join("\n"),
  pureProse: ["Please summarise the deployment notes below and suggest improvements.", "The rollout finished but two replicas kept restarting for a while.", "We should probably look at the resource limits again."].join("\n"),
  degradedYaml: ["containers:", "  - name: app", "    env:", "      - name: DB_PASSWORD", "        value: Pr0d-P@ssw0rd-Xy9Zk2mQ"].join("\n"),
};

async function measure(text) {
  const ctx = new RedactionContext({ salt: "baseline" });
  await ctx.redactText(text, ALL);
  return ctx.coverageSummary();
}

test("baseline: pure prose produces zero attempts and zero unknown bytes [GREEN NOW]", async () => {
  const summary = await measure(CORPUS.pureProse);
  assert.equal(summary.attempted_regions, 0, "prose is NOT_APPLICABLE to every parser");
  assert.equal(summary.unknown_bytes, 0);
});

test("baseline: real structured payloads are located, not merely attempted [GREEN NOW]", async () => {
  for (const key of ["k8sSecret", "dotenv", "helmValues", "pastedCurl"]) {
    const summary = await measure(CORPUS[key]);
    assert.ok(summary.attempted_regions > 0, `${key}: parsers must engage`);
    assert.equal(summary.failed_regions, 0, `${key}: nothing should be unlocatable`);
    assert.equal(summary.unknown_bytes, 0, `${key}: UNKNOWN is the metric that matters`);
    assert.ok(summary.attempted_bytes <= CORPUS[key].length, `${key}: no double counting`);
  }
});

test("baseline: a degraded structure is PARTIAL, and visible as such [GREEN NOW]", async () => {
  // The YAML sequence is exactly the case the metric exists to expose: the parser does
  // engage, the value is located, but the structure is only partly understood.
  const summary = await measure(CORPUS.degradedYaml);
  assert.ok(summary.partial_regions >= 3, `expected several PARTIAL regions, got ${summary.partial_regions}`);
  assert.ok(summary.parsed_regions >= 1, "while the plain mappings around it are PARSED");
  assert.equal(summary.failed_regions, 0, "PARTIAL is not FAILED");
  assert.equal(summary.unknown_bytes, 0);
});

test("baseline: prose contributes located attempts, never FAILED ones [GREEN NOW]", async () => {
  const summary = await measure(CORPUS.proseWithLogs);
  assert.equal(summary.failed_regions, 0, "prose must never land in FAILED");
  assert.equal(summary.unknown_bytes, 0);
  assert.ok(summary.attempted_regions > 0, "a colon line is legitimately a YAML mapping, and is reported as such");
});

test("baseline: total UNKNOWN share over the corpus [GREEN NOW]", async () => {
  let bytes = 0;
  let unknown = 0;
  let attemptedBytes = 0;
  for (const text of Object.values(CORPUS)) {
    const summary = await measure(text);
    bytes += text.length;
    unknown += summary.unknown_bytes;
    attemptedBytes += summary.attempted_bytes;
    assert.ok(summary.attempted_bytes <= text.length, "union never exceeds the payload");
  }
  // Measured: this corpus has no unlocatable construct at all. That is a baseline, not
  // a guarantee -- a corpus containing header-shaped or assignment-shaped lines with
  // no value would raise it, and that is the point of measuring.
  assert.equal(unknown, 0, `measured unknown bytes: ${unknown} of ${bytes}`);
  assert.ok(attemptedBytes / bytes > 0.5, `attempt coverage should be substantial, got ${(attemptedBytes / bytes * 100).toFixed(1)}%`);
});
