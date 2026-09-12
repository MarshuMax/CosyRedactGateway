// R3.1 -- span-density / merge scaling regression.
//
// Kept SMALL and deterministic so it can live in the normal suite: the full sizes, the MB corpora
// and the soak belong to `npm run perf`. What this file guards is the shape of the growth curve,
// because the defect it was written for was a 30x cost increase at 800 spans and that is visible
// well below the heavy sizes.
//
// A single slow run is NOT a finding; a reproducible superlinear TREND is. The assertion therefore
// requires every ratio in the tail to exceed the bound rather than failing on one sample.

import test from "node:test";
import assert from "node:assert/strict";
import { findSensitiveSpans, RedactionContext } from "../worker.js";
import { measure, report, assertNotSuperlinear } from "./helpers/perf.mjs";

const FLAGS = { gitleaks: true, highEntropy: true, email: true };
const SIZES = [100, 200, 400, 800];
const WATCHDOG_MS = 10_000;

/**
 * Candidate-dense corpora that differ in STRUCTURE, keeping the text per hit roughly constant.
 *
 * `minSpans` is the number of spans each shape legitimately produces per `m`. The `samebound` shape
 * concatenates the addresses, so adjacent ones share a boundary and merge -- measured at m/2, which
 * is correct behaviour rather than a shortfall. Asserting a flat `spans >= m` for every shape was a
 * fixture error.
 */
const SHAPES = {
  disjoint: { make: (m) => Array.from({ length: m }, (_, i) => `user${i}@example.com`).join(" "), minSpans: (m) => m },
  nested: { make: (m) => Array.from({ length: m }, (_, i) => `k${i}=\${{ \${{ user${i}@example.com }} }}`).join("\n"), minSpans: (m) => m },
  samebound: { make: (m) => Array.from({ length: m }, (_, i) => `user${i}@example.com`).join(""), minSpans: (m) => Math.floor(m / 2) },
  dense: { make: (m) => Array.from({ length: m }, (_, i) => `DB_PASSWORD_${i}=wJalrXUtnFEMIK7MDENGbPxRfiCY`).join("\n"), minSpans: (m) => m },
};

async function scalingOf(fn, sizes = SIZES) {
  const points = [];
  let prev = null;
  for (const size of sizes) {
    const { median } = await measure(() => fn(size), { warmup: 1, runs: 3 });
    points.push({ size, median, ratio: prev === null ? null : median / prev });
    prev = median;
    assert.ok(median < WATCHDOG_MS, `watchdog: ${size} took ${median.toFixed(0)}ms`);
  }
  return points;
}

test("R3.1: findSensitiveSpans does not grow quadratically in span density [RED]", async () => {
  // The defect this pins: `enclosingReference()` re-scanned the whole document for EVERY span, so
  // the envelope phase was O(spans x text). Measured before the fix at 800 spans: 832ms for
  // disjoint candidates, 4.8s for nested ones, with a doubling ratio of ~3.9. After computing the
  // document's reference constructs ONCE and scanning that set, the same points are 28ms and 41ms.
  for (const [name, { make, minSpans }] of Object.entries(SHAPES)) {
    const points = await scalingOf((m) => findSensitiveSpans(make(m), FLAGS));
    assertNotSuperlinear(points, { max: 3.2, tail: 2 });
    const spans = findSensitiveSpans(make(SIZES.at(-1)), FLAGS).length;
    const floor = minSpans(SIZES.at(-1));
    assert.ok(spans >= floor, `${name}: the corpus must actually produce candidates (${spans} < ${floor})`);
  }
});

test("R3.1: full redaction follows the same curve as span finding [RED]", async () => {
  // The token-minting stage must not add its own superlinear term. maxRedactions is raised out of
  // the way: it fires during minting and would otherwise cap the measurement rather than describe
  // it -- and it is not a defence for the candidate-merge stage, which runs first.
  const points = await scalingOf(async (m) => {
    const ctx = new RedactionContext({ salt: "perf", maxRedactions: 1e9 });
    await ctx.redactText(SHAPES.disjoint.make(m), FLAGS);
  }, [100, 200, 400]);
  assertNotSuperlinear(points, { max: 3.2, tail: 2 });
});

test("R3.1: the scaling report is available for the record [GREEN NOW]", async () => {
  // Printed rather than asserted, so a trend is visible in the output without becoming a
  // machine-dependent pass/fail condition.
  const points = await scalingOf((m) => findSensitiveSpans(SHAPES.disjoint.make(m), FLAGS), [100, 200, 400]);
  console.log(report("findSensitiveSpans, disjoint candidates", points));
  assert.ok(points.length === 3);
});
