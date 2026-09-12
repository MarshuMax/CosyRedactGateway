// R3 -- heavy performance suite: scaling, MB corpora and soak.
//
// Deliberately NOT part of `npm test`. The full sizes, the multi-megabyte bodies and the soak take
// minutes and produce machine-dependent absolute numbers, which must never become a correctness
// gate for an ordinary test run. `npm test` keeps only the small, deterministic scaling checks.
//
// Usage:
//   node scripts/perf.mjs                 scaling + body sizes
//   node scripts/perf.mjs --soak          additionally run the soak
//   CRG_PERF=1 node --test test/*.perf.test.js   the in-suite scaling checks, at full size

import { measure, report, worstRatio } from "../test/helpers/perf.mjs";
import { findSensitiveSpans, RedactionContext } from "../worker.js";

const FLAGS = { gitleaks: true, highEntropy: true, email: true };
const sizes = [100, 200, 400, 800, 1600, 3200];

const SHAPES = {
  disjoint: (m) => Array.from({ length: m }, (_, i) => `user${i}@example.com`).join(" "),
  nested: (m) => Array.from({ length: m }, (_, i) => `k${i}=\${{ \${{ user${i}@example.com }} }}`).join("\n"),
  samebound: (m) => Array.from({ length: m }, (_, i) => `user${i}@example.com`).join(""),
  dense: (m) => Array.from({ length: m }, (_, i) => `DB_PASSWORD_${i}=wJalrXUtnFEMIK7MDENGbPxRfiCY`).join("\n"),
};

console.log("== R3.1 span density / merge scaling ==");
for (const [name, make] of Object.entries(SHAPES)) {
  const points = [];
  let prev = null;
  for (const m of sizes) {
    const text = make(m);
    const { median } = await measure(() => findSensitiveSpans(text, FLAGS), { warmup: 1, runs: 3 });
    points.push({ size: m, median, ratio: prev === null ? null : median / prev });
    prev = median;
  }
  console.log(report(name, points, (p) => `worst=${worstRatio(points).toFixed(2)}`));
}

if (process.argv.includes("--soak")) {
  console.log("\n== R3.6 soak ==");
  const ctx = () => new RedactionContext({ salt: "soak", maxRedactions: 1e9 });
  const N = Number(process.env.CRG_SOAK_ITERATIONS || 20000);
  const t0 = process.hrtime.bigint();
  let rss0 = process.memoryUsage().rss;
  for (let i = 0; i < N; i++) {
    const c = ctx();
    await c.redactText(`DB_PASSWORD=wJalrXUtnFEMIK7MDENGbPxRfiCY\nnotes: value ${i}`, FLAGS);
    if (i === Math.floor(N / 2)) rss0 = process.memoryUsage().rss;
  }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const rss1 = process.memoryUsage().rss;
  console.log(`  ${N} iterations in ${(ms / 1000).toFixed(1)}s (${(N / (ms / 1000)).toFixed(0)}/s)`);
  console.log(`  RSS after warmup ${(rss0 / 1048576).toFixed(1)} MiB -> end ${(rss1 / 1048576).toFixed(1)} MiB`);
}
