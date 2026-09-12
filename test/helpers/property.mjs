// R1 -- deterministic property-test harness.
//
// R1 is DELIBERATELY separate from R2:
//
//   R1 (this file plus the *.property.test.js suites) -- KNOWN security properties, checked
//     against a DETERMINISTIC generator. The goal is not to stumble on a bug; it is to show
//     that a property that is already believed holds for every input the generator can make.
//   R2 -- adversarial and random exploration, where the search itself is the point.
//
// Rules this harness exists to enforce:
//   - a fixed seed drives every run, so a failure is reproducible by construction;
//   - no wall clock, no crypto randomness, no Math.random: a property that passes here passes
//     on every machine and on every later run;
//   - a failure prints the SEED and the MINIMAL key input, so a report is actionable without
//     re-running the generator;
//   - case counts stay in the hundreds. Volume is not the objective and a slow suite gets
//     skipped, which would be worse than a smaller one.

/**
 * mulberry32: a small, fast, fully deterministic PRNG. Not for security -- for reproducibility.
 * The same seed produces the same stream on every platform, which `Math.random` cannot promise.
 */
export function makeRng(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    seed,
    float: next,
    int: (min, max) => min + Math.floor(next() * (max - min + 1)),
    pick: (xs) => xs[Math.floor(next() * xs.length)],
    bool: (p = 0.5) => next() < p,
    /** A fresh rng derived from this one: keeps a sub-generator reproducible on its own. */
    derive: () => makeRng(Math.floor(next() * 0xffffffff)),
  };
}

/** A pinned default seed so CI and local runs agree. */
export const DEFAULT_SEED = 0x5eed1234;

/**
 * Run `check(input, index)` for `count` cases from `gen(rng)`.
 *
 * On the first failure, re-runs the generator with a fresh RNG from the SAME seed and stops at
 * the offending index, so the reported input is exactly the one that failed even if the check
 * mutated it.
 */
export function forAll({ seed = DEFAULT_SEED, count = 200, gen, check, label = "property" }) {
  const rng = makeRng(seed);
  for (let i = 0; i < count; i++) {
    const input = gen(rng, i);
    let failure = null;
    try {
      check(input, i);
    } catch (e) {
      failure = e;
    }
    if (failure) {
      // Replay to the same index so the reported case is pristine.
      const replay = makeRng(seed);
      let exact = null;
      for (let j = 0; j <= i; j++) exact = gen(replay, j);
      const minimal = minimize(exact, gen, check, seed, i);
      const detail = [
        `[${label}] property failed`,
        `  seed:  ${seed} (0x${(seed >>> 0).toString(16)})`,
        `  case:  ${i} of ${count}`,
        `  input: ${JSON.stringify(exact)}`,
        minimal !== null && JSON.stringify(minimal) !== JSON.stringify(exact)
          ? `  minimal: ${JSON.stringify(minimal)}`
          : null,
        `  error: ${failure.message}`,
      ].filter(Boolean).join("\n");
      const wrapped = new Error(detail);
      wrapped.cause = failure;
      throw wrapped;
    }
  }
}

/**
 * Shrink toward a small input, on a best-effort basis: for a STRING input, try successively
 * shorter prefixes, then single characters. Text properties in this codebase almost always fail
 * on a short line, and a one-line reproduction is worth the extra passes.
 */
function minimize(input, gen, check, seed, index) {
  if (typeof input !== "string" || input.length <= 1) return null;
  const fails = (candidate) => {
    try { check(candidate, index); return false; } catch { return true; }
  };
  // Prefix search: the smallest prefix that still fails.
  let best = null;
  for (let n = 1; n < input.length; n++) {
    if (fails(input.slice(0, n))) { best = input.slice(0, n); break; }
  }
  if (best === null) return null;
  // Then try to trim from the left as well.
  for (let n = 1; n < best.length; n++) {
    if (fails(best.slice(n))) return best.slice(n);
  }
  return best;
}

/**
 * Generate `count` deterministic cases and return them.
 *
 * Async properties need the cases materialised first, because forAll's `check` is synchronous.
 * Collecting through the SAME seeded rng keeps the cases reproducible and lets forAll still be
 * used for the synchronous half of a property.
 */
export function generate({ seed = DEFAULT_SEED, count = 200, gen }) {
  const rng = makeRng(seed);
  const out = [];
  for (let i = 0; i < count; i++) out.push(gen(rng, i));
  return out;
}

/** Convenience for a property that must hold for every generated input. */
export const must = (cond, message) => {
  if (!cond) throw new Error(message);
};

/** Assert equality with a message that names the values. */
export const mustEqual = (a, b, message) => {
  if (a !== b) throw new Error(`${message}: ${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
};
