// R3 -- performance measurement helpers.
//
// Three-tier acceptance, so a machine-dependent absolute millisecond never becomes the correctness
// gate:
//
//   PRIMARY   scaling / complexity -- the ratio T(2m)/T(m). This is the gate.
//   SECONDARY same-machine relative baseline -- recorded for trend, not asserted.
//   WATCHDOG  a generous absolute timeout, to stop a hung machine rather than to express an SLA.
//
// A single slow run is NOT a finding. A reproducible superlinear trend is.

/**
 * Median of `runs` timings after `warmup` untimed runs.
 *
 * Median rather than mean because a GC pause or a scheduler hiccup moves the mean and does not move
 * the median, and this suite runs on a shared machine.
 */
export async function measure(fn, { warmup = 2, runs = 5 } = {}) {
  for (let i = 0; i < warmup; i++) await fn();
  const samples = [];
  for (let i = 0; i < runs; i++) {
    const t0 = process.hrtime.bigint();
    await fn();
    samples.push(Number(process.hrtime.bigint() - t0) / 1e6);
  }
  samples.sort((a, b) => a - b);
  return { median: samples[Math.floor(samples.length / 2)], samples, min: samples[0], max: samples[samples.length - 1] };
}

/**
 * Time `fn` at each size and return the doubling ratios.
 *
 * `ratio` is T(2m)/T(m). For a linear pass it approaches 2; for quadratic work it approaches 4.
 */
export async function scaling({ sizes, fn, measureOpts = {} }) {
  const points = [];
  let prev = null;
  for (const size of sizes) {
    const { median } = await measure(() => fn(size), measureOpts);
    points.push({ size, median, ratio: prev === null ? null : median / prev });
    prev = median;
  }
  return points;
}

/** Largest ratio between consecutive points, ignoring the first. */
export const worstRatio = (points) => Math.max(...points.slice(1).map((p) => p.ratio));

/** A readable one-line-per-point report. */
export function report(label, points, extra = () => "") {
  const lines = [`  ${label}`];
  for (const p of points) {
    lines.push(
      `    n=${String(p.size).padStart(5)}  ${p.median.toFixed(2).padStart(9)}ms  ratio=${p.ratio === null ? "   —" : p.ratio.toFixed(2).padStart(5)}  ${extra(p)}`
    );
  }
  return lines.join("\n");
}

/**
 * Fail when every doubling ratio in the tail exceeds `max`, which is the shape of superlinear
 * growth rather than a single unlucky point.
 *
 * `max` defaults to 3: a linear scan measures near 2, and measurement noise on a shared machine can
 * push an individual point well above it, so requiring the WHOLE tail avoids failing on one sample.
 */
export function assertNotSuperlinear(points, { max = 3, tail = 3 } = {}) {
  const ratios = points.slice(1).map((p) => p.ratio);
  const considered = ratios.slice(-tail);
  if (considered.length === 0) return;
  const allAbove = considered.every((r) => r > max);
  if (!allAbove) return;
  throw new Error(
    `superlinear growth: ${considered.map((r) => r.toFixed(2)).join(", ")} all above ${max}\n` +
      points.map((p) => `  n=${p.size} ${p.median.toFixed(2)}ms ratio=${p.ratio === null ? "-" : p.ratio.toFixed(2)}`).join("\n")
  );
}

/** Run `fn` with a watchdog, so a pathological input cannot hang the suite. */
export async function withWatchdog(fn, ms) {
  let timer;
  const guard = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`watchdog fired after ${ms}ms`)), ms);
  });
  try {
    return await Promise.race([fn(), guard]);
  } finally {
    clearTimeout(timer);
  }
}

/** True when the full-size performance suites should run. */
export const perfEnabled = () => process.env.CRG_PERF === "1";
