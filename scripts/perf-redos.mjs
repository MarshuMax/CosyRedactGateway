// R3.2 -- regex / ReDoS adversarial sweep.
//
// Run with:  npm run perf:redos   [--family=A] [--max=131072]
//
// Every case runs in a CHILD PROCESS with a generous watchdog (5 s by default). The watchdog exists
// to stop a hung machine, not to express an SLA: a synchronous regex that backtracks cannot be
// interrupted from inside the same process, so the parent kills it instead.
//
// Each family pairs an ADVERSARIAL input with a same-length CONTROL. Without the control, ordinary
// scanning cost is easily mistaken for backtracking, which is the whole point of the pairing.
//
// Reported per point: T(n), the doubling ratio T(2n)/T(n), and adversarial/control. The complexity
// exponent p = log2(T(2n)/T(n)) is reported as a DIAGNOSTIC only -- roughly 1 linear, 2 quadratic,
// much more than 2 suspicious -- and never fails anything on a single noisy sample.
//
// Isolation order when something looks wrong: one flag family -> all flags -> ctx.redactText().

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKER = join(HERE, "r3-redos-worker.mjs");

const SIZES = (process.env.CRG_REDOS_SIZES || "512,1024,2048,4096,8192,16384,32768,65536,131072")
  .split(",").map(Number);
const WATCHDOG_MS = Number(process.env.CRG_REDOS_WATCHDOG || 5000);
const TARGET_MS = Number(process.env.CRG_REDOS_TARGET || 20);
const FAMILY = (process.argv.find((a) => a.startsWith("--family=")) || "").split("=")[1] || null;
const MAX = Number((process.argv.find((a) => a.startsWith("--max=")) || "").split("=")[1] || SIZES.at(-1));

const FLAGS = { gitleaks: true, highEntropy: true, email: true, phone: true, secret: true, identity: true, bank: true };

/** Run one case in a child process. Resolves to a result record, or a timeout record. */
function runCase(spec) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [WORKER, JSON.stringify(spec)], { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    const timer = setTimeout(() => {
      // kill() and not a polite signal: a backtracking regex ignores everything else.
      child.kill("SIGKILL");
      resolve({ timedOut: true });
    }, WATCHDOG_MS);
    child.stdout.on("data", (d) => { out += d; });
    child.stderr.on("data", (d) => { err += d; });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) return resolve({ crashed: true, code, err: err.slice(0, 300) });
      try { resolve(JSON.parse(out)); } catch { resolve({ crashed: true, code, err: `unparseable: ${out.slice(0, 200)}` }); }
    });
  });
}

const caseSpec = (text, extra = {}) => ({ kind: "find", text, flags: FLAGS, targetMs: TARGET_MS, ...extra });

// =====================================================================================
// Families
// =====================================================================================

const pad = (n, s = "A") => s.repeat(Math.max(0, n));

const FAMILIES = {
  // A. Generic assignment rules. Highest priority: a nested quantifier here once cost >60s.
  "A-assignment": {
    adversarial: (n) => `password${pad(n, " ")}`,
    control: (n) => `password=${pad(n, "x")}`,
  },
  "A-assignment-delimiter": {
    // A long key, a long whitespace run, and the delimiter never arrives.
    adversarial: (n) => `${pad(Math.floor(n / 2), "k")}${pad(Math.floor(n / 4), " ")}:${pad(Math.floor(n / 4), " ")}`,
    control: (n) => `${pad(Math.floor(n / 2), "k")}: ${pad(Math.floor(n / 4), "v")}`,
  },
  "A-assignment-quote": {
    // An unterminated quote after a long run.
    adversarial: (n) => `token="${pad(n, "q")}`,
    control: (n) => `token="${pad(n, "q")}"`,
  },
  "A-assignment-siblings": {
    // Many fragments that each look like an assignment but never complete, plus one SUCCESSFUL
    // sibling so a genuine scan cost is visible next to the near-miss.
    adversarial: (n) => `${Array.from({ length: Math.max(1, Math.floor(n / 24)) }, () => "key = ").join("")}`,
    control: (n) => `${Array.from({ length: Math.max(1, Math.floor(n / 24)) }, () => "key=").join("")}x${pad(8)}`,
  },
  "A-assignment-separators": {
    adversarial: (n) => `password${pad(n, "=")}`,
    control: (n) => `password=${pad(n, "a")}`,
  },

  // B. Provider token near-miss: a valid prefix, a long body, and a failing tail.
  "B-provider-wrong-tail": {
    adversarial: (n) => `ghp_${pad(n, "a")}!`,
    control: (n) => `ghp_${pad(n, "a")}`,
  },
  "B-provider-missing-terminator": {
    adversarial: (n) => `AKIA${pad(n, "A")}`,
    control: (n) => `AKIA${pad(Math.max(0, n - 1), "A")}Z`,
  },
  "B-provider-almost-suffix": {
    adversarial: (n) => `sk_live_${pad(n, "1")}$`,
    control: (n) => `sk_live_${pad(n, "1")}Z`,
  },
  "B-provider-long-class": {
    adversarial: (n) => `xoxb-${pad(n, "9")}-`,
    control: (n) => `xoxb-${pad(n, "9")}-Z`,
  },

  // C. Reference / structured parser pathological input.
  "C-reference-unclosed": {
    adversarial: (n) => `${"$".repeat(1)}{${"{".repeat(Math.floor(n / 2))}`,
    control: (n) => `x${pad(n)}`,
  },
  "C-reference-depth": {
    adversarial: (n) => `${"${{ ".repeat(Math.floor(n / 10))}`,
    control: (n) => `x${pad(n)}`,
  },
  "C-reference-siblings": {
    adversarial: (n) => `${"${A} ".repeat(Math.floor(n / 5))}`,
    control: (n) => `x${pad(n)}`,
  },
  "C-reference-unclosed-paren": {
    adversarial: (n) => `$( ${"(".repeat(Math.floor(n / 2))}`,
    control: (n) => `x${pad(n)}`,
  },

  // D. Structured grammar near-miss.
  "D-yaml-unclosed-quote": {
    adversarial: (n) => `key: "${pad(n, "v")}`,
    control: (n) => `key: "${pad(n, "v")}"`,
  },
  "D-yaml-deep-indent": {
    adversarial: (n) => `${Array.from({ length: Math.floor(n / 40) }, (_, i) => `${pad((i % 40) + 1, " ")}key${i}:`).join("\n")}`,
    control: (n) => `${Array.from({ length: Math.floor(n / 40) }, (_, i) => `key${i}: v`).join("\n")}`,
  },
  "D-url-repeated-param": {
    adversarial: (n) => `https://h/?${Array.from({ length: Math.floor(n / 8) }, () => "a=").join("&")}`,
    control: (n) => `https://h/?${Array.from({ length: Math.floor(n / 8) }, (_, i) => `a${i}=v`).join("&")}`,
  },
  "D-email-failing-tail": {
    adversarial: (n) => `${pad(n, "a")}@`,
    control: (n) => `${pad(n, "a")}@example.com`,
  },
  "D-email-long-domain": {
    adversarial: (n) => `u@${pad(n, "a")}.`,
    control: (n) => `u@${pad(n, "a")}.com`,
  },
  "D-header-bearer-tail": {
    adversarial: (n) => `Authorization: Bearer ${pad(n, "A")}=`,
    control: (n) => `Authorization: Bearer ${pad(n, "A")}Z`,
  },
  "D-whitespace-chain": {
    adversarial: (n) => `key:${pad(n, " ")}`,
    control: (n) => `key: ${pad(n, "v")}`,
  },
};

// =====================================================================================
// Driver
// =====================================================================================

const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];

async function measurePoint(text, { runs = 5, warmup = 2 } = {}) {
  // The worker already repeats internally, so one child per run; the median across runs absorbs
  // machine noise the way the R3 standard asks.
  const samples = [];
  let timedOut = false;
  for (let i = 0; i < warmup + runs; i++) {
    const r = await runCase(caseSpec(text));
    if (r.timedOut) { timedOut = true; break; }
    if (r.crashed) return { crashed: r };
    if (i >= warmup) samples.push(r);
  }
  if (timedOut) return { timedOut: true };
  return {
    perIteration: median(samples.map((s) => s.perIteration)),
    iterations: median(samples.map((s) => s.iterations)),
    reachedTarget: samples.every((s) => s.reachedTarget),
  };
}

const names = FAMILY ? Object.keys(FAMILIES).filter((k) => k.startsWith(FAMILY)) : Object.keys(FAMILIES);
console.log(`R3.2 ReDoS sweep -- watchdog ${WATCHDOG_MS}ms, target ${TARGET_MS}ms/point, sizes up to ${MAX}`);
console.log("");

const summary = [];

for (const name of names) {
  const family = FAMILIES[name];
  const sizes = SIZES.filter((n) => n <= MAX);
  const rows = [];
  let prevAdv = null;
  let prevCtl = null;

  for (const n of sizes) {
    const ctl = await measurePoint(family.control(n));
    const adv = await measurePoint(family.adversarial(n));
    const row = { n, ctl, adv };
    rows.push(row);

    const ratio = prevAdv && !adv.timedOut && !prevAdv.timedOut ? adv.perIteration / prevAdv.perIteration : null;
    const p = ratio ? Math.log2(ratio) : null;
    const ac = !adv.timedOut && !ctl.timedOut ? adv.perIteration / ctl.perIteration : null;
    const flag = adv.timedOut ? "TIMEOUT" : (p !== null && p > 2.5 ? `p=${p.toFixed(2)} SUSPECT` : "");
    console.log(
      `  ${name.padEnd(28)} n=${String(n).padStart(6)}  adv=${adv.timedOut ? "TIMEOUT" : adv.perIteration.toFixed(4) + "ms"}` +
      `  ctl=${ctl.timedOut ? "TIMEOUT" : ctl.perIteration.toFixed(4) + "ms"}` +
      `  ratio=${ratio === null ? "  —" : ratio.toFixed(2)}  a/c=${ac === null ? "  —" : ac.toFixed(2)}  ${flag}`
    );
    if (!adv.timedOut) prevAdv = adv;
    if (!ctl.timedOut) prevCtl = ctl;
  }
  const tail = rows.slice(-3).filter((r) => !r.adv.timedOut && !r.ctl.timedOut);
  summary.push({
    family: name,
    maxN: sizes.at(-1),
    timedOut: rows.some((r) => r.adv.timedOut),
    tailRatios: tail.map((r, i) => (i === 0 ? null : r.adv.perIteration / tail[i - 1].adv.perIteration)).filter(Boolean),
    tailAC: tail.map((r) => r.adv.perIteration / r.ctl.perIteration),
  });
}

console.log("\n== summary ==");
for (const s of summary) {
  const p = s.tailRatios.map((r) => Math.log2(r).toFixed(2)).join(", ");
  const ac = s.tailAC.map((r) => r.toFixed(2)).join(", ");
  console.log(
    `  ${s.family.padEnd(28)} maxN=${String(s.maxN).padStart(6)}  timeout=${s.timedOut ? "YES" : "no "}  tail p=[${p}]  tail a/c=[${ac}]`
  );
}
