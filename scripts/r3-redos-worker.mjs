// R3.2 -- execution worker for ReDoS probing.
//
// One case per PROCESS, because a synchronous regex that backtracks cannot be interrupted from the
// same process: the event loop never gets a turn, so `Promise.race` against a timer is useless as a
// watchdog. The parent spawns this file and kills it on timeout.
//
// Timing model. Process startup is comparable to the work for small inputs, so the parent cannot
// measure wall time across a spawn. Instead this worker runs the case REPEATEDLY until it has spent
// a target duration, and reports milliseconds PER ITERATION together with the iteration count. The
// parent records both, so a report cannot confuse "fast because the case is trivial" with "fast
// because the case never ran".
//
// Input arrives as JSON on argv[2]:
//   { kind: "find" | "redact", text, flags, options, targetMs, maxIterations }

import { findSensitiveSpans, RedactionContext, ForeignTokenRegistry } from "../worker.js";

const spec = JSON.parse(process.argv[2]);
const targetMs = spec.targetMs ?? 20;
const maxIterations = spec.maxIterations ?? 200000;

function buildOptions() {
  const options = { salt: "redos" };
  if (spec.options?.foreign) {
    const o = spec.options.foreign;
    options.foreignRegistry = new ForeignTokenRegistry([
      { name: o.name, pattern: new RegExp(o.source, o.flags) },
    ]);
  }
  return options;
}

async function once() {
  if (spec.kind === "find") {
    findSensitiveSpans(spec.text, spec.flags);
    return;
  }
  if (spec.kind === "redact") {
    const ctx = new RedactionContext(buildOptions());
    await ctx.redactText(spec.text, spec.flags);
    return;
  }
  throw new Error(`unknown kind: ${spec.kind}`);
}

// Warmup, then repeat until the target duration is reached. The loop measures its own elapsed time
// so a slow case stops after one iteration rather than overshooting badly.
for (let i = 0; i < 2; i++) await once();

let iterations = 0;
const started = process.hrtime.bigint();
let elapsedMs = 0;
while (iterations < maxIterations) {
  await once();
  iterations++;
  elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  if (elapsedMs >= targetMs) break;
}

const perIteration = elapsedMs / iterations;
process.stdout.write(JSON.stringify({
  ok: true,
  iterations,
  elapsedMs,
  perIteration,
  // A case that could not reach the target in maxIterations is still reported, but flagged, so the
  // parent can tell "genuinely fast" from "cheap loop bound".
  reachedTarget: elapsedMs >= targetMs,
}));
