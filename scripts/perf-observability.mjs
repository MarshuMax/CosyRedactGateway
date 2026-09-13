// Observability overhead and bounded-retention soak.
//
//   node scripts/perf-observability.mjs
//   node --expose-gc scripts/perf-observability.mjs     (adds post-GC measurements)
//
// This is a MEASUREMENT harness, not a CI gate. It reports; it does not pass or fail on timing or
// memory, because both depend on V8, GC timing and the machine. The only assertions are STRUCTURAL:
// the recent ring must never exceed its cap, and the fixed-key maps must not grow with request count.
//
// It answers two questions:
//   1. what does observability ON cost relative to OFF, on an identical workload?
//   2. once the recent ring is full, does anything keep growing with request count?
//
// HARNESS BOUNDEDNESS. The R3.6 soak's apparent memory leak turned out to be an unbounded
// `samples.push()` in the measurement harness. This file therefore retains a FIXED number of sample
// points (overwritten in place), never stores response bodies, never stores per-request telemetry
// records, and never stores per-request latencies.

import { handleRequest, __resetTelemetryStore, __telemetryStore, TELEMETRY_RECENT_DEFAULT } from '../worker.js';

const SECRET = 'wJalrXUtnFEMIK7MDENGbPxRfiCY';
const BODY = JSON.stringify({ model: 'g', messages: [{ role: 'user', content: `PW=${SECRET} mail a@b.com` }] });
const UPSTREAM = JSON.stringify({ choices: [{ message: { role: 'assistant', content: 'ok' } }] });
const UPSTREAM_HEADERS = { 'content-type': 'application/json' };

const HAS_GC = typeof global.gc === 'function';
const MiB = (n) => n / 1048576;
const mem = () => {
  const m = process.memoryUsage();
  return { rss: m.rss, heap: m.heapUsed, ext: m.external, ab: m.arrayBuffers ?? 0 };
};
const gcNow = () => { if (HAS_GC) { global.gc(); global.gc(); } };
const snapshot = () => {
  gcNow();
  const m = mem();
  return { ...m, postGcHeap: HAS_GC ? m.heap : null, postGcRss: HAS_GC ? m.rss : null };
};

/** One full round trip. Nothing is retained: no body kept, no latency recorded. */
async function oneRequest(env) {
  const res = await handleRequest(
    new Request('https://proxy.example/H$https://api.example/v1/chat/completions', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: BODY,
    }),
    env,
    { salt: 'perf', fetchImpl: async () => new Response(UPSTREAM, { headers: UPSTREAM_HEADERS }) });
  await res.text();
}

/** Fixed-size sampled buffer: overwrites in place, never grows. */
class FixedSamples {
  constructor(cap = 40) { this.cap = cap; this.buf = new Array(cap).fill(null); this.n = 0; this.i = 0; }
  push(v) { this.buf[this.i] = v; this.i = (this.i + 1) % this.cap; if (this.n < this.cap) this.n++; }
  get length() { return this.n; }
  inOrder() { const start = this.n < this.cap ? 0 : this.i; const out = []; for (let k = 0; k < this.n; k++) out.push(this.buf[(start + k) % this.cap]); return out; }
}

async function runWorkload({ label, env, iterations }) {
  __resetTelemetryStore();
  const gcStart = snapshot();
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) await oneRequest(env);
  const totalMs = Number(process.hrtime.bigint() - t0) / 1e6;
  const gcEnd = snapshot();
  return {
    label, iterations, totalMs,
    reqPerSec: iterations / (totalMs / 1000),
    msPerReq: totalMs / iterations,
    start: gcStart, end: gcEnd,
  };
}

function reportWorkload(r) {
  console.log(`  requests      = ${r.iterations}`);
  console.log(`  total_ms      = ${r.totalMs.toFixed(1)}`);
  console.log(`  req/s         = ${r.reqPerSec.toFixed(0)}`);
  console.log(`  ms/req        = ${r.msPerReq.toFixed(3)}`);
  console.log(`  rss           = ${MiB(r.end.rss).toFixed(1)} MiB`);
  console.log(`  heapUsed      = ${MiB(r.end.heap).toFixed(1)} MiB`);
  console.log(`  external      = ${MiB(r.end.ext).toFixed(1)} MiB`);
  console.log(`  arrayBuffers  = ${MiB(r.end.ab).toFixed(1)} MiB`);
  if (HAS_GC) console.log(`  post-GC heap  = ${MiB(r.end.postGcHeap).toFixed(1)} MiB   post-GC rss = ${MiB(r.end.postGcRss).toFixed(1)} MiB`);
}

// =====================================================================================
// 3 + 4: bounded-retention soak, with the post-cap phase separated from start-up
// =====================================================================================

async function soak({ cap, iterations }) {
  __resetTelemetryStore();
  const env = { REDACT_OBSERVABILITY: '1', REDACT_OBSERVABILITY_BUFFER: String(cap) };
  // Fixed sample points, overwritten in place. Not one sample per request.
  const POINTS = 40;
  const samples = new FixedSamples(POINTS);
  const every = Math.max(1, Math.floor(iterations / POINTS));

  const warmup = Math.min(200, Math.floor(iterations / 10));
  for (let i = 0; i < warmup; i++) await oneRequest(env);

  let phaseB = null;   // around the moment the ring fills
  let phaseC = null;   // N >> cap
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    await oneRequest(env);
    const done = i + 1;
    // B: the first point at or after the ring is full. C: the final point.
    if (phaseB === null && done >= cap) phaseB = { done, ...snapshot() };
    if (done % every === 0 || done === iterations) samples.push({ done, ...snapshot() });
  }
  const totalMs = Number(process.hrtime.bigint() - t0) / 1e6;
  phaseC = { done: iterations, ...snapshot() };

  const store = __telemetryStore();
  const report = store.retentionReport();

  return { cap, iterations, warmup, totalMs, samples: samples.inOrder(), phaseB, phaseC, report, store };
}

// =====================================================================================
// main
// =====================================================================================

const ITER = Number(process.env.PERF_REQUESTS || 3000);
const SOAK_N = Number(process.env.PERF_SOAK_REQUESTS || 10000);
const SOAK_CAP = Number(process.env.PERF_SOAK_CAP || 100);

console.log(`Observability overhead and bounded-retention soak`);
console.log(`node ${process.version}  --expose-gc ${HAS_GC ? 'present' : 'ABSENT (post-GC measurement: unavailable)'}`);
console.log(`iterations=${ITER}  soak_requests=${SOAK_N}  soak_cap=${SOAK_CAP}`);
console.log('');

console.log('== Observability OFF ==');
const off = await runWorkload({ label: 'off', env: {}, iterations: ITER });
reportWorkload(off);
console.log('');

console.log('== Observability ON ==');
const on = await runWorkload({ label: 'on', env: { REDACT_OBSERVABILITY: '1' }, iterations: ITER });
reportWorkload(on);
console.log('');

console.log('== Overhead (ON relative to OFF) ==');
console.log(`  throughput_ratio = ${(on.reqPerSec / off.reqPerSec).toFixed(4)}   (>1 means ON was faster)`);
console.log(`  latency_ratio    = ${(on.msPerReq / off.msPerReq).toFixed(4)}   (>1 means ON was slower)`);
console.log(`  latency_delta    = ${(on.msPerReq - off.msPerReq).toFixed(4)} ms/req`);
console.log(`  rss_delta        = ${MiB(on.end.rss - off.end.rss).toFixed(2)} MiB`);
console.log(`  heap_delta       = ${MiB(on.end.heap - off.end.heap).toFixed(2)} MiB`);
console.log(`  external_delta   = ${MiB(on.end.ext - off.end.ext).toFixed(2)} MiB`);
console.log(`  arrayBuffers_delta = ${MiB(on.end.ab - off.end.ab).toFixed(2)} MiB`);
console.log('  (report only; no pass/fail threshold, since these depend on V8 and the machine)');
console.log('');

console.log('== Bounded retention soak ==');
const s = await soak({ cap: SOAK_CAP, iterations: SOAK_N });
console.log(`  requests = ${s.iterations}  (warmup ${s.warmup})  elapsed = ${s.totalMs.toFixed(0)} ms`);
console.log(`  cap      = ${s.report.recent.cap}`);
console.log(`  recent.length = ${s.report.recent.length}`);
console.log(`  within        = ${s.report.recent.within}`);
console.log(`  fixed_key_maps:`);
for (const [k, v] of Object.entries(s.report.fixed_key_maps)) console.log(`    ${k.padEnd(22)} = ${v}`);
console.log(`  diagnostics: dropped_enum_values_total=${s.report.diagnostics.dropped_enum_values_total} records_dropped_invalid_total=${s.report.diagnostics.records_dropped_invalid_total}`);
console.log(`  latency.count = ${s.report.latency.count}  max_ms = ${s.report.latency.max_ms.toFixed(2)}`);
console.log('');

console.log('== Post-cap behaviour (the part that matters) ==');
console.log(`  A cold start   : rss=${MiB(s.samples[0]?.rss ?? 0).toFixed(1)} MiB  heap=${MiB(s.samples[0]?.heap ?? 0).toFixed(1)} MiB`);
console.log(`  B ring full    : at request ${s.phaseB?.done ?? 'n/a'}  rss=${MiB(s.phaseB?.rss ?? 0).toFixed(1)} MiB  heap=${MiB(s.phaseB?.heap ?? 0).toFixed(1)} MiB`);
console.log(`  C N>>cap       : at request ${s.phaseC?.done ?? 'n/a'}  rss=${MiB(s.phaseC?.rss ?? 0).toFixed(1)} MiB  heap=${MiB(s.phaseC?.heap ?? 0).toFixed(1)} MiB`);
if (s.phaseB && s.phaseC) {
  const dReq = s.phaseC.done - s.phaseB.done;
  const dRss = MiB(s.phaseC.rss - s.phaseB.rss);
  const dHeap = MiB(s.phaseC.heap - s.phaseB.heap);
  console.log(`  B -> C delta   : rss=${dRss >= 0 ? '+' : ''}${dRss.toFixed(2)} MiB  heap=${dHeap >= 0 ? '+' : ''}${dHeap.toFixed(2)} MiB  over ${dReq} requests`);
  if (dReq > 0) console.log(`  per 1k requests: rss=${(dRss / dReq * 1000).toFixed(3)} MiB  heap=${(dHeap / dReq * 1000).toFixed(3)} MiB`);
  if (HAS_GC) {
    console.log(`  post-GC heap   : B=${MiB(s.phaseB.postGcHeap).toFixed(1)} -> C=${MiB(s.phaseC.postGcHeap).toFixed(1)} MiB  (delta ${(MiB(s.phaseC.postGcHeap - s.phaseB.postGcHeap)).toFixed(2)} MiB)`);
    console.log(`  post-GC rss    : B=${MiB(s.phaseB.postGcRss).toFixed(1)} -> C=${MiB(s.phaseC.postGcRss).toFixed(1)} MiB  (delta ${(MiB(s.phaseC.postGcRss - s.phaseB.postGcRss)).toFixed(2)} MiB)`);
  } else {
    console.log('  post-GC measurement: unavailable (run with --expose-gc)');
  }
}
console.log('');

// ---------------------------------------------------------------------------------------------
// The only assertions in this file: STRUCTURAL, not temporal.
// ---------------------------------------------------------------------------------------------
const failures = [];
if (s.report.recent.length !== s.report.recent.cap) {
  failures.push(`recent.length is ${s.report.recent.length}, expected exactly cap ${s.report.recent.cap}`);
}
if (s.report.recent.within !== true) failures.push('recent.within is not true');
// A fixed-key map must be bounded by the enums it mirrors, not by request count. The soak uses one
// request shape, so every map should hold a handful of keys; 50 is far above any legitimate value and
// far below what unbounded growth over 10000 requests would produce.
const mapSizes = Object.entries(s.report.fixed_key_maps);
const oversized = mapSizes.filter(([, v]) => v > 50);
if (oversized.length) failures.push(`fixed-key maps grew: ${JSON.stringify(Object.fromEntries(oversized))}`);

console.log('== Structural assertions ==');
if (failures.length) {
  for (const f of failures) console.log(`  FAIL ${f}`);
  process.exitCode = 1;
} else {
  console.log(`  ok  recent.length === cap (${s.report.recent.length})`);
  console.log(`  ok  recent.within === true`);
  console.log(`  ok  every fixed-key map stayed bounded (max ${Math.max(...mapSizes.map(([, v]) => v))})`);
}
void TELEMETRY_RECENT_DEFAULT;
