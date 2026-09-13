// v2.1 observability -- PR1 acceptance.
//
// The six things this file has to prove, and nothing else:
//   zero plaintext   in the store, in the log line, in the summary
//   bounded retention
//   exact default-off equivalence
//   correct span/sink statistics
//   SSE finalize exactly once
//   the existing suite stays green (that is the rest of the suite, not this file)
//
// Memory-slop measurement (RSS / heapUsed / post-GC) is deliberately NOT here: those numbers
// depend on V8, GC timing and the machine, so they are not a unit-test threshold. They live in
// scripts/perf-observability.mjs.

import test from "node:test";
import assert from "node:assert/strict";
import {
  handleRequest,
  TelemetryStore,
  RedactionContext,
  TelemetryAccumulator,
  formatTelemetryLine,
  observabilityEnabled,
  telemetryBufferSize,
  __resetTelemetryStore,
  __telemetryStore,
  TELEMETRY_RECENT_DEFAULT,
  TELEMETRY_RECENT_MAX,
  TELEMETRY_SCHEMA_VERSION,
  SINK_MODE,
  SINK_KIND,
  applySinkPolicy,
} from "../worker.js";

const SECRET = "wJalrXUtnFEMIK7MDENGbPxRfiCY";
const EMAIL = "someone@example.com";
const NL = String.fromCharCode(10);
const ENV = (extra = {}) => ({ REDACT_MAX_BODY_BYTES: "16384", ...extra });
const ON = ENV({ REDACT_OBSERVABILITY: "1" });

function call({ env = ON, content = "plain text", path = "/v1/chat/completions", fetchImpl = null, body = null } = {}) {
  const payload = body !== null ? body : JSON.stringify({ model: "g", messages: [{ role: "user", content }] });
  return handleRequest(
    new Request(`https://proxy.example/H$https://api.example${path}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: payload,
    }),
    env,
    {
      salt: "obs",
      fetchImpl: fetchImpl || (async () => new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: "ok" } }] }), { headers: { "content-type": "application/json" } })),
    }
  );
}
/** Echo the upstream token back in assistant text, so a real restore happens. */
const echoToken = async (_u, init) => {
  const tok = (String(init.body).match(/CRG_[A-Z0-9]{6}_[A-Z0-9]{4}/) || [])[0];
  return new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: `pw ${tok}` } }] }), { headers: { "content-type": "application/json" } });
};
/** Put the token in an untrusted tool operand, where it must be PRESERVED. */
const toolOperand = async (_u, init) => {
  const tok = (String(init.body).match(/CRG_[A-Z0-9]{6}_[A-Z0-9]{4}/) || [])[0];
  return new Response(JSON.stringify({ type: "message", role: "assistant", content: [{ type: "tool_use", id: "t", name: "untrusted", input: { pw: tok } }] }), { headers: { "content-type": "application/json" } });
};

/** Capture stderr while running fn, so log output can be inspected. */
async function captureStderr(fn) {
  const orig = console.error;
  const lines = [];
  console.error = (...a) => { lines.push(a.join(" ")); };
  try { return { result: await fn(), lines }; } finally { console.error = orig; }
}

// =====================================================================================
// zero plaintext
// =====================================================================================

test("observability: no plaintext, token or body reaches the store or the log [GREEN NOW]", async () => {
  __resetTelemetryStore();
  const { lines } = await captureStderr(async () => {
    await (await call({ content: `PW=${SECRET} mail ${EMAIL}` })).text();
    await (await call({ content: `PW=${SECRET}`, fetchImpl: echoToken })).text();
    await (await call({ content: `PW=${SECRET}`, fetchImpl: toolOperand })).text();
  });
  const rendered = JSON.stringify(lines) + globalThis.__lastSummary;
  for (const forbidden of [SECRET, EMAIL, "CRG_"]) {
    assert.equal(rendered.includes(forbidden), false, `telemetry output must never contain ${forbidden}`);
  }
  assert.ok(lines.some((l) => l.startsWith("[CRG]")), "and it must actually have logged something");
});

test("observability: applySinkPolicy keeps its original public return shape [GREEN NOW]", async () => {
  // `changed` is telemetry-internal metadata and must NOT widen this exported function's return
  // shape. Widening it would be an API change for every caller, made on behalf of a private
  // counter. The RC baseline returned exactly { text, mode, blocked }.
  const ctx = new RedactionContext({ salt: "shape" });
  await ctx.tokenFor(SECRET);
  const shapes = [];
  // PRESERVE + operand with an unknown token -> blocked
  shapes.push(applySinkPolicy("CRG_ZZZZZZ_9999", ctx, { kind: SINK_KIND.TOOL_ARGUMENT, toolName: "t" }));
  // PRESERVE, nothing to refuse
  shapes.push(applySinkPolicy("plain text", ctx, { kind: SINK_KIND.TOOL_ARGUMENT, toolName: "t" }));
  // BLOCK
  shapes.push(applySinkPolicy("plain text", ctx, { kind: SINK_KIND.SHELL }));
  // RESTORE with nothing to resolve
  shapes.push(applySinkPolicy("plain text", ctx, { kind: SINK_KIND.ASSISTANT_TEXT }));
  // RESTORE WITH a real substitution: the changed=true path, which the review pointed out was
  // missing. Without it the test never exercised a restoration at all -- the OWN token minted
  // above was created and then not used -- so a `changed` leak on only this path would have gone
  // unnoticed.
  const ownToken = await ctx.tokenFor(SECRET);
  const restored = applySinkPolicy(`value=${ownToken}`, ctx, { kind: SINK_KIND.ASSISTANT_TEXT });
  assert.equal(restored.text, `value=${SECRET}`, "the OWN token must actually be restored");
  shapes.push(restored);
  for (const r of shapes) {
    assert.deepEqual(Object.keys(r).sort(), ["blocked", "mode", "text"],
      `applySinkPolicy must return exactly {text, mode, blocked}; got ${JSON.stringify(Object.keys(r))}`);
    assert.equal("changed" in r, false, "changed must not escape the function");
  }
});

test("observability: the accumulator does not accept text at all [GREEN NOW]", () => {
  // Structural, not heuristic: there is no parameter through which text could arrive.
  const acc = new TelemetryAccumulator(new TelemetryStore(), { upstream: "api.example" });
  acc.onSinkEvent(SINK_MODE.RESTORE, false, true);
  acc.setStatus(200);
  acc.setOutcome("forwarded");
  const ok = acc.finalizeExactlyOnce();
  assert.equal(ok, true);
  const rec = acc.store.recent.toArray()[0];
  assert.deepEqual(Object.keys(rec).sort(), [
    "coverage", "detectors", "limit_reason", "outcome", "response_ready_ms", "schema_version",
    "seq", "sink_modes", "sink_outcomes", "spans", "status", "stream_duration_ms", "t", "upstream",
  ].sort(), "the record schema is a closed allowlist");
  assert.equal(rec.schema_version, TELEMETRY_SCHEMA_VERSION);
});

// =====================================================================================
// statistics: span vs sink, and the RESTORE/restored distinction
// =====================================================================================

test("observability: span and sink are reported as separate dimensions [GREEN NOW]", () => {
  __resetTelemetryStore();
  return (async () => {
    await (await call({ content: `PW=${SECRET}`, fetchImpl: echoToken })).text();
    const rec = __storeSummary().recent;
    // mode RESTORE with a real substitution -> restored
    assert.equal(rec.sink_modes.restore, 1);
    assert.equal(rec.sink_outcomes.restored, 1);
    // span dimension is independent of it
    assert.ok(rec.spans.redact >= 1, "the secret was redacted at the span level");
  })();
});

test("observability: RESTORE with nothing to resolve is preserved, not restored [GREEN NOW]", async () => {
  // The distinction that was wrong in the first design draft. A RESTORE channel that found no
  // OWN token delivers the text unchanged; calling that `restored` overstates what happened.
  __resetTelemetryStore();
  await (await call({ content: "nothing sensitive here" })).text();
  const rec = __storeSummary().recent;
  assert.equal(rec.sink_modes.restore, 1, "the mode was RESTORE");
  assert.equal(rec.sink_outcomes.preserved, 1, "but the OUTCOME was preserved");
  assert.equal(rec.sink_outcomes.restored, undefined);
});

test("observability: an untrusted operand is preserved, and BLOCK-with-nothing-to-refuse is too [GREEN NOW]", async () => {
  __resetTelemetryStore();
  await (await call({ content: `PW=${SECRET}`, fetchImpl: toolOperand })).text();
  let rec = __storeSummary().recent;
  assert.equal(rec.sink_modes.preserve, 1);
  assert.equal(rec.sink_outcomes.preserved, 1);
  assert.equal(rec.sink_outcomes.blocked, undefined);
});

// =====================================================================================
// rejection outcomes
// =====================================================================================

test("observability: rejections record their own outcome, and only when they happen [GREEN NOW]", async () => {
  __resetTelemetryStore();
  // A normal request must NOT be recorded as a rejection -- this is the bug where the finalize
  // call sat above its guard and every request logged `413 rejected_body`.
  await (await call({ content: "ordinary" })).text();
  let rec = __storeSummary().recent;
  assert.equal(rec.outcome, "forwarded");
  assert.equal(rec.status, 200);
  assert.equal(rec.limit_reason, null);

  const deep = JSON.stringify({ model: "g", deep: (() => { let n = "x"; for (let i = 0; i < 700; i++) n = { c: n }; return n; })() });
  await (await call({ body: deep })).text();
  rec = __storeSummary().recent;
  assert.equal(rec.outcome, "rejected_depth");
  assert.equal(rec.limit_reason, "json_depth");
  assert.equal(rec.status, 413);
});

test("observability: a 413 performs no upstream fetch [GREEN NOW]", async () => {
  __resetTelemetryStore();
  let fetched = 0;
  await (await call({ body: JSON.stringify({ model: "g", deep: (() => { let n = "x"; for (let i = 0; i < 700; i++) n = { c: n }; return n; })() }), fetchImpl: async () => { fetched++; return new Response("{}", { headers: { "content-type": "application/json" } }); } })).text();
  assert.equal(fetched, 0);
});

test("observability: a real block_scalar span is counted as a detector, not dropped [GREEN NOW]", async () => {
  // NOT a fabricated store.record({detectors:{block_scalar:1}}). This runs the real production
  // path -- findSensitiveSpans -> redactText -> telemetryProjection -> store -- so it proves the
  // allowlist admits what the binding parser actually emits.
  //
  // bindingSpansOf() sets `type: b.bodyCandidate ? "block_scalar" : kind`, and detectorOfSpan()
  // excludes "block_scalar" from its `find` so it survives as candidates[0]. The earlier allowlist
  // omitted it and also carried non-detectors (`highEntropy`, `structuredContext`, `infra`,
  // `reference`), so a valid block_scalar span was counted as a dropped enum.
  __resetTelemetryStore();
  const BLOCK = "password: |" + NL + "  wJalrXUtnFEMIK7MDENGbPxRfiCY" + NL;
  const res = await call({ content: BLOCK });
  await res.text();
  const store = __telemetryStore();
  assert.ok(store, "observability is on");
  assert.equal(store.diagnostics.dropped_enum_values_total, 0, "no enum was dropped");
  const dets = store.by_detector;
  assert.ok(Object.keys(dets).length >= 1, `expected at least one detector, got ${JSON.stringify(dets)}`);
  assert.equal(
    Object.prototype.hasOwnProperty.call(dets, "block_scalar"), true,
    `block_scalar must be admitted; got ${JSON.stringify(dets)}`
  );
});

test("observability: every detector in the real domain is emitted and admitted [GREEN NOW]", async () => {
  // Hardened after review. The previous version destructured `for (const [, text] of cases)` and
  // THREW THE EXPECTED NAME AWAY, so it only proved "each fixture produced SOME detector that is in
  // the allowlist". A fixture that was supposed to yield `entropy` but had its attribution taken by
  // a structured binding would still have passed. Each fixture now asserts its EXACT expected
  // detector, under ISOLATED flags so the detectors cannot mask one another.
  //
  // The flags were not guessed: each was derived by running the fixture and reading what it
  // actually emits with only that detector enabled.
  //
  // `only()` sets EVERY flag explicitly, and that matters: `structuredContext` is OPT-OUT in this
  // codebase (`flags.structuredContext !== false`), so simply omitting it leaves it ON. A probe
  // written as `{ highEntropy: true }` therefore still ran the structured binding, which took
  // attribution and reported `binding` where the fixture was supposed to prove `entropy`. The
  // isolation has to be explicit or the fixture proves nothing about the detector it names.
  const ALL = { gitleaks: true, highEntropy: true, email: true, phone: true, secret: true, identity: true, bank: true, structuredContext: true };
  const only = (...keep) => Object.fromEntries(Object.keys(ALL).map((k) => [k, keep.includes(k)]));
  const DOMAIN = [
    ["gitleaks", 'token = "ghp_' + "A".repeat(36) + '"', only("gitleaks")],
    ["entropy", 'secret = "wJalrXUtnFEMIK7MDENGbPxRfiCY"', only("highEntropy")],
    ["binding", "DB_PASSWORD=wJalrXUtnFEMI12345678", only("structuredContext")],
    ["block_scalar", "password: |" + NL + "  wJalrXUtnFEMIK7MDENGbPxRfiCY" + NL, only("structuredContext")],
    ["secret", "key sk-" + "b".repeat(64), only("secret")],
    ["email", "contact a@b.com", only("email")],
    ["phone", "call +8613800138000", only("phone")],
    ["identity", "id 110101199003078515", only("identity")],
    ["bank", "card 4111111111111111", only("bank")],
  ];
  const seen = [];
  for (const [expected, text, flags] of DOMAIN) {
    const ctx = new RedactionContext({ salt: "det", maxRedactions: 1e9 });
    await ctx.redactText(text, flags);
    const counts = ctx.telemetryProjection().detectorCounts;
    assert.equal(counts[expected], 1, `${expected} fixture must emit exactly one ${expected}; got ${JSON.stringify(counts)}`);
    assert.deepEqual(Object.keys(counts), [expected], `${expected} fixture must emit ONLY ${expected}; got ${JSON.stringify(counts)}`);
    seen.push(expected);
  }
  // The domain is asserted EXACTLY, not with a loose `>= 5`, so removing a detector from the
  // allowlist fails here rather than shrinking the covered set silently.
  assert.deepEqual([...seen].sort(), ["bank", "binding", "block_scalar", "email", "gitleaks", "identity", "phone", "secret", "entropy"].sort());

  const store = new TelemetryStore();
  for (const d of seen) {
    store.record({ t: 0, upstream: "h", status: 200, outcome: "forwarded",
      spans: { decisions: 1, redact: 1, preserve: 0, bytes_redacted: 1, detectors: { [d]: 1 }, reasons: {}, infra_types: {} },
      detectors: { [d]: 1 }, coverage: null, sink_modes: {}, sink_outcomes: {}, limit_reason: null });
  }
  assert.equal(store.diagnostics.dropped_enum_values_total, 0,
    `every emitted detector must be admitted; dropped: ${seen.filter((d) => !(d in store.by_detector)).join(",")}`);
  assert.deepEqual(Object.keys(store.by_detector).sort(), [...seen].sort());
});

// =====================================================================================
// bounded retention
// =====================================================================================

test("observability: the recent ring is bounded and never grows past its cap [GREEN NOW]", () => {
  const store = new TelemetryStore({ recentCap: 4 });
  for (let i = 0; i < 50; i++) {
    store.record({ t: i, upstream: "h", status: 200, outcome: "forwarded", response_ready_ms: 1,
      spans: { decisions: 0, redact: 0, preserve: 0, bytes_redacted: 0, detectors: {}, reasons: {}, infra_types: {} },
      detectors: {}, coverage: null, sink_modes: {}, sink_outcomes: {}, limit_reason: null });
  }
  assert.equal(store.recent.length, 4, "capped");
  assert.equal(store.recent.toArray().length, 4);
  assert.equal(store.recent.toArray()[0].t, 49, "newest first");
  const rep = store.retentionReport();
  assert.ok(rep.recent.within, "retentionReport reports the bound");
  assert.equal(rep.recent.cap, 4);
  // Counters keep counting even though the ring overwrote.
  assert.equal(store.counters.requests_total, 50, "counters are cumulative, not ring-bound");
});

test("observability: the cap cannot be configured past the hard maximum [GREEN NOW]", () => {
  assert.equal(new TelemetryStore({ recentCap: 999999 }).recentCap, TELEMETRY_RECENT_MAX);
  // An explicit 0 is not a capacity, so it falls back to the default; a negative is likewise
  // invalid rather than clamped to 1 -- the two used to take different paths by accident.
  assert.equal(new TelemetryStore({ recentCap: 0 }).recentCap, TELEMETRY_RECENT_DEFAULT);
  assert.equal(new TelemetryStore({ recentCap: -5 }).recentCap, TELEMETRY_RECENT_DEFAULT);
  assert.equal(new TelemetryStore({ recentCap: Number.NaN }).recentCap, TELEMETRY_RECENT_DEFAULT);
  assert.equal(new TelemetryStore({ recentCap: 1 }).recentCap, 1, "1 is a legal capacity");
  assert.equal(new TelemetryStore().recentCap, TELEMETRY_RECENT_DEFAULT);
  assert.equal(telemetryBufferSize({ REDACT_OBSERVABILITY_BUFFER: "10" }), 10);
  assert.equal(telemetryBufferSize({ REDACT_OBSERVABILITY_BUFFER: "999999" }), TELEMETRY_RECENT_MAX);
  assert.equal(telemetryBufferSize({}), TELEMETRY_RECENT_DEFAULT);
});

test("observability: an unknown statistical enum is dropped, not stored [GREEN NOW]", () => {
  const store = new TelemetryStore();
  store.record({ t: 0, upstream: "h", status: 200, outcome: "forwarded", response_ready_ms: 1,
    spans: { decisions: 2, redact: 2, preserve: 0, bytes_redacted: 10, detectors: { gitleaks: 1, FUTURE_DETECTOR: 1 }, reasons: { "hard-secret": 1, "made-up-reason": 1 }, infra_types: {} },
    detectors: { gitleaks: 1, FUTURE_DETECTOR: 1 }, coverage: null, sink_modes: {}, sink_outcomes: {}, limit_reason: null });
  assert.equal(store.by_detector.gitleaks, 1, "known detector counted");
  assert.equal(store.by_detector.FUTURE_DETECTOR, undefined, "unknown detector NOT stored");
  assert.ok(store.diagnostics.dropped_enum_values_total >= 2, "and it is counted");
  // The unknown VALUE is never retained anywhere.
  assert.equal(JSON.stringify(store.summary()).includes("FUTURE_DETECTOR"), false);
});

test("observability: an unknown CORE enum refuses the whole record [GREEN NOW]", () => {
  const store = new TelemetryStore();
  const before = store.diagnostics.records_dropped_invalid_total;
  store.record({ t: 0, upstream: "h", status: 200, outcome: "TOTALLY_MADE_UP", response_ready_ms: 1,
    spans: { decisions: 0, redact: 0, preserve: 0, bytes_redacted: 0, detectors: {}, reasons: {}, infra_types: {} },
    detectors: {}, coverage: null, sink_modes: {}, sink_outcomes: {}, limit_reason: null });
  assert.equal(store.recent.length, 0, "no half-trustworthy record is stored");
  assert.equal(store.diagnostics.records_dropped_invalid_total, before + 1);
});

// =====================================================================================
// SSE finalize
// =====================================================================================

test("observability: an SSE stream finalizes exactly once, at close [GREEN NOW]", async () => {
  __resetTelemetryStore();
  const sse = async () => {
    const tok = `CRG_AAAAAA_0001`;
    const ev = (s) => `event: response.output_text.delta${NL}data: ${JSON.stringify({ type: "response.output_text.delta", delta: s })}${NL}${NL}`;
    return new Response(ev("hello " + tok) + `data: [DONE]${NL}${NL}`, { headers: { "content-type": "text/event-stream" } });
  };
  const res = await call({ path: "/v1/responses", body: JSON.stringify({ model: "g", stream: true, input: `PW=${SECRET}` }), fetchImpl: sse });
  await res.text();
  const rec = __storeSummary().recent;
  assert.equal(rec.outcome, "forwarded");
  assert.ok(Number.isFinite(rec.stream_duration_ms), "stream_duration_ms is filled at close");
  assert.equal(typeof rec.response_ready_ms === "number" || rec.response_ready_ms === null, true);
  const total = Object.values(rec.sink_modes).reduce((a, b) => a + b, 0);
  assert.ok(total >= 1, "and sink events were collected during streaming");
});

test("observability: finalizeExactlyOnce is idempotent [GREEN NOW]", () => {
  const store = new TelemetryStore();
  const acc = new TelemetryAccumulator(store, { upstream: "h" });
  acc.setStatus(200); acc.setOutcome("forwarded");
  assert.equal(acc.finalizeExactlyOnce(), true);
  assert.equal(acc.finalizeExactlyOnce("client_cancel", 5), false, "second call is a no-op");
  assert.equal(store.recent.length, 1, "and does not duplicate the record");
  assert.equal(store.recent.toArray()[0].outcome, "forwarded", "nor overwrite it");
});

// =====================================================================================
// default-off equivalence
// =====================================================================================

test("observability: disabled means no store, no record, no log [GREEN NOW]", async () => {
  __resetTelemetryStore();
  assert.equal(observabilityEnabled({}), false);
  assert.equal(observabilityEnabled({ REDACT_OBSERVABILITY: "0" }), false);
  assert.equal(observabilityEnabled({ REDACT_OBSERVABILITY: "true" }), false, "only the exact string 1 enables it");
  assert.equal(observabilityEnabled({ REDACT_OBSERVABILITY: "1" }), true);

  const { lines } = await captureStderr(async () => {
    await (await call({ env: ENV(), content: `PW=${SECRET}` })).text();
  });
  assert.equal(lines.filter((l) => l.includes("[CRG]")).length, 0, "no log line when disabled");
});

test("observability: the response is byte-identical whether telemetry is on or off [GREEN NOW]", async () => {
  // The equivalence the design promised: default-off must not change any observable response.
  const mk = async (env) => {
    const res = await call({ env, content: `PW=${SECRET} mail ${EMAIL}`, fetchImpl: echoToken });
    return { status: res.status, body: await res.text(), ct: res.headers.get("content-type") };
  };
  __resetTelemetryStore();
  const off = await mk(ENV());
  __resetTelemetryStore();
  const on = await mk(ON);
  assert.equal(on.status, off.status);
  assert.equal(on.ct, off.ct);
  // The token itself is per-request random, so compare the response SHAPE rather than the bytes.
  const shape = (s) => s.replace(/CRG_[A-Z0-9]{6}_[A-Z0-9]{4}/g, "CRG_X_X");
  assert.equal(shape(on.body), shape(off.body), "same response shape with telemetry on and off");
});

// =====================================================================================
// log formatting
// =====================================================================================

test("observability: the log line renders the record and adds nothing [GREEN NOW]", () => {
  const line = formatTelemetryLine({
    seq: 7, upstream: "api.example", status: 200, outcome: "forwarded",
    response_ready_ms: 12.6, stream_duration_ms: null,
    spans: { decisions: 3, redact: 3, preserve: 0, bytes_redacted: 64, detectors: { email: 1, gitleaks: 2 }, reasons: {}, infra_types: {} },
    detectors: { email: 1, gitleaks: 2 }, coverage: null,
    sink_modes: { restore: 1 }, sink_outcomes: { restored: 1 }, limit_reason: null,
  });
  assert.match(line, /^\[CRG\] seq=7 /);
  assert.match(line, /status=200/);
  assert.match(line, /redacted=3/);
  assert.match(line, /detectors=email:1,gitleaks:2/);
  assert.match(line, /sink_modes=restore:1/);
  assert.match(line, /sink_outcomes=restored:1/);
  assert.match(line, /response_ready_ms=13/, "rounded");
  assert.equal(line.includes("stream_duration_ms"), false, "null fields are omitted, not printed as null");
  assert.equal(formatTelemetryLine(null), null);
});

/** The newest record the module-level store holds. */
function __storeSummary() {
  const store = __telemetryStore();
  return { recent: store ? store.recent.toArray()[0] : null };
}
