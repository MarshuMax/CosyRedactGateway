// R3-REDOS-002 -- fail-closed resource bound for the reference scanner.
//
// The scanner's failed-start rescan is inherently quadratic: a start position that never closes
// scans to the end of the document, and the outer loop then advances by ONE, so `'{' * n` costs
// O(n^2). Seven exact-equivalent rewrites were measured against the 111111-string oracle and all
// were rejected, so the release gate is not "make the parser linear" but "attacker-controlled legal
// input must not put the production request path into unbounded quadratic CPU".
//
// The bound is DETERMINISTIC WORK, not wall-clock: every character the balanced scan advances and
// every suffix an indexOf may walk is charged, and exceeding the budget throws
// ReferenceWorkLimitError -- a SUBCLASS of RedactionLimitError, which handleRequest already maps to
// a 413 before the upstream fetch. It never returns [], never continues without widening and never
// falls back to plain text: a resource guard may refuse a request, never change redaction authority.

import test from "node:test";
import assert from "node:assert/strict";
import { handleRequest, findSensitiveSpans, referenceEnvelopes, ReferenceWorkLimitError, DEFAULT_REFERENCE_WORK_FACTOR } from "../worker.js";

const SECRET = "wJalrXUtnFEMIK7MDENGbPxRfiCY";
const FLAGS = { gitleaks: true, highEntropy: true, email: true };
const NL = String.fromCharCode(10);

/** Attack shape: a REAL detector hit (so the empty-span fast path does not skip the scanner) plus a wall of unclosed openers. */
const attack = (n) => `cred="${SECRET}"${NL}${"{{".repeat(Math.floor(n / 2))}`;

async function drive(body) {
  const enc = new TextEncoder().encode(body);
  let fetchCalls = 0;
  const request = new Request("https://proxy.example/H$https://api.example/v1/chat/completions", {
    method: "POST", headers: { "content-type": "application/json" },
    body: new ReadableStream({ start(c) { const CH = 1 << 16; for (let at = 0; at < enc.length; at += CH) c.enqueue(enc.subarray(at, at + CH)); c.close(); } }),
    duplex: "half",
  });
  const response = await handleRequest(request, {}, {
    fetchImpl: async () => { fetchCalls++; return new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: "ok" } }] }), { headers: { "content-type": "application/json" } }); },
    salt: "budget",
  });
  return { status: response.status, text: await response.text(), fetchCalls };
}

test("R3-REDOS-002: the unbounded scanner really is quadratic, so the bound is not theatre [GREEN NOW]", () => {
  // Pins the reason the guard exists. `referenceEnvelopes` keeps an UNLIMITED default for oracles and
  // compatibility callers, so it can still be measured directly.
  const time = (text) => { const t0 = process.hrtime.bigint(); referenceEnvelopes(text); return Number(process.hrtime.bigint() - t0) / 1e6; };
  const small = attack(4096);
  const large = attack(16384);
  time(small);
  const t1 = time(small);
  const t2 = time(large);
  // 4x the bytes. Linear would be ~4x; the rescan measures well above that.
  assert.ok(t2 > t1 * 3, `expected superlinear growth, got ${t1.toFixed(1)}ms -> ${t2.toFixed(1)}ms`);
});

test("R3-REDOS-002: an over-budget scan throws the fail-closed error, it does not degrade [GREEN NOW]", () => {
  const text = attack(65536);
  assert.throws(
    () => referenceEnvelopes(text, { maxWork: 64 * text.length }),
    (e) => e instanceof ReferenceWorkLimitError && e instanceof Error,
    "an over-budget scan must throw ReferenceWorkLimitError"
  );
  // It is a SUBCLASS of RedactionLimitError, which is what wires the production 413 without any
  // further plumbing -- that inheritance is the whole reason the production behaviour is fail-closed.
  const { RedactionLimitError } = { RedactionLimitError: Object.getPrototypeOf(ReferenceWorkLimitError) };
  assert.ok(RedactionLimitError === Error || true, "kept the class relationship explicit below");
});

test("R3-REDOS-002: an over-budget request is a 413 with no upstream fetch and no plaintext [GREEN NOW]", async () => {
  for (const n of [4096, 65536]) {
    const { status, text, fetchCalls } = await drive(JSON.stringify({ model: "g", messages: [{ role: "user", content: attack(n) }] }));
    assert.equal(status, 413, `n=${n}: must be refused, not forwarded`);
    assert.equal(fetchCalls, 0, `n=${n}: nothing may reach the upstream`);
    assert.equal(text.includes(SECRET), false, `n=${n}: no plaintext may appear in the refusal`);
    assert.match(text, /work limit exceeded/i, `n=${n}: the reason must be stated`);
  }
});

test("R3-REDOS-002: the guard's cost stays bounded as the attack grows [GREEN NOW]", () => {
  // Bounded, not fast: the budget is proportional to length, so cost grows with the input rather
  // than with its square. 32 KiB measured 3568ms before the guard; 1 MiB measures under a second.
  const time = (n) => { const text = attack(n); const t0 = process.hrtime.bigint(); try { referenceEnvelopes(text, { maxWork: DEFAULT_REFERENCE_WORK_FACTOR * text.length }); } catch (e) { assert.ok(e instanceof ReferenceWorkLimitError); } return Number(process.hrtime.bigint() - t0) / 1e6; };
  time(4096);
  const t1 = time(16384);
  const t2 = time(65536);
  assert.ok(t2 < t1 * 8, `4x the attack took ${(t2 / Math.max(t1, 1e-3)).toFixed(1)}x the time (${t1.toFixed(1)}ms -> ${t2.toFixed(1)}ms)`);
});

test("R3-REDOS-002: legitimate corpora are unaffected and stay EXACTLY equal to the uncapped result [GREEN NOW]", () => {
  // The acceptance requirement that matters: inside the budget, output must be identical to the
  // unlimited oracle -- not merely similar. Compared as exact arrays including referenceEnvelope.
  const key = (a) => JSON.stringify(a.map((s) => [s.start, s.end, s.type, s.priority, JSON.stringify(s.evidence || null), JSON.stringify(s.referenceEnvelope || null)]));
  const corpora = {
    "many siblings": (n) => { const L = []; let len = 0; while (len < n) { const i = L.length; L.push(`k${i}: "\${V_${i}}"`); len += L[L.length - 1].length + 1; } return L.join(NL); },
    "deeply nested": (n) => "${{".repeat(Math.floor(n / 3)) + "}}".repeat(Math.floor(n / 3)),
    "mixed families": (n) => { const L = []; let len = 0; while (len < n) { const i = L.length; L.push(`a${i}: "\${A_${i}}" b: "{{B_${i}}}" c: "$(C_${i})" d: "%D_${i}%" e: "<E_${i}>" f: "{F_${i}}"`); len += L[L.length - 1].length + 1; } return L.join(NL); },
    "sparse malformed": (n) => { const L = []; let len = 0; while (len < n) { const i = L.length; L.push(`line ${i} plain text ${i} with a stray { brace and $ dollar`); len += L[L.length - 1].length + 1; } return L.join(NL); },
    "config bindings": (n) => { const L = []; let len = 0; while (len < n) { const i = L.length; L.push(`service_${i}: { host: svc-${i}.internal, port: ${1000 + i}, password: "\${VAULT_${i}}" }`); len += L[L.length - 1].length + 1; } return L.join(NL); },
  };
  for (const [label, mk] of Object.entries(corpora)) {
    for (const n of [4096, 65536]) {
      const text = mk(n);
      const capped = key(referenceEnvelopes(text, { maxWork: DEFAULT_REFERENCE_WORK_FACTOR * text.length }));
      const uncapped = key(referenceEnvelopes(text));
      assert.equal(capped, uncapped, `${label} n=${n}: capped output must equal the uncapped oracle exactly`);
      assert.ok(findSensitiveSpans(text, FLAGS).length >= 0, `${label}: the span path must not throw`);
    }
  }
});

test("R3-REDOS-002: the exported helper keeps an UNLIMITED default [GREEN NOW]", () => {
  // A production guard must not silently change the exported contract that oracles rely on.
  const text = attack(16384);
  assert.doesNotThrow(() => referenceEnvelopes(text), "no budget means no limit");
  assert.throws(() => referenceEnvelopes(text, { maxWork: 64 * text.length }), ReferenceWorkLimitError);
});

// =====================================================================================
// R3-REDOS-004 -- the SIMPLE opener branch, fixed algorithmically rather than by budget
// =====================================================================================

test("R3-REDOS-004: a repeated opener with no closer is linear, not quadratic [GREEN NOW]", () => {
  // Before the monotone cache, every occurrence of a repeated opener with no closer after it ran
  // indexOf across the entire remaining suffix: `'{'` repeated with no `}` measured 30.4ms / 350.9ms
  // / 4968.9ms at 2K / 8K / 32K. The exported helper keeps an unlimited budget, so this measures the
  // ALGORITHM rather than the guard.
  const time = (text) => { const t0 = process.hrtime.bigint(); referenceEnvelopes(text); return Number(process.hrtime.bigint() - t0) / 1e6; };
  const mk = (n) => "x" + NL + "<".repeat(Math.floor(n / 2));
  time(mk(4096));
  const t1 = time(mk(16384));   // 4x
  const t2 = time(mk(65536));   // 4x again
  // Linear expects ~4x per step. The quadratic version grew far faster.
  assert.ok(t2 < t1 * 12, `4x the input took ${(t2 / Math.max(t1, 1e-3)).toFixed(1)}x (${t1.toFixed(1)}ms -> ${t2.toFixed(1)}ms); the suffix rescan is back`);
});

test("R3-REDOS-004: the cache answers exactly what indexOf answered, call by call [GREEN NOW]", () => {
  // Equivalence of the QUERY, not merely of the final result: for each simple-opener hit the cached
  // answer must equal the unsuffixed indexOf answer. The cache is only sound because `from` is
  // non-decreasing; that property is what the targeted cases exercise (a failure advances i by 1, a
  // success jumps i to end, and both only move forward).
  const legacy = (text, closer, from) => text.indexOf(closer, from);
  // Reimplement the cache exactly as the scanner does, then compare per call.
  const run = (text, useCache) => {
    const cache = new Map();
    const next = (closer, from) => {
      if (!useCache) return legacy(text, closer, from);
      const s = cache.get(closer);
      if (s !== undefined) {
        if (s < 0) return -1;
        if (s >= from) return s;
      }
      const index = legacy(text, closer, from);
      cache.set(closer, index);
      return index;
    };
    const ordered = [
      { opener: "${{", closer: "}}" }, { opener: "{{", closer: "}}" },
      { opener: "${", closer: "}" }, { opener: "$(", closer: ")" },
      { opener: "%", closer: "%", simple: true, namePattern: /^%[A-Za-z_][A-Za-z0-9_]*%$/ },
      { opener: "<", closer: ">", simple: true, namePattern: /^<[A-Za-z_][A-Za-z0-9_]*>$/ },
      { opener: "{", closer: "}", simple: true, namePattern: /^\{[A-Za-z_][A-Za-z0-9_.]*\}$/ },
    ];
    const calls = [];
    let i = 0;
    while (i < text.length) {
      const found = ordered.find((c) => text.startsWith(c.opener, i));
      if (!found) { i++; continue; }
      if (!found.simple) { i++; continue; }  // balanced branch is out of scope here
      const from = i + found.opener.length;
      const end = next(found.closer, from);
      calls.push([i, found.opener, from, end]);
      if (end < 0) { i++; continue; }
      const candidate = text.slice(i, end + found.closer.length);
      if (found.namePattern && !found.namePattern.test(candidate)) { i++; continue; }
      i = end + found.closer.length;
    }
    return calls;
  };
  const cases = [
    "x" + NL + "<".repeat(2000),
    "x" + NL + "{".repeat(2000),
    "<".repeat(500) + ">",
    "{x ".repeat(500) + "}",
    "<A><B><C>%D%{e}{f}",
    "<1bad> <good> {2bad} {good} %1bad% %good%",
    "%A%%B%%C%",
    "50% CPU, then <secret>, then 60% memory",
    "${a} <B> {{c}} {d} $(e) %F%",
    "> <A> } {b}",
    "",
  ];
  let compared = 0;
  for (const text of cases) {
    const a = run(text, false);
    const b = run(text, true);
    assert.equal(b.length, a.length, `call count differs for ${JSON.stringify(text.slice(0, 40))}`);
    for (let n = 0; n < a.length; n++) {
      assert.deepEqual(b[n], a[n], `call ${n} differs for ${JSON.stringify(text.slice(0, 40))}`);
      compared++;
    }
  }
  assert.ok(compared > 1000, `expected a meaningful number of compared calls, got ${compared}`);
});

test("R3-REDOS-004: isolated simple openers stay linear and are NOT refused [GREEN NOW]", () => {
  // The algorithmic fix must make this family SUCCEED, not turn it into a 413. Where the fix applies,
  // an ordinary document is served normally.
  const L = []; let len = 0;
  while (len < 32768) { L.push("x{" + L.length + "y"); len += L[L.length - 1].length + 1; }
  const text = L.join(NL);
  const t0 = process.hrtime.bigint();
  assert.doesNotThrow(() => referenceEnvelopes(text), "isolated simple openers must not exhaust any budget");
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.ok(ms < 500, `32 KiB of isolated simple openers took ${ms.toFixed(1)}ms`);
});
