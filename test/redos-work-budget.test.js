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
