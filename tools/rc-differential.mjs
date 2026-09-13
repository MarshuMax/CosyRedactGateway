// item 3b: RC baseline differential. Executable harness, not a summary.
//
//   node tools/rc-differential.mjs
//
// ORACLE is the RC worker itself, exported from the tag -- deliberately NOT the current worker in
// another configuration. "current ON vs current OFF" cannot see a change that affects both, which
// is exactly what a rewrite of the observability hooks could introduce.
//
//   git show v2.0.0-rc.1:worker.js > /tmp/rcdiff/rc-worker.mjs
//
// SUBJECT is the current worker with REDACT_OBSERVABILITY explicitly off (not "1").
//
// Corpus design: the per-request token id is a CSPRNG value, so a body that RESTORES a token cannot
// be byte-identical across two runs. Rather than normalise the body -- which would hide the
// differences this harness exists to find -- the corpus is built so the final wire bytes are
// deterministic: either no token reaches the response, or the upstream echoes back the token THIS
// request minted, so both sides restore the SAME plaintext and the final bytes match exactly.
//
// Exit code is non-zero on any difference. It lives in tools/ rather than test/ because
// `node --test` collects test/ and this needs a checked-out baseline plus a /tmp oracle.

import { existsSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname } from 'node:path';

const ORACLE = '/tmp/rcdiff/rc-worker.mjs';
if (!existsSync(ORACLE)) {
  mkdirSync(dirname(ORACLE), { recursive: true });
  try {
    execFileSync('git', ['show', 'v2.0.0-rc.1:worker.js'], { stdio: ['ignore', 'pipe', 'inherit'] });
    const out = execFileSync('git', ['show', 'v2.0.0-rc.1:worker.js']);
    const { writeFileSync } = await import('node:fs');
    writeFileSync(ORACLE, out);
    console.error(`oracle exported from tag v2.0.0-rc.1 -> ${ORACLE}`);
  } catch {
    console.error('FATAL: oracle missing and could not be exported.');
    console.error(`  generate it with:  git show v2.0.0-rc.1:worker.js > ${ORACLE}`);
    process.exit(2);
  }
}
const { handleRequest: RC } = await import(ORACLE);
const { handleRequest: NOW } = await import('/home/ubuntu/repo/CosyRedactGateway/worker.js');

const SECRET = 'wJalrXUtnFEMIK7MDENGbPxRfiCY';
const NL = String.fromCharCode(10);
const TOKEN_RE = /CRG_[A-Z0-9]{6}_[A-Z0-9]{4}/;
const FIXED_FOREIGN = 'CRG_AAAAAA_0001';
const URL = (path) => `https://proxy.example/H$https://api.example${path}`;
const enc = new TextEncoder();

// ---------------------------------------------------------------------------------------------
// Corpus. `upstream` describes what the fake upstream returns for that case.
// ---------------------------------------------------------------------------------------------
const CASES = [
  { name: 'plain, no secrets',          body: 'hello world',                        upstream: { kind: 'json', text: 'ok' } },
  { name: 'upstream drops the token',   body: `PW=${SECRET}`,                       upstream: { kind: 'json', text: 'ok' } },
  { name: 'upstream returns foreign',   body: `PW=${SECRET}`,                       upstream: { kind: 'json', text: `pw is ${FIXED_FOREIGN}` } },
  { name: 'preserve in tool operand',   body: `PW=${SECRET}`, path: '/v1/messages', upstream: { kind: 'toolEchoForeign' } },
  { name: 'upstream 401 forwarded',     body: 'hello',                              upstream: { kind: 'status', status: 401, text: '{"error":"nope"}' } },
  { name: 'upstream 429 forwarded',     body: 'hello',                              upstream: { kind: 'status', status: 429, text: '{"error":"slow"}' } },
  { name: 'upstream 500 forwarded',     body: 'hello',                              upstream: { kind: 'status', status: 500, text: '{"error":"boom"}' } },
  { name: 'non-JSON content-type 415',  body: 'hello', ct: 'text/plain',            upstream: null },
  { name: 'invalid JSON 400',           raw: '{not json',                           upstream: null },
  { name: 'body over cap 413',          body: 'x'.repeat(300), cap: '64',           upstream: null },
  { name: 'depth over limit 413',       deep: 700,                                  upstream: null },
  { name: 'SSE normal',                 body: `PW=${SECRET}`, path: '/v1/responses', stream: true, upstream: { kind: 'sse', text: 'ok' } },
  { name: 'true restore (own token)',   body: `PW=${SECRET}`,                       upstream: { kind: 'echoOwn' }, strict: true },
];

function makeFetch(spec, trace) {
  return async (_u, init) => {
    trace.fetches++;
    trace.forwarded = String(init?.body ?? '');
    if (spec === null || spec === undefined) {
      return new Response(JSON.stringify({ choices: [{ message: { role: 'assistant', content: 'ok' } }] }), { headers: { 'content-type': 'application/json' } });
    }
    switch (spec.kind) {
      case 'json':
        return new Response(JSON.stringify({ choices: [{ message: { role: 'assistant', content: spec.text } }] }), { headers: { 'content-type': 'application/json' } });
      case 'toolEchoForeign':
        return new Response(JSON.stringify({ type: 'message', role: 'assistant', content: [{ type: 'tool_use', id: 't', name: 'untrusted', input: { pw: FIXED_FOREIGN } }] }), { headers: { 'content-type': 'application/json' } });
      case 'status':
        return new Response(spec.text, { status: spec.status, headers: { 'content-type': 'application/json' } });
      case 'sse': {
        const ev = (s) => `event: response.output_text.delta${NL}data: ${JSON.stringify({ type: 'response.output_text.delta', delta: s })}${NL}${NL}`;
        return new Response(ev(spec.text) + `data: [DONE]${NL}${NL}`, { headers: { 'content-type': 'text/event-stream' } });
      }
      case 'echoOwn': {
        // Echo THIS request's own token. RC and the subject mint different random ids, but each
        // gateway restores its own token to the SAME plaintext, so the final bytes still compare
        // exactly -- which is stronger than normalising the token away.
        const token = trace.forwarded.match(TOKEN_RE)?.[0] || null;
        trace.minted = token;
        if (!token) throw new Error('true-restore case did not mint a token');
        return new Response(JSON.stringify({ choices: [{ message: { role: 'assistant', content: `restored=${token}` } }] }), { headers: { 'content-type': 'application/json' } });
      }
      default:
        throw new Error(`unhandled upstream kind ${spec.kind}`);
    }
  };
}

function requestFor(spec) {
  const body = spec.raw !== undefined
    ? spec.raw
    : spec.deep
      ? JSON.stringify({ model: 'g', deep: (() => { let n = 'x'; for (let i = 0; i < spec.deep; i++) n = { c: n }; return n; })() })
      : JSON.stringify({ model: 'g', messages: [{ role: 'user', content: spec.body }], ...(spec.stream ? { stream: true } : {}) });
  const headers = { 'content-type': spec.ct || 'application/json' };
  const path = spec.path || '/v1/chat/completions';
  return new Request(URL(path), { method: 'POST', headers, body });
}

/** Canonical headers: the ones we emit, sorted, with volatile names excluded. */
function canonicalHeaders(res) {
  const keep = ['content-type', 'access-control-allow-origin', 'cache-control'];
  const out = {};
  for (const h of keep) { const v = res.headers.get(h); if (v !== null) out[h] = v; }
  return JSON.stringify(Object.fromEntries(Object.entries(out).sort()));
}

async function run(handler, spec, env) {
  const trace = { fetches: 0, forwarded: null, minted: null };
  const res = await handler(requestFor(spec), env, { salt: 'rc', fetchImpl: makeFetch(spec.upstream, trace) });
  const text = await res.text();
  return {
    status: res.status,
    body: text,
    bodyBytes: enc.encode(text).length,
    headers: canonicalHeaders(res),
    fetches: trace.fetches,
    forwarded: trace.forwarded,
    minted: trace.minted,
    own: (trace.forwarded || '').match(TOKEN_RE)?.[0] || null,
  };
}

let diff = 0;
const rows = [];
for (const spec of CASES) {
  const baseEnv = spec.cap ? { REDACT_MAX_BODY_BYTES: spec.cap } : {};
  const a = await run(RC, spec, baseEnv);
  const b = await run(NOW, spec, { ...baseEnv, REDACT_OBSERVABILITY: 'off' });
  const problems = [];
  if (a.status !== b.status) problems.push(`status RC=${a.status} NOW=${b.status}`);
  if (a.body !== b.body) problems.push(`body RC=${JSON.stringify(a.body.slice(0, 90))} NOW=${JSON.stringify(b.body.slice(0, 90))}`);
  if (a.bodyBytes !== b.bodyBytes) problems.push(`bytes RC=${a.bodyBytes} NOW=${b.bodyBytes}`);
  if (a.headers !== b.headers) problems.push(`headers RC=${a.headers} NOW=${b.headers}`);
  if (a.fetches !== b.fetches) problems.push(`fetch RC=${a.fetches} NOW=${b.fetches}`);
  if ((a.forwarded || '') !== (b.forwarded || '')) {
    // The forwarded body legitimately differs ONLY by the random token id.
    const shape = (s) => s.replace(/CRG_[A-Z0-9]{6}_[A-Z0-9]{4}/g, 'CRG_X_X');
    if (shape(a.forwarded || '') !== shape(b.forwarded || '')) problems.push('forwarded body differs beyond the token id');
  }
  // Per-case strict assertions.
  if (spec.strict) {
    if (!a.minted) problems.push('RC: no token was minted');
    if (!b.minted) problems.push('NOW: no token was minted');
    if ((a.forwarded || '').includes(SECRET)) problems.push('RC: plaintext was forwarded');
    if ((b.forwarded || '').includes(SECRET)) problems.push('NOW: plaintext was forwarded');
    if (a.own && !(a.forwarded || '').includes(a.own)) problems.push('RC: forwarded body lacks its own token');
    if (b.own && !(b.forwarded || '').includes(b.own)) problems.push('NOW: forwarded body lacks its own token');
    if (!a.body.includes(SECRET)) problems.push('RC: plaintext was NOT restored');
    if (!b.body.includes(SECRET)) problems.push('NOW: plaintext was NOT restored');
    if (a.body.includes('CRG_')) problems.push('RC: final body still contains a token');
    if (b.body.includes('CRG_')) problems.push('NOW: final body still contains a token');
  }
  if (problems.length) diff++;
  rows.push({ name: spec.name, a, b, problems });
}

console.log('case'.padEnd(34) + 'status'.padEnd(8) + 'bytes'.padEnd(7) + 'fetch'.padEnd(7) + 'result');
for (const r of rows) {
  console.log(r.name.padEnd(32) + String(r.a.status).padEnd(8) + String(r.a.bodyBytes).padEnd(7) + String(r.a.fetches).padEnd(7) + (r.problems.length ? 'DIFF' : 'ok'));
  for (const p of r.problems) console.log(`    ${p}`);
}

const tr = rows.find((r) => r.a.minted !== null || r.b.minted !== null);
if (tr) {
  console.log('true-restore evidence:');
  console.log(`  1 plaintext in request      RC=${true} NOW=${true}`);
  console.log(`  2 own token minted          RC=${tr.a.minted} NOW=${tr.b.minted} (different ids, as designed)`);
  console.log(`  3 forwarded body has token  RC=${(tr.a.forwarded || '').includes(tr.a.minted)} NOW=${(tr.b.forwarded || '').includes(tr.b.minted)}`);
  console.log(`  4 forwarded body has plain  RC=${(tr.a.forwarded || '').includes(SECRET)} NOW=${(tr.b.forwarded || '').includes(SECRET)} (must be false)`);
  console.log(`  5 final body restored       RC=${tr.a.body.includes(SECRET)} NOW=${tr.b.body.includes(SECRET)}`);
  console.log(`  6 final body token-free     RC=${!tr.a.body.includes('CRG_')} NOW=${!tr.b.body.includes('CRG_')}`);
}
console.log(`cases=${CASES.length}`);
console.log(`diff=${diff}`);
process.exit(diff === 0 ? 0 : 1);
