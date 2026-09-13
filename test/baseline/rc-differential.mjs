// item 3b: RC baseline differential, run manually.
//
//   node test/baseline/rc-differential.mjs
//
// ORACLE is the RC worker itself, regenerated from the tag rather than kept as a fixture:
//
//   git show v2.0.0-rc.1:worker.js > /tmp/rcdiff/rc-worker.mjs
//
// SUBJECT is the current worker with REDACT_OBSERVABILITY off. This is NOT "current ON vs current
// OFF": that comparison cannot see a change that affects both, which is exactly what a test-only
// rewrite of the observability hooks could introduce.
//
// Corpus design, and why: the per-request token id is a CSPRNG value, so a response that RESTORES a
// token can never be byte-identical across two runs. Rather than normalise the whole body (which
// would hide real differences), the corpus is chosen so the final wire bytes are deterministic --
// either no token reaches the response at all, or the upstream is handed a fixed foreign token that
// both sides treat identically.
//
// Compared per case: status, response body BYTES, the response headers we emit, the upstream fetch
// count, and the body itself.
//
// KNOWN GAP, not yet closed: the `true restore` section at the bottom is broken. It was meant to
// cover the one path the deterministic corpus cannot reach -- an upstream echoing the token THIS
// request minted -- but its request construction is faulty, so both sides return 502 with no token
// minted and it proves only that they fail identically. It must be repaired before this file is
// treated as covering restoration.
