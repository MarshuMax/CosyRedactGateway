# Security

## Threat model

Cosy Redact Gateway assumes the selected upstream may store or inspect everything it receives. The relay therefore edits supported JSON request text before the upstream fetch and only keeps the plaintext/token mapping in memory for the lifetime of that request.

It does **not** attempt to make a malicious upstream trustworthy. It only reduces accidental disclosure of values recognized by the configured detectors.

## Deployment checklist

1. Set `REDACT_ALLOWED_HOSTS` unless arbitrary upstream routing is an explicit requirement.
2. Protect public deployments with your platform's authentication/rate limiting if they should not be open relays.
3. Keep `REDACT_MAX_BODY_BYTES` bounded. It is a hard cap on request-body bytes consumed: an oversized read is cancelled before JSON parsing or redaction. The shipped default is 16 MiB; lower it on memory-constrained deployments. `REDACT_MAX_REDACTIONS` is a **different kind of limit** and does not substitute for it. It caps the number of unique plaintext identities minted in one request (default 16384), so it bounds request-local mapping and output allocation -- not detector candidate count, span count, occurrence count, or pre-mint CPU work. It is consulted during token minting, which runs after the parsers, detectors, envelopes and merge have already completed, so it cannot shorten the work a document full of candidates causes.
4. Do not log request bodies, upstream bodies, or the per-runtime salt in surrounding infrastructure.
5. Keep redirects disabled. The implementation uses `redirect: "manual"` so an upstream cannot redirect the forwarded API key to a second origin.
6. Treat URL-embedded upstream query parameters as visible routing metadata. Secrets should normally remain in forwarded authorization headers, not the proxy URL.
7. Review `docs/GITLEAKS-COMPAT.md` before relying on `G` as an exact Gitleaks replacement.

## Header policy

Authorization/provider headers are preserved, while hop-by-hop and relay identity/session headers are removed. In particular the proxy drops `Cookie`, `CF-*`, `Sec-*`, `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, and similar headers before the upstream fetch.

## State lifetime

The salt is generated once when a Worker/Deno isolate starts. Multiple concurrent isolates may therefore use different salts. Restoration does not depend on cross-request or cross-instance state: each response stream closes over its own request-local mapping.

8. Rely on the resource limits as **fail-closed**, not as graceful degradation. An over-limit
   request is refused before the upstream fetch; it is never served with weaker redaction.
   `REDACT_REFERENCE_WORK_FACTOR` bounds the reference scanner's work deterministically so
   that malformed or adversarial reference constructs cannot turn a request into unbounded
   CPU.
9. Note the asymmetry: the request body has a byte cap, the response body does not. Size
   memory accordingly, and treat the upstream as trusted for response size.

10. Observability is **off by default** and records metadata only -- never plaintext, tokens,
    bodies, URL paths or `ruleId`. If you enable it, treat the log stream as operational
    metadata rather than as content, and note that counters are per-process (Node) or
    per-isolate (Cloudflare) and reset on restart or isolate replacement. See
    `docs/OBSERVABILITY.md`.
