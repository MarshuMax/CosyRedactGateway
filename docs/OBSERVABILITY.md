# Observability

Optional, **off by default**, metadata-only telemetry. It answers "did redaction actually
happen, and what did the gateway decide?" without ever recording what it redacted.

This is v2.1 PR1: the telemetry core and the structured log line. The `/admin` endpoint, its
UI and its authentication are PR2 and do not exist yet.

## Enabling it

| Variable | Default | Meaning |
|---|---:|---|
| `REDACT_OBSERVABILITY` | unset | Telemetry is disabled unless this is exactly the string `1`. |
| `REDACT_OBSERVABILITY_BUFFER` | 500 | Size of the recent-request ring. Clamped to the hard maximum of 2000. |

When disabled there is no store, no record, no log line, and the response is unchanged. That
equivalence is pinned by a regression test, not just asserted here.

## What is recorded

One record per completed request, and one human-readable line on stderr.

```
[CRG] seq=1 upstream=api.example status=200 outcome=forwarded detected=1 redacted=1
      preserved=0 detectors=entropy:1 sink_modes=restore:1 sink_outcomes=restored:1
      response_ready_ms=13
```

The record has a **closed schema**:

| Field | Notes |
|---|---|
| `schema_version` | `1`. Deliberately not the application version: a record schema and a build identifier are different things, and hardcoding a release here would drift. |
| `t`, `seq` | Timestamp; monotonic per-process sequence. |
| `upstream` | Hostname only. No path, no query. |
| `status`, `outcome` | See the outcome list below. |
| `response_ready_ms` | Elapsed from telemetry admission until the downstream Response is ready to return, **including the upstream wait**. Filled on every recorded path. Idempotent: the first mark wins. |
| `stream_duration_ms` | SSE only: the body's lifetime, filled at close / error / cancel. `null` for non-stream. |
| `spans` | `{decisions, redact, preserve, bytes_redacted, detectors, reasons, infra_types}` |
| `detectors` | detector name -> count |
| `sink_modes` | `{restore, preserve, block}` -- the **policy** |
| `sink_outcomes` | `{restored, preserved, blocked}` -- what was actually **delivered** |
| `coverage` | Per-parser `{attempted, parsed, partial, failed, bytes}` |
| `limit_reason` | `body_bytes` / `json_depth` / `reference_work` / `redaction_limit` / `upstream_depth`, else `null`. A refusal that is not a resource limit (415, malformed JSON 400) records `null` rather than inventing one. |

`outcome` is one of:

| outcome | meaning |
|---|---|
| `forwarded` | an upstream HTTP response was relayed, whatever its status -- including 4xx and 5xx |
| `rejected_content_type` | 415; a non-JSON request body |
| `rejected_json` | 400; an unparseable request body |
| `rejected_body` | 413; the request byte cap |
| `rejected_depth` | 413; request JSON nesting |
| `rejected_redaction` | 413; the unique-entity cap |
| `rejected_work` | 413; the reference-scan work budget |
| `upstream_error` | the upstream fetch THREW; the gateway generated the 502 |
| `upstream_depth` | 502; the upstream RESPONSE nested too deeply |
| `stream_error` | an SSE terminal error, including the depth guard |
| `client_cancel` | the client cancelled the SSE stream |

`forwarded` versus `upstream_error` and `upstream_depth` is the distinction to keep straight: the
gateway reports what IT did. A provider returning 429 or 500 is `forwarded`; only a transport
failure or a gateway-generated refusal is an error outcome. In particular a native upstream 502 is
`forwarded`, while a gateway-generated response-depth 502 is `upstream_depth` -- both reach the
client as 502, so the status alone cannot tell them apart, which is why the outcome is reported by
the code that knows rather than inferred from the status code.

## What is never recorded

No plaintext, no tokens, no `CRG_` values, no request or response bodies, no token-to-plaintext
mapping, no URL path or query, and no `ruleId`.

That is enforced **structurally**, not by scanning for suspicious strings:

1. The accumulator holds counters only. It receives no `ctx`, no `Response`, no stream, no span
   rows and no text, so there is no parameter through which plaintext could arrive.
2. Telemetry consumes a **safe projection** (`telemetryProjection()`) that copies counts and
   returns no rows. `policySummary()` still returns `rows: this.spanActions` and is untouched,
   but telemetry never sees it -- both because it has no use for the detail and because a field
   added to a row later would otherwise silently widen the surface.
3. Enum values are allowlisted against frozen constant sets.
4. Unknown values are handled in two tiers:
   - **Statistical dimensions** (`detector`, `reason`, `infraType`, `parser`): the bucket is
     dropped and `dropped_enum_values_total` is incremented. **The unknown string is never
     retained**, so a future detector cannot widen the schema. One new detector does not
     discard the whole record.
   - **Core enums** (`outcome`, span action, sink mode, sink outcome): the **whole record is
     refused** and `records_dropped_invalid_total` is incremented. If these are untrustworthy
     the record means nothing, and a half-trustworthy record misleads.

There is deliberately **no** heuristic "plaintext guard" in production. Substring scanning for
`CRG_` or a sentinel is a test technique, not a correctness mechanism, and it would both fail
to prove absence and misfire on legitimate long metadata.

## Sink mode is not sink outcome

These are two dimensions and are reported separately, because conflating them is easy and
wrong.

| mode | blocked | text changed | outcome |
|---|---|---|---|
| `RESTORE` | no | **yes** | `restored` |
| `RESTORE` | no | **no** | **`preserved`** |
| `PRESERVE` | no | no | `preserved` |
| `PRESERVE` | yes | -- | `blocked` |
| `BLOCK` | no | no | **`preserved`** |
| `BLOCK` | yes | -- | `blocked` |

Two rows deserve their emphasis:

- **`RESTORE` does not mean anything was resolved.** A RESTORE channel that found no OWN token
  delivers the text unchanged. `classifyRestore()` has always drawn this distinction from
  `applied.text !== text`; the telemetry uses the same rule, evaluated once inside
  `applySinkPolicy` where both the input and the output string exist, and only the resulting
  boolean crosses into telemetry.
- **`BLOCK` is a policy, not an event.** A BLOCK channel with nothing to refuse delivered the
  text as-is, so its outcome is `preserved`.

## Bounded retention

The recent-request ring has a fixed capacity (default 500, hard maximum 2000) and **overwrites
the oldest entry**; it never grows. Counter maps have fixed key spaces. Log lines are written
straight out and never accumulated.

This is not hypothetical diligence. During the v2.0 R3.6 soak an apparent gateway memory leak
turned out to be an unbounded `arr.push` in the measurement harness itself. The same mistake is
not repeated in production.

`TelemetryStore.retentionReport()` returns the current length and cap of every structure plus
the dropped-value counters, so the bound is inspectable rather than assumed.

## Latency is two fields

`response_ready_ms` is elapsed time from **telemetry admission until the downstream Response is
ready to return**, and it **includes the upstream wait**. It is deliberately not described as
gateway processing time.

`stream_duration_ms` is the SSE body's own lifetime, filled at close, error or cancel.

An SSE record carries **both**, and neither is null: one answers "how long until we could answer",
the other "how long the stream then lived". Collapsing them into one number would make the two
incomparable.

The accumulator owns the start point and computes the delta itself, so the several terminal paths
cannot each pick their own origin and produce numbers that look comparable but are not.
`coverage` is snapshotted right after request redaction succeeds and **before** the upstream fetch,
so a request whose fetch later fails still reports the redaction and parser coverage it really had
rather than reporting zero.

## Scope: this is not a global metric

| Runtime | Scope |
|---|---|
| Node | the current **process** |
| Cloudflare Workers | the current **isolate** |
| Deno | the current **runtime / process** |

A restart or an isolate replacement resets everything. On Cloudflare with several isolates,
the counters are **not** a deployment total -- they describe the isolate that served the
request you are looking at. v2.1 has no persistence and no cross-isolate aggregation, and no
UI may present these numbers as global.

## Known boundary: an unconsumed stream has no record

A request finalizes exactly once, on one of: non-stream completion, SSE close, SSE error, or
explicit client cancel.

An SSE response that is **never consumed and never cancelled** produces **no record**. Its
accumulator is reachable only from the stream closure, so it becomes garbage rather than a
retained pending entry -- and we do not add a `FinalizationRegistry`, a GC hook or a weak
reference to manufacture a guarantee the runtime does not offer.

There is deliberately **no global pending/in-flight accumulator map**. Such a map would
reintroduce exactly the retention leak this design exists to avoid: a client that holds a
Response without reading it would pin an entry forever. Fewer records is the correct trade
against unreliable finalization and real memory retention.

> telemetry records completed or explicitly terminated stream lifecycles; an SSE response that
> is never consumed and never cancelled may have no per-request telemetry record.

## Status: PR1 frozen

PR1 -- the telemetry core and the structured log line -- is frozen at commit `934bafa6` on branch
`v2.1-observability`, based on the v2.0.0-rc.1 tag (`151c12fd`). Twenty-five commits, 830 insertions
and 15 deletions in `worker.js`.

Frozen means: no further benchmarks, no additional leak cases, no production telemetry optimisation.
PR2 (the `/admin` endpoint, its authentication and its UI) starts from `934bafa6` as its baseline and
its contents are not back-filled into PR1.

What PR1 established, and the evidence behind each:

| Claim | Evidence |
|---|---|
| 11 terminal outcomes all wired | every recorded path asserted through the real `handleRequest` |
| Three telemetry outlets carry no plaintext, token, routing metadata or raw error text | T1 sweep over `recent.toArray()`, `summary()` and the log lines, with a positive control that uses the SAME scanner and a negative-verified leaky build |
| A telemetry fault cannot change a status, body or security outcome | four fault injections, each comparing OFF against faulted-ON; the sink case asserts the security verdict, not just absence of a crash |
| The recent ring is bounded | `recent.length === cap`, `within === true` after 10,000 requests against a cap of 100 |
| Fixed-key maps do not grow with request count | every map `<= 1` key after the same soak |
| No sustained post-cap growth signal | B (ring full) to C (10,000 requests) delta: RSS -1.94 MiB, heap +0.12 MiB, post-GC heap 9.0 -> 9.1 MiB |

Observability overhead, measured on identical workloads, is **reported and not gated**: the ON run
measured slightly faster (throughput ratio 1.0737, latency ratio 0.9313), which is JIT and execution
order rather than a speed-up, since the ON run executes second against warmed code. The +22.75 MiB RSS
difference between the two runs is **start-up**, not a resident telemetry cost -- the post-cap phase
shows no evidence of request-count-proportional growth, which is precisely why that phase is measured separately from process start.
None of these numbers is a pass/fail threshold; they depend on V8, GC timing and the machine.

### Test asset layout

| Location | Role | Runs in `npm test` |
|---|---|---|
| `test/` | correctness and bounded deterministic regressions | yes |
| `tools/rc-differential.mjs` | RC baseline differential; needs a checked-out tag and a /tmp oracle | **no**, deliberately |
| `scripts/perf-*.mjs` | heavy sweeps and measurement, observation only | **no** |
