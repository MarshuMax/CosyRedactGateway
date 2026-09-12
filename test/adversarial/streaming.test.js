// R2.2 -- Streaming / SSE fragmentation.
//
// TWO ORACLES, kept strictly apart:
//
//   A. TRANSPORT fragmentation. The SSE BYTES are identical; only the HTTP chunk boundaries move.
//      Oracle: `gateway(fragmentedBytes) === gateway(unsplitBytes)`, byte for byte.
//
//   B. LOGICAL delta fragmentation. The same logical text is carried by a different number of SSE
//      events. Raw equality is WRONG here -- SseRestorer merges a channel and puts the restored
//      content on the first record of the run, so later deltas legitimately become empty and the
//      event count may differ. Oracle: equality of the canonicalised logical content, plus
//      separate checks that the output is parsable, ordered, and has not lost metadata or changed
//      sink policy.
//
// Confusing the two is the mistake this file is laid out to prevent: raw equality for B fails on
// correct behaviour, and canonical comparison for A hides a real byte-level change.

import test from "node:test";
import assert from "node:assert/strict";
import { handleRequest, ForeignTokenRegistry, RedactionContext } from "../../worker.js";
import { generate, makeRng } from "../helpers/property.mjs";
import {
  parseSse,
  parsedEvents,
  canonicalStream,
  canonicalText,
  canonicalSearchable,
  allEventsParsable,
  streamInChunks,
  everySplitPoint,
  randomChunks,
  oneByteChunks,
} from "./streaming-helpers.mjs";

const FLAGS = "H";
const SEED_STREAM = 0x2e610002;

const PAT = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
const AWS = "wJalrXUtnFEMIK7MDENGbPxRfiCY";
const B64 = "cGFzc3dvcmQxMjM0NTY3OA==";
const ACME_NS = { name: "acme", pattern: /(?<![A-Za-z0-9_])ACME_[A-Z0-9_]{4,}(?![A-Za-z0-9_])/, streamPrefix: "ACME_" };

/**
 * Round trip where `buildEvents` receives what the gateway minted for THIS request.
 *
 * The request id is per-request random by design, so the token (and a surrogate built from it)
 * differs between two trips of the same input. Two comparisons are therefore supported:
 *
 *   - SAME-REQUEST comparisons use the value this trip minted;
 *   - CROSS-REQUEST comparisons normalise the token first, and token uniqueness across requests is
 *     covered by its own invariant test (R0.2.1), not re-asserted here.
 *
 * An earlier version of this file built a fixture from a token learned in an EARLIER trip and then
 * compared raw bytes, which measured the random request id rather than fragmentation.
 */
async function gatewayTrip({ body, buildEvents, options = {}, chunks = null, path = "/v1/chat/completions" }) {
  let minted = null;
  const fetchImpl = async (_u, init) => {
    const seen = JSON.parse(init.body);
    minted = (JSON.stringify(seen).match(/CRG_[A-Z0-9]+_[A-Z0-9]+/) || [])[0] || null;
    const events = buildEvents(minted, seen);
    const text = events.map((e) => `event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join("") + "data: [DONE]\n\n";
    const bytes = new TextEncoder().encode(text);
    return new Response(streamInChunks(bytes, chunks ? [...chunks] : []), { headers: { "content-type": "text/event-stream" } });
  };
  const request = new Request(`https://proxy.example/${FLAGS}$https://api.example${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const response = await handleRequest(request, {}, { fetchImpl, salt: "fixed", ...options });
  return { out: await response.text(), minted, bytes: new TextEncoder().encode(String(minted)) };
}

/** Normalise a per-request token so two trips of the same input become comparable. */
const normalize = (s) => s.replace(/CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}/g, "<TOKEN>");

/** The length of the SSE body a fixture produces, needed to plan chunk boundaries. */
function sseLength(events) {
  return new TextEncoder().encode(
    events.map((e) => `event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join("") + "data: [DONE]\n\n"
  ).length;
}

const chatBody = (content = `PASSWORD=${PAT}`) => ({ model: "g", stream: true, messages: [{ role: "user", content }] });
const text = (t, prefix = "the value is ") => [{ type: "response.output_text.delta", delta: `${prefix}${t}` }];

// =====================================================================================
// A. TRANSPORT fragmentation -- byte equality is the oracle
// =====================================================================================

test("R2.2-A: every split point of the HTTP stream gives byte-identical output [RED]", async () => {
  // One logical event, so nothing about channel merging is involved: this isolates the transport.
  // Each trip builds its event from ITS OWN token, and the comparison normalises the token, because
  // the request id is random by design and the difference it causes is not a transport difference.
  const type = "response.output_text.delta";
  const build = (t) => [{ type, delta: `the value is ${t}` }];
  const byteLength = sseLength(build("CRG_AAAAAA_0001"));

  const base = await gatewayTrip({ body: chatBody(), path: "/v1/responses", buildEvents: build });
  for (const plan of everySplitPoint(new Uint8Array(byteLength))) {
    const { out } = await gatewayTrip({ body: chatBody(), path: "/v1/responses", buildEvents: build, chunks: plan });
    assert.equal(normalize(out), normalize(base.out), `chunk plan ${JSON.stringify(plan)} changed the output`);
  }
});

test("R2.2-A: one byte at a time gives byte-identical output [RED]", async () => {
  const build = (t) => [{ type: "response.output_text.delta", delta: `value ${t}` }];
  const byteLength = sseLength(build("CRG_AAAAAA_0001"));
  const base = await gatewayTrip({ body: chatBody(), path: "/v1/responses", buildEvents: build });
  const { out } = await gatewayTrip({
    body: chatBody(), path: "/v1/responses", buildEvents: build,
    chunks: oneByteChunks(new Uint8Array(byteLength)),
  });
  assert.equal(normalize(out), normalize(base.out), "a 1-byte-per-chunk transport must not change a byte");
});

test("R2.2-A: random 2..8 piece splits give byte-identical output [RED]", async () => {
  const build = (t) => [{ type: "response.output_text.delta", delta: `value ${t}` }];
  const byteLength = sseLength(build("CRG_AAAAAA_0001"));
  const base = await gatewayTrip({ body: chatBody(), path: "/v1/responses", buildEvents: build });
  const rng = makeRng(SEED_STREAM);
  for (let i = 0; i < 60; i++) {
    const plan = randomChunks(rng, new Uint8Array(byteLength));
    const { out } = await gatewayTrip({ body: chatBody(), path: "/v1/responses", buildEvents: build, chunks: plan });
    assert.equal(normalize(out), normalize(base.out), `random plan ${JSON.stringify(plan)} changed the output`);
  }
});

test("R2.2-A: a multi-byte character split across chunks gives byte-identical output [RED]", async () => {
  // The gateway decodes with a streaming TextDecoder, so a UTF-8 sequence divided between two
  // chunks must be reassembled rather than replaced with a replacement character.
  const build = (t) => [{ type: "response.output_text.delta", delta: `值 ${t} ✓ 完成` }];
  const base = await gatewayTrip({ body: chatBody(), path: "/v1/responses", buildEvents: build });
  assert.ok(base.out.includes("值"), "the multi-byte characters must survive");

  const bytes = new TextEncoder().encode(
    `event: response.output_text.delta\ndata: ${JSON.stringify(build("CRG_AAAAAA_0001")[0])}\n\ndata: [DONE]\n\n`
  );
  const plans = [];
  for (let i = 1; i < bytes.length; i++) if ((bytes[i] & 0xc0) === 0x80) plans.push([i, bytes.length - i]);
  assert.ok(plans.length > 0, "the fixture must contain multi-byte characters to split");
  for (const plan of plans) {
    const { out } = await gatewayTrip({ body: chatBody(), path: "/v1/responses", buildEvents: build, chunks: plan });
    assert.equal(normalize(out), normalize(base.out), `a UTF-8 sequence split at ${plan[0]} changed the output`);
    assert.equal(out.includes("\uFFFD"), false, "and must not produce a replacement character");
  }
});

test("R2.2-A: transport fragmentation is invariant for every sink channel [RED]", async () => {
  // The same statement across the channels that route differently. A sink policy that behaved
  // differently under fragmentation would be a real defect.
  const cases = [
    ["output_text", "response.output_text.delta"],
    ["function_call_arguments", "response.function_call_arguments.delta"],
    ["mcp_call_arguments", "response.mcp_call_arguments.delta"],
    ["custom_tool_call_input", "response.custom_tool_call_input.delta"],
    ["unknown_event", "response.future.thing.delta"],
  ];
  for (const [label, type] of cases) {
    const build = (t) => [{ type, delta: `curl x?y=${t}` }];
    const byteLength = sseLength(build("CRG_AAAAAA_0001"));
    const base = await gatewayTrip({ body: chatBody(), path: "/v1/responses", buildEvents: build });
    for (const cut of [1, Math.floor(byteLength / 3), Math.floor(byteLength / 2), byteLength - 1]) {
      const { out } = await gatewayTrip({ body: chatBody(), path: "/v1/responses", buildEvents: build, chunks: [cut, byteLength - cut] });
      assert.equal(normalize(out), normalize(base.out), `${label}: split at ${cut} changed the output`);
    }
  }
});

// =====================================================================================
// B. LOGICAL delta fragmentation -- canonical content is the oracle
// =====================================================================================

test("R2.2-B: the canonicalizer is stable and the two oracles really differ [GREEN NOW]", () => {
  // Guard on the helper itself, and a demonstration that raw equality is the WRONG oracle for
  // logical fragmentation -- otherwise a future reader may "simplify" B into A.
  const single = 'event: x\ndata: {"delta":"abc"}\n\ndata: [DONE]\n\n';
  const split = 'event: x\ndata: {"delta":"a"}\n\nevent: x\ndata: {"delta":"bc"}\n\ndata: [DONE]\n\n';

  assert.notEqual(single, split, "the raw SSE bodies differ, which is legal");
  assert.equal(canonicalText(single), canonicalText(split), "but the canonical content is equal");
  assert.deepEqual(canonicalStream(single).content, { delta: "abc" });
  assert.deepEqual(canonicalStream(split).content, { delta: "abc" });
  assert.equal(allEventsParsable(single) && allEventsParsable(split), true);
});

test("R2.2-B: a surrogate split across events keeps its canonical content [RED]", async () => {
  // The fragmentable value that exists today: a surrogate is base64 of a CRG token, so it is NOT
  // CRG-shaped and the stream layer has to reassemble it from whatever pieces arrive. Compared
  // token-normalised, because each trip mints a different request id.
  const doc = ["apiVersion: v1", "kind: Secret", "data:", `  password: ${B64}`].join("\n");
  const body = { model: "g", stream: true, input: doc };
  const build = (surrogate) => [{ type: "response.output_text.delta", delta: `value ${surrogate}` }];

  // Learn the surrogate shape from one trip, then re-derive it per trip from the upstream input.
  const probe = await gatewayTrip({
    body,
    path: "/v1/responses",
    buildEvents: (t, seen) => {
      const surrogate = (String(seen.input).match(/password: (\S+)/) || [])[1];
      assert.ok(surrogate, "fixture must produce a surrogate");
      return build(surrogate);
    },
  });
  // NO assertion on `minted` here: with a representation-constrained field the upstream never sees
  // a CRG token at all, only the surrogate, so `minted` is null by design. Asserting on it was a
  // fixture mistake, and the surrogate is recovered from the upstream input instead.
  assert.ok(probe.out.length > 0, "the probe must produce a stream");

  for (const fraction of [0.25, 0.5, 0.75]) {
    const whole = await gatewayTrip({
      body,
      path: "/v1/responses",
      buildEvents: (t, seen) => build((String(seen.input).match(/password: (\S+)/) || [])[1]),
    });
    const split = await gatewayTrip({
      body,
      path: "/v1/responses",
      buildEvents: (t, seen) => {
        const surrogate = (String(seen.input).match(/password: (\S+)/) || [])[1];
        const cut = Math.max(1, Math.floor(surrogate.length * fraction));
        return [
          { type: "response.output_text.delta", delta: `value ${surrogate.slice(0, cut)}` },
          { type: "response.output_text.delta", delta: surrogate.slice(cut) },
        ];
      },
    });
    assert.equal(
      canonicalSearchable(split.out), canonicalSearchable(whole.out),
      `fraction=${fraction}: canonical content changed`
    );
    assert.equal(allEventsParsable(split.out), true, `fraction=${fraction}: every event must stay parsable`);
  }
});

test("R2.2-B: metadata and event ordering survive logical fragmentation [RED]", async () => {
  // Canonical content equality alone would not notice a lost field or a reordered event, so those
  // are asserted separately. Two events, each carrying its own metadata, unfragmented.
  const body = { model: "g", stream: true, input: "PASSWORD=" + PAT };
  const events = (t) => [
    { type: "response.output_text.delta", delta: `a ${t}`, sequence_number: 1, item_id: "item_1" },
    { type: "response.output_text.delta", delta: ` b`, sequence_number: 2, item_id: "item_2" },
  ];
  const { out } = await gatewayTrip({ body, path: "/v1/responses", buildEvents: events });

  const sequenced = parsedEvents(out).filter((e) => e.json && e.json.sequence_number !== undefined);
  assert.equal(sequenced.length, 2, `both sequenced events must survive, saw ${sequenced.length}`);
  assert.deepEqual(sequenced.map((e) => e.json.sequence_number), [1, 2], "order must be preserved");
  assert.deepEqual(sequenced.map((e) => e.json.item_id), ["item_1", "item_2"], "and metadata with it");
  assert.ok(sequenced[0].json.delta.includes("a "), "the first event carries the first text");
});

test("R2.2-B: logical fragmentation does not change sink policy [RED]", async () => {
  // An operand channel must preserve (or refuse) under fragmentation exactly as it does whole.
  const cases = [
    ["tool_argument", "response.function_call_arguments.delta", "delta"],
    ["mcp_call_arguments", "response.mcp_call_arguments.delta", "delta"],
    ["unknown", "response.future.thing.delta", "delta"],
  ];
  for (const [label, type, field] of cases) {
    const whole = await gatewayTrip({
      body: chatBody(), path: "/v1/responses",
      buildEvents: (t) => [{ type, [field]: `curl x?y=${t}` }],
    });
    const split = await gatewayTrip({
      body: chatBody(), path: "/v1/responses",
      buildEvents: (t) => {
        // The SAME payload, distributed across two events. An earlier version split the token but
        // dropped the surrounding text, so the two sides were not the same logical content at all.
        const cut = Math.floor(t.length / 2);
        return [
          { type, [field]: `curl x?y=${t.slice(0, cut)}` },
          { type, [field]: t.slice(cut) },
        ];
      },
    });
    assert.equal(
      canonicalSearchable(split.out), canonicalSearchable(whole.out),
      `${label}: canonical content changed`
    );
    // The plaintext must never appear in an operand channel, whole or fragmented. Searched in the
    // REASSEMBLED content, because fragmentation legitimately distributes a value across fields.
    assert.equal(canonicalSearchable(split.out).includes(PAT), false, `${label}: no plaintext after fragmentation`);
    assert.equal(canonicalSearchable(whole.out).includes(PAT), false, `${label}: no plaintext when whole`);
  }
});

test("R2.2-B: an unknown event does not gain RESTORE authority by being fragmented [RED]", async () => {
  const type = "response.future.thing.delta";
  const whole = await gatewayTrip({
    body: chatBody(), path: "/v1/responses",
    buildEvents: (t) => [{ type, delta: `value ${t}` }],
  });
  assert.equal(canonicalSearchable(whole.out).includes(PAT), false, "an unknown event must not resolve when whole");

  const split = await gatewayTrip({
    body: chatBody(), path: "/v1/responses",
    buildEvents: (t) => {
      const cut = Math.floor(t.length / 2);
      return [
        { type, delta: `value ${t.slice(0, cut)}` },
        { type, delta: t.slice(cut) },
      ];
    },
  });
  assert.equal(canonicalSearchable(split.out).includes(PAT), false, "and must not gain it by being fragmented");
  assert.equal(canonicalSearchable(split.out), canonicalSearchable(whole.out), "canonical content unchanged");
});

test("R2.2-B: an unrelated base64 blob is not held or altered under fragmentation [RED]", async () => {
  // Shape alone must not create a holdback, so a base64 string the request never minted passes
  // through, whole or fragmented.
  const blob = Buffer.from("not-a-token-at-all").toString("base64");
  const build = (events) => events;
  const whole = await gatewayTrip({
    body: chatBody(), path: "/v1/responses",
    buildEvents: () => build([{ type: "response.output_text.delta", delta: `x ${blob} y` }]),
  });
  assert.ok(canonicalSearchable(whole.out).includes(blob), "an unrelated blob must pass through");

  const cut = Math.floor(blob.length / 2);
  const split = await gatewayTrip({
    body: chatBody(), path: "/v1/responses",
    buildEvents: () => build([
      { type: "response.output_text.delta", delta: `x ${blob.slice(0, cut)}` },
      { type: "response.output_text.delta", delta: `${blob.slice(cut)} y` },
    ]),
  });
  assert.equal(canonicalSearchable(split.out), canonicalSearchable(whole.out), "canonical content unchanged");
  // The blob is base64, so a two-event split legitimately places it in two `delta` fields; it is
  // contiguous only after reassembly, which is what is searched here.
  assert.ok(canonicalSearchable(split.out).includes(blob), "and the blob is not altered or held");
});

// =====================================================================================
// Seeded exploration
// =====================================================================================

test("R2.2: seeded logical fragmentation keeps canonical content stable [GREEN NOW]", async () => {
  // Exploration over where the logical text is cut, using the category seed. Only canonical
  // equality and parsability are asserted, because those are what hold for every cut.
  const blob = Buffer.from("unrelated-blob-payload").toString("base64");
  const values = ["plain text with no token", blob, "值 with multi-byte ✓", `a ${blob} b ${blob} c`];
  let cases = 0;
  for (const { value, pieces } of generate({
    seed: SEED_STREAM,
    count: 120,
    gen: (r) => ({ value: r.pick(values), pieces: r.int(2, 6) }),
  })) {
    const whole = await gatewayTrip({
      body: chatBody(), path: "/v1/responses",
      buildEvents: () => [{ type: "response.output_text.delta", delta: value }],
    });

    const points = [];
    for (let i = 1; i < pieces; i++) {
      const at = Math.floor((value.length * i) / pieces);
      if (at > 0 && at < value.length && !points.includes(at)) points.push(at);
    }
    const split = await gatewayTrip({
      body: chatBody(), path: "/v1/responses",
      buildEvents: () => {
        const events = [];
        let prev = 0;
        for (const c of [...points, value.length]) {
          events.push({ type: "response.output_text.delta", delta: value.slice(prev, c) });
          prev = c;
        }
        return events;
      },
    });
    assert.equal(
      canonicalSearchable(split.out), canonicalSearchable(whole.out),
      `value=${JSON.stringify(value)} cuts=${points.length}`
    );
    assert.equal(allEventsParsable(split.out), true, "every event stays parsable");
    cases++;
  }
  assert.equal(cases, 120);
});
