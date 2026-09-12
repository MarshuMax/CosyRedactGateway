// R2.2 -- streaming helpers.
//
// The two fragmentation oracles are DIFFERENT and must never be conflated:
//
//   A. TRANSPORT fragmentation -- identical SSE bytes, only the HTTP chunk boundaries move.
//      The oracle is byte equality of the gateway's output:
//          gateway(fragmentedBytes) === gateway(unsplitBytes)
//
//   B. LOGICAL delta fragmentation -- the same logical text arrives as a different number of SSE
//      events. Raw SSE equality is WRONG here: SseRestorer merges a channel and places the
//      restored content on the FIRST record of the run, so later deltas legitimately become empty
//      and the event count may differ. The oracle is equality of the CANONICAL logical content,
//      plus separate checks that the output is still well-formed, correctly ordered, and has not
//      lost metadata or changed sink policy.
//
// Using raw string equality for B would fail on correct behaviour; using canonical comparison for
// A would hide a transport-level byte change. Hence two oracles, named separately.

/**
 * Parse an SSE body into events that keep their raw fields, so canonicalisation can preserve
 * ordering and metadata while comparing content.
 *
 * Deliberately hand-written rather than reused from worker.js: a test helper that shares the
 * implementation's parser cannot detect a parser bug.
 */
export function parseSse(body) {
  const events = [];
  const blocks = String(body).split(/\r?\n\r?\n/);
  for (const block of blocks) {
    if (!block.trim()) continue;
    const event = { event: "", data: [], comments: [], raw: block };
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith("event:")) event.event = line.slice(6).trim();
      else if (line.startsWith("data:")) event.data.push(line.slice(5).replace(/^ /, ""));
      else if (line.startsWith(":")) event.comments.push(line);
      else if (line.trim()) event.other = (event.other || []).concat(line);
    }
    event.dataText = event.data.join("\n");
    events.push(event);
  }
  return events;
}

/** Every event's data payload parsed as JSON, or null when it is not JSON. */
export function parsedEvents(body) {
  return parseSse(body).map((e) => {
    if (e.dataText === "[DONE]") return { done: true, event: e.event };
    try {
      return { json: JSON.parse(e.dataText), event: e.event };
    } catch {
      return { unparsable: e.dataText, event: e.event };
    }
  });
}

const CHANNEL_KEYS = {
  // OpenAI chat / Responses style
  assistant: ["choices", "delta", "content"],
  tool: ["choices", "delta", "tool_calls"],
};

/** Recursively collect every string leaf of a value, keyed by its path. */
function leaves(value, path = [], out = []) {
  if (typeof value === "string") { out.push([path.join("."), value]); return out; }
  if (Array.isArray(value)) { value.forEach((v, i) => leaves(v, [...path, String(i)], out)); return out; }
  if (value && typeof value === "object") {
    for (const k of Object.keys(value)) leaves(value[k], [...path, k], out);
  }
  return out;
}

/**
 * Fields that carry CONTENT and therefore accumulate across logical events.
 *
 * Everything else in an event is METADATA: it legitimately repeats on every event (`type` is the
 * event kind) or describes that one event. An earlier version of this helper concatenated EVERY
 * string leaf, which counted `type` once per event and made a correctly merged run compare unequal
 * to its single-event equivalent -- a false oracle.
 */
const CONTENT_FIELDS = new Set(["delta", "text", "partial_json", "arguments", "input", "content", "output_text"]);

/** Metadata fields of the first event that carries any, for separate preservation checks. */
function metadataOf(events) {
  const out = {};
  for (const e of events) {
    if (!e.json || typeof e.json !== "object") continue;
    const walk = (value, path) => {
      if (typeof value === "string") {
        if (!CONTENT_FIELDS.has(path[path.length - 1])) out[path.join(".")] = value;
        return;
      }
      if (Array.isArray(value)) { value.forEach((v, i) => walk(v, [...path, String(i)])); return; }
      if (value && typeof value === "object") for (const k of Object.keys(value)) walk(value[k], [...path, k]);
    };
    walk(e.json, []);
    if (Object.keys(out).length) break;
  }
  return out;
}

/** Concatenate every CONTENT field, keyed by path, in event order. */
function contentOf(events) {
  const byPath = new Map();
  const order = [];
  for (const event of events) {
    if (!event.json || typeof event.json !== "object") continue;
    const walk = (value, path) => {
      if (typeof value === "string") {
        const key = path[path.length - 1];
        if (!CONTENT_FIELDS.has(key)) return;
        const identity = path.join(".").replace(/\.\d+(?=\.|$)/g, "[]");
        if (!byPath.has(identity)) { byPath.set(identity, []); order.push(identity); }
        byPath.get(identity).push(value);
        return;
      }
      if (Array.isArray(value)) { value.forEach((v, i) => walk(v, [...path, String(i)])); return; }
      if (value && typeof value === "object") for (const k of Object.keys(value)) walk(value[k], [...path, k]);
    };
    walk(event.json, []);
  }
  const content = {};
  for (const key of order) content[key] = byPath.get(key).join("");
  return content;
}

/**
 * Canonical logical content of a streamed response.
 *
 * Invariant to how the text was distributed across events and to the legal re-shaping that channel
 * merging performs, while still distinguishing fields from one another.
 */
export function canonicalStream(body) {
  const events = parsedEvents(body);
  let done = 0;
  let unparsable = 0;
  const usable = [];
  for (const e of events) {
    if (e.done) { done++; continue; }
    if (e.unparsable !== undefined) { unparsable++; continue; }
    usable.push(e);
  }
  return {
    content: contentOf(usable),
    metadata: metadataOf(usable),
    events: events.length,
    done,
    unparsable,
  };
}

/**
 * One searchable string: the canonical CONTENT with per-request tokens normalised.
 *
 * Raw output must NOT be searched for a value that fragmentation may have distributed across
 * fields -- the reassembled logical content is the only place it is guaranteed to appear
 * contiguously. Token normalisation removes the random request id, which is not what these tests
 * are about.
 */
export function canonicalSearchable(body) {
  const { content } = canonicalStream(body);
  return Object.keys(content).sort().map((k) => `${k}=${content[k]}`).join("\n")
    .replace(/CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}/g, "<TOKEN>");
}

/** Flatten the canonical content into one comparable string (sorted, so key order is not content). */
export function canonicalText(body) {
  const { content } = canonicalStream(body);
  return Object.keys(content).sort().map((k) => `${k}=${content[k]}`).join("\n");
}

/** True when every non-[DONE] event's data is parsable JSON. */
export function allEventsParsable(body) {
  const events = parsedEvents(body);
  return events.every((e) => e.done || e.unparsable === undefined);
}

/**
 * Feed `bytes` to a ReadableStream in the given chunk sizes, optionally splitting at raw byte
 * offsets. Returns the response from `handler`.
 */
export function streamInChunks(bytes, chunks) {
  const encoder = new Uint8Array(bytes);
  let at = 0;
  return new ReadableStream({
    pull(controller) {
      if (at >= encoder.length) { controller.close(); return; }
      const size = chunks.length ? chunks.shift() : encoder.length - at;
      const end = Math.min(at + Math.max(1, size), encoder.length);
      controller.enqueue(encoder.slice(at, end));
      at = end;
    },
  });
}

/** Deterministic chunk plan: every single split point, for small inputs. */
export function everySplitPoint(bytes) {
  const plans = [[bytes.length]];
  for (let cut = 1; cut < bytes.length; cut++) plans.push([cut, bytes.length - cut]);
  return plans;
}

/** Deterministic chunk plan: random 2..8 pieces, driven by a seeded rng. */
export function randomChunks(rng, bytes, min = 2, max = 8) {
  const pieces = rng.int(min, max);
  const cuts = new Set();
  while (cuts.size < pieces - 1) cuts.add(rng.int(1, Math.max(1, bytes.length - 1)));
  const sorted = [...cuts].sort((a, b) => a - b);
  const plan = [];
  let prev = 0;
  for (const c of sorted) { plan.push(c - prev); prev = c; }
  plan.push(bytes.length - prev);
  return plan.filter((n) => n > 0);
}

/** One byte at a time. */
export function oneByteChunks(bytes) {
  return Array.from({ length: bytes.length }, () => 1);
}
