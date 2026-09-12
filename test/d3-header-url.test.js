// D3a/D3b/D3c: pasted HTTP headers and URL query values.
//
// Two levels are kept strictly apart (DESIGN-v2 9.10):
//
//   - PASTED header text: `Authorization: Bearer <secret>` appearing in a prompt. This
//     is redacted.
//   - TRANSPORT headers: what this gateway sends upstream, built in
//     filteredRequestHeaders() and never routed through text redaction. They must keep
//     carrying the real Authorization / x-api-key, because the upstream needs them to
//     authenticate.
//
// URL handling uses RAW spans only: the query value is replaced as-is, with no
// decoding and no re-encoding, so percent-escapes, `+`, parameter order, duplicate
// parameters and fragments survive byte for byte.
//
// D3c: `redactJson` used to skip any string under a `url` key before it could reach
// redactText, so `{"url": "https://x/?access_token=SECRET"}` was forwarded verbatim.
//
// Assertion tags:
//   [GREEN NOW]  passes against the current tree

import test from "node:test";
import assert from "node:assert/strict";
import {
  RedactionContext,
  redactJson,
  parseHeaderBindings,
  parseUrlBindings,
  handleRequest,
  TOKEN_PREFIX,
} from "../worker.js";

const SECRET = "Pr0d-P@ssw0rd-Xy9Zk2mQ";
const FLAGS = { gitleaks: true, highEntropy: true, email: true };

function ctx() {
  return new RedactionContext({ salt: "fixture" });
}

async function redact(text, flags = FLAGS, context = ctx()) {
  return { out: await context.redactText(text, flags), ctx: context };
}

// ------------------------------------------------------ 1. pasted headers ------

test("D3a: a pasted sensitive header is redacted, the scheme survives [GREEN NOW]", async () => {
  const cases = [
    [`Authorization: Bearer ${SECRET}`, "Authorization: Bearer "],
    [`x-api-key: ${SECRET}`, "x-api-key: "],
    [`Proxy-Authorization: Basic ${SECRET}`, "Proxy-Authorization: Basic "],
    [`X-Auth-Token: ${SECRET}`, "X-Auth-Token: "],
    [`X-Amz-Security-Token: ${SECRET}`, "X-Amz-Security-Token: "],
  ];
  for (const [line, prefix] of cases) {
    const { out } = await redact(line);
    assert.equal(out.includes(SECRET), false, `${line}: secret must be gone`);
    assert.ok(out.startsWith(prefix), `${line}: the name and scheme must survive`);
    assert.ok(out.includes(TOKEN_PREFIX), `${line}: a token must replace the value`);
  }
});

test("D3a: non-credential headers are left alone [GREEN NOW]", async () => {
  for (const line of [
    "Content-Type: application/json",
    "Accept: text/event-stream",
    "User-Agent: curl/8.4.0",
    // Deterministic id: a UUID's tail is caught by the entropy detector (`H`), which
    // is the known infrastructure false-positive tracked for the infrastructure
    // recognisers, not a header-layer concern.
    "X-Request-Id: req-0000000000000001",
    "Anthropic-Version: 2023-06-01",
  ]) {
    const { out } = await redact(line);
    assert.equal(out, line, `${line} must stay inert`);
  }
});

test("D3a: the header span covers exactly the value [GREEN NOW]", () => {
  const line = `  Authorization: Bearer ${SECRET}`;
  const [binding] = parseHeaderBindings(line);
  assert.ok(binding, "must parse");
  assert.equal(line.slice(binding.valueStart, binding.valueEnd), SECRET, "span is the value only");
  assert.equal(binding.syntax, "http-header");
  assert.equal(binding.scheme.toLowerCase(), "bearer");
  assert.ok(binding.evidence.includes("scheme_preserved"));
});

test("D3a: header round-trip is byte-identical [GREEN NOW]", async () => {
  const doc = [
    `Authorization: Bearer ${SECRET}`,
    "Content-Type: application/json",
    `x-api-key: ${SECRET}`,
  ].join("\n");
  const context = ctx();
  const out = await context.redactText(doc, FLAGS);
  assert.equal(out.includes(SECRET), false, "both values redacted");
  assert.equal(context.restoreText(out), doc, "restore reproduces the document");
});

test("D3a: the gateway's own transport headers are NOT redacted [GREEN NOW]", async () => {
  // The other level. A real upstream needs the real credential, so this path must stay
  // untouched; asserting it here prevents a future "fix" that redacts transport headers
  // and breaks every authenticated call.
  let seen = null;
  const fetchImpl = async (_u, init) => {
    seen = init.headers;
    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
  };
  const request = new Request("https://p/G$https://api.example/v1/chat/completions", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${SECRET}`,
      "x-api-key": SECRET,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({ model: "g", messages: [{ role: "user", content: `my key is ${SECRET}` }] }),
  });
  await handleRequest(request, {}, { fetchImpl, salt: "fixed" });

  const sent = seen instanceof Headers ? seen : new Headers(seen);
  assert.equal(sent.get("authorization"), `Bearer ${SECRET}`, "transport Authorization is forwarded verbatim");
  assert.equal(sent.get("x-api-key"), SECRET, "transport x-api-key is forwarded verbatim");
  assert.equal(sent.get("anthropic-version"), "2023-06-01", "provider headers are forwarded");
});

// ---------------------------------------------------------- 2. URL query ------

test("D3b: a sensitive query value is redacted, everything else survives [GREEN NOW]", async () => {
  const url = `https://api.example.com/v1/resource?page=2&access_token=${SECRET}&limit=10#section`;
  const { out } = await redact(`See ${url} for details`);
  assert.equal(out.includes(SECRET), false, "the secret must be gone");
  assert.ok(out.includes("?page=2&access_token="), "parameter order and name survive");
  assert.ok(out.includes("&limit=10#section"), "later parameters and the fragment survive");
  assert.ok(out.startsWith("See https://api.example.com/v1/resource?"), "the URL prefix survives");
});

test("D3b: the raw span is used, with no decode or re-encode [GREEN NOW]", async () => {
  // Percent-escapes, `+` and duplicate parameters must come out byte for byte. A
  // decode -> modify -> re-encode pipeline would normalise all three away.
  const encoded = "p%40ss+w%2Frd%3D%3D";
  const url = `https://x/?token=${encoded}&token=second#f`;
  const { out, ctx: context } = await redact(url);
  assert.equal(out.includes(encoded), false, "the raw value is what gets replaced");
  assert.equal(out.includes("&token=second"), false, "a duplicate parameter is redacted too, not skipped");
  assert.equal((out.match(/CRG_/g) || []).length, 2, "one token per occurrence");
  assert.ok(out.includes("&token="), "while the parameter structure survives");
  assert.equal(context.restoreText(out), url, "round-trip is byte-identical");

  const [binding] = parseUrlBindings(url);
  assert.equal(binding.raw, encoded, "the span holds the raw value, not a decoded one");
  assert.ok(binding.evidence.includes("raw_span_no_reencode"));
});

test("D3b: non-sensitive query parameters are left alone [GREEN NOW]", async () => {
  for (const url of [
    "https://example.com/docs?page=2&limit=10",
    "https://example.com/search?q=hello+world",
    "https://example.com/?sort=created_at",
  ]) {
    const { out } = await redact(url);
    assert.equal(out, url, `${url} must stay inert`);
  }
});

test("D3b: query names are matched after decoding the NAME only [GREEN NOW]", async () => {
  // The name may be percent-encoded; the VALUE must not be decoded.
  const url = "https://x/?access%5Ftoken=abc123def456";
  const [binding] = parseUrlBindings(url);
  assert.ok(binding, "an encoded name must still be recognised");
  assert.equal(binding.raw, "abc123def456", "and the value stays raw");
});

// --------------------------------------------------- 3. JSON url coverage -----

test("D3c: a JSON `url` field is scanned, not skipped [GREEN NOW]", async () => {
  // `shouldSkipString` used to return true for any `url` key, so the string never
  // reached redactText at all and the secret was forwarded verbatim.
  const body = { url: `https://api.example.com/?access_token=${SECRET}` };
  const out = await redactJson(body, ctx(), FLAGS);
  assert.equal(out.url.includes(SECRET), false, "the query secret must be gone");
  assert.ok(out.url.startsWith("https://api.example.com/?access_token="), "the URL prefix survives");
});

test("D3c: a nested image_url.url is scanned for query secrets [GREEN NOW]", async () => {
  const body = {
    messages: [{ role: "user", content: [{ type: "image_url", image_url: { url: "https://x/?token=abc123def456" } }] }],
  };
  const out = await redactJson(body, ctx(), FLAGS);
  const nested = out.messages[0].content[0].image_url.url;
  assert.equal(nested.includes("abc123def456"), false, "the nested query secret must be gone");
});

test("D3c: binary payload fields are still skipped [GREEN NOW]", async () => {
  // The reason `image_url` was in the skip list: it commonly carries a base64 data
  // URL, which is not text and must not be rewritten.
  const dataUrl = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
  const body = { image_url: dataUrl, b64_json: "iVBORw0KGgo=", input_audio: { data: "AAAA" } };
  const out = await redactJson(body, ctx(), FLAGS);
  assert.equal(out.image_url, dataUrl, "image_url payload untouched");
  assert.equal(out.b64_json, "iVBORw0KGgo=", "b64_json untouched");
  assert.equal(out.input_audio.data, "AAAA", "audio payload untouched");
});

test("D3c: JSON round-trip is byte-identical [GREEN NOW]", async () => {
  const body = {
    url: `https://api.example.com/?access_token=${SECRET}&x=1#f`,
    messages: [{ role: "user", content: `see https://y/?api_key=${SECRET}` }],
  };
  const context = ctx();
  const out = await redactJson(structuredClone(body), context, FLAGS);
  const serialized = JSON.stringify(out);
  assert.equal(serialized.includes(SECRET), false, "no secret survives");
  const restored = JSON.parse(serialized);
  const back = {
    url: context.restoreText(restored.url),
    messages: restored.messages.map((m) => ({ ...m, content: context.restoreText(m.content) })),
  };
  assert.deepEqual(back, body, "restore reproduces the payload");
});
