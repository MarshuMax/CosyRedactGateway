// R0.3 -- production context wiring.
//
// Two programmatic inputs were accepted by the layers below but never reached the request-side
// RedactionContext, and both gaps were easy to miss because each feature LOOKED wired:
//
//   foreignRegistry -- the RESPONSE path received it, so the G0.1 response E2E passed while
//     the FORWARD path still re-tokenised a foreign token it is supposed to preserve.
//   profile         -- RedactionContext honoured it, but handleRequest passed none, so a
//     deployment could not choose a profile through the production entry point at all.
//
// Every test here goes through handleRequest(). Testing RedactionContext directly is what
// allowed the gaps to survive this long: the unit is correct, the wiring is not.

import test from "node:test";
import assert from "node:assert/strict";
import {
  handleRequest,
  ForeignTokenRegistry,
  DEFAULT_PROFILE,
  DEVOPS_PROFILE,
} from "../worker.js";
import { readFileSync } from "node:fs";

const ACME_NS = { name: "acme", pattern: /(?<![A-Za-z0-9_])ACME_[A-Z0-9_]{4,}(?![A-Za-z0-9_])/, streamPrefix: "ACME_" };
const FOREIGN = "ACME_ABCDEF_0001";
// `H` is required for an infrastructure identifier: it is the entropy detector that claims a
// resource id, so a gitleaks-only route never sees one.
const FLAGS = "H";
const ALL_FLAGS = "HP SIBEG".replace(/ /g, "");

/** Send one chat request and return what the upstream actually received. */
async function forward(content, options = {}, flags = FLAGS) {
  let upstream = null;
  const fetchImpl = async (_u, init) => {
    upstream = JSON.parse(init.body);
    return new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: "ok" } }] }),
      { headers: { "content-type": "application/json" } });
  };
  const request = new Request(`https://proxy.example/${flags}$https://api.example/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "g", messages: [{ role: "user", content }] }),
  });
  const response = await handleRequest(request, {}, { fetchImpl, salt: "fixed", ...options });
  assert.equal(response.status, 200, `request failed: ${await response.text()}`);
  // Drop the injected notice, which is prefixed to the same message.
  const raw = upstream.messages[0].content;
  return raw.includes("\n\n") ? raw.slice(raw.indexOf("\n\n") + 2) : raw;
}

// -------------------------------------------------- 1. foreignRegistry on the way IN ----

test("R0.3: a registered foreign token survives the FORWARD path unchanged [RED]", async () => {
  const registry = new ForeignTokenRegistry([ACME_NS]);
  const sent = `DB_PASSWORD=${FOREIGN}`;
  const seen = await forward(sent, { foreignRegistry: registry });
  assert.equal(seen, sent, "the upstream must see the foreign token as it was written");
  assert.equal(/CRG_/.test(seen), false, "and this layer must not mint a token for it");
});

test("R0.3: without the registry the same value is governed by the ordinary detectors [RED]", async () => {
  // The counterpart, so the previous test cannot pass by the value simply being unremarkable.
  const sent = `DB_PASSWORD=${FOREIGN}`;
  const seen = await forward(sent);
  assert.notEqual(seen, sent, "with no registration it is an ordinary value");
  assert.match(seen, /^DB_PASSWORD=CRG_[A-Z0-9]+_[A-Z0-9]+$/, "and the strong key raises it");
});

test("R0.3: an unregistered foreign-looking value gets normal detector policy [RED]", async () => {
  // Registered in a DIFFERENT registry, so it is foreign-looking but not registered here.
  const other = new ForeignTokenRegistry([{ name: "other", pattern: /(?<![A-Za-z0-9_])OTHER_[A-Z0-9_]{4,}(?![A-Za-z0-9_])/ }]);
  const seen = await forward(`DB_PASSWORD=${FOREIGN}`, { foreignRegistry: other });
  assert.notEqual(seen, `DB_PASSWORD=${FOREIGN}`, "registration elsewhere does not protect it here");
  assert.match(seen, /CRG_/);
});

test("R0.3: a foreign token in prose is preserved in both directions [RED]", async () => {
  // Forward: preserved. Return: still preserved, not resolved (this layer holds no mapping).
  const registry = new ForeignTokenRegistry([ACME_NS]);
  const sent = `the value ${FOREIGN} is set elsewhere`;
  const seen = await forward(sent, { foreignRegistry: registry });
  assert.equal(seen, sent);

  let upstream = null;
  const fetchImpl = async (_u, init) => {
    upstream = JSON.parse(init.body);
    void upstream;
    return new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: `it is ${FOREIGN}` } }] }),
      { headers: { "content-type": "application/json" } });
  };
  const request = new Request(`https://proxy.example/${FLAGS}$https://api.example/v1/chat/completions`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "g", messages: [{ role: "user", content: sent }] }),
  });
  const response = await handleRequest(request, {}, { fetchImpl, salt: "fixed", foreignRegistry: registry });
  const body = await response.text();
  assert.ok(body.includes(FOREIGN), "the return path preserves it too");
});

// ------------------------------------------------------------- 2. profile wiring ------

test("R0.3: options.profile reaches the request-side context [RED]", async () => {
  // The same payload under two profiles, through handleRequest: the deployment choice has to
  // be observable, otherwise accepting the option is theatre.
  const doc = "instance: i-0a1b2c3d4e5f67890";
  const strict = await forward(doc, { profile: DEFAULT_PROFILE });
  const devops = await forward(doc, { profile: DEVOPS_PROFILE });

  assert.equal(strict.includes("i-0a1b2c3d4e5f67890"), false, "the default profile redacts a verified resource id");
  assert.match(strict, /^instance: CRG_/);
  assert.equal(devops, doc, "the devops profile preserves it");
});

test("R0.3: with no profile supplied the default is used [RED]", async () => {
  const doc = "instance: i-0a1b2c3d4e5f67890";
  const implicit = await forward(doc);
  const explicit = await forward(doc, { profile: DEFAULT_PROFILE });
  // The tokens differ by design: the request-id is per-request random, so byte equality is not
  // the property to compare (see the R0.2.1 invariants). The SHAPE of the outcome is.
  assert.match(implicit, /^instance: CRG_[A-Z0-9]+_[A-Z0-9]+$/, "absent means DEFAULT, not 'no policy'");
  assert.match(explicit, /^instance: CRG_[A-Z0-9]+_[A-Z0-9]+$/);
  assert.equal(
    implicit.replace(/CRG_[A-Z0-9]+_[A-Z0-9]+/, "CRG_X_X"),
    explicit.replace(/CRG_[A-Z0-9]+_[A-Z0-9]+/, "CRG_X_X"),
    "and the two outcomes are structurally identical"
  );
});

test("R0.3: no profile can release a hard credential [RED]", async () => {
  const secret = "wJalrXUtnFEMIK7MDENGbPxRfiCY";
  for (const profile of [DEFAULT_PROFILE, DEVOPS_PROFILE]) {
    const seen = await forward(`DB_PASSWORD=${secret}`, { profile });
    assert.equal(seen.includes(secret), false, "a credential is redacted under every profile");
    assert.match(seen, /CRG_/);
  }
  // ...and under the permissive profile the value IS restored on the way back.
  let upstream = null;
  const fetchImpl = async (_u, init) => {
    upstream = JSON.parse(init.body);
    const token = String(upstream.messages[0].content).match(/CRG_[A-Z0-9]+_[A-Z0-9]+/)[0];
    return new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: `it is ${token}` } }] }),
      { headers: { "content-type": "application/json" } });
  };
  const request = new Request(`https://proxy.example/${ALL_FLAGS}$https://api.example/v1/chat/completions`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "g", messages: [{ role: "user", content: `DB_PASSWORD=${secret}` }] }),
  });
  const response = await handleRequest(request, {}, { fetchImpl, salt: "fixed", profile: DEVOPS_PROFILE });
  assert.ok((await response.text()).includes(secret), "prose still restores under a permissive profile");
});

// ------------------------------------------------- 3. both together, and no env name ---

test("R0.3: the registry and the profile are independent inputs [RED]", async () => {
  const registry = new ForeignTokenRegistry([ACME_NS]);
  const doc = ["instance: i-0a1b2c3d4e5f67890", `DB_PASSWORD=${FOREIGN}`].join("\n");
  const seen = await forward(doc, { foreignRegistry: registry, profile: DEVOPS_PROFILE });
  assert.equal(seen, doc, "the profile preserves the resource id and the registry preserves the foreign token");
});

test("R0.3: no new environment variable was invented for the profile [GREEN NOW]", () => {
  // The slice deliberately stops at the programmatic path. Exposing REDACT_INFRA_PROFILE (or
  // similar) is a deployment-configuration decision for a later hardening pass, not something
  // to smuggle in here.
  const src = readFileSync(new URL("../worker.js", import.meta.url), "utf8");
  const envNames = [...new Set([...src.matchAll(/env\?\.([A-Z_]+)/g)].map((m) => m[1]))];
  assert.deepEqual(
    envNames.filter((n) => /PROFILE|INFRA/.test(n)), [],
    `an env var for the profile was added: ${JSON.stringify(envNames)}`
  );
  // The programmatic inputs are the ones that must work.
  assert.ok(src.includes("maxRedactions,foreignRegistry,profile:options.profile"),
    "handleRequest must pass both through to the context");
});
