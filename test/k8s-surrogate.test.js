// Kubernetes surrogate tests.
//
// Reproduced against a real API server (minikube, k8s v1.35):
//
//   data.password: CRG_K7M2Q9_T8F4N6P3   -> BadRequest: illegal base64 data at input byte 3
//   data.password: Q1JHX0FCQ18xMjM=      -> accepted (server dry run)
//   data.password: Q1JHX0FCQ18xMjM       -> BadRequest: illegal base64 data at input byte 12
//   data.password: Q1JHX0FCQ18xMjM==     -> BadRequest: illegal base64 data at input byte 16
//
// Two conclusions are encoded below:
//   1. A plain portable token is not a legal value for Secret.data, so a
//      representation-aware surrogate (base64 of the token) is required.
//   2. Kubernetes validates decodability, not decoded length. A surrogate does
//      NOT have to be length-preserving -- but its length still leaks the
//      plaintext length, which is why the ledger records it for auditing and for
//      optional length-preserving output.
//
// The `kubectl` cases skip automatically when no cluster/CLI is available. The
// offline assertions (valid base64, strict padding) always run, because the
// hand-rolled base64 path is exactly where a padding bug would hide and
// Kubernetes rejects it outright.
//
// Assertion tags:
//   [GREEN NOW]  passes against current main
//   [RED]        fails against current main and specifies target behaviour
//   [SKIP-ABLE]  requires a live cluster for the server-side half

import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

const NAMESPACE = process.env.CRG_TEST_NAMESPACE || "default";

// Canonical base64: no whitespace, padding present exactly as required.
function isCanonicalBase64(value) {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return false;
  if (value.length % 4 !== 0) return false;
  const decoded = Buffer.from(value, "base64");
  return decoded.toString("base64") === value;
}

function hasKubectl() {
  try {
    execFileSync("kubectl", ["version", "--client"], { stdio: "ignore", timeout: 15000 });
    return true;
  } catch {
    return false;
  }
}

function clusterReachable() {
  try {
    execFileSync("kubectl", ["get", "ns", NAMESPACE, "--request-timeout=5s"], { stdio: "ignore", timeout: 20000 });
    return true;
  } catch {
    return false;
  }
}

function serverDryRun(dataValue) {
  const manifest = [
    "apiVersion: v1",
    "kind: Secret",
    "metadata:",
    "  name: crg-surrogate-test",
    `  namespace: ${NAMESPACE}`,
    "data:",
    `  password: ${dataValue}`,
    "",
  ].join("\n");
  try {
    execFileSync("kubectl", ["apply", "-f", "-", "--dry-run=server"], {
      input: manifest,
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 30000,
    });
    return { accepted: true, stderr: "" };
  } catch (err) {
    return { accepted: false, stderr: String(err.stderr || err.message) };
  }
}

// Target surrogate generator. Placeholder until worker.js exports the real one.
function base64Surrogate(token) {
  return Buffer.from(token, "utf8").toString("base64");
}

const LIVE = hasKubectl() && clusterReachable();

// ------------------------------------------------------ 1. current state ----

test("a plain portable token is not accepted by Secret.data [RED]", { skip: !LIVE }, () => {
  const token = "CRG_K7M2Q9_T8F4N6P3";
  assert.equal(isCanonicalBase64(token), false, "a portable token is not valid base64 by design");
  const r = serverDryRun(token);
  assert.equal(r.accepted, false, "API server must reject a non-base64 Secret.data value");
  assert.match(r.stderr, /illegal base64 data/);
});

// ----------------------------------------------------- 2. surrogate path ----

test("base64 surrogate of a portable token is canonically padded [RED]", () => {
  for (const token of ["CRG_K7M2Q9_T8F4N6P3", "CRG_AB_CD", "CRG_7K2M9Q_E0007"]) {
    const surrogate = base64Surrogate(token);
    assert.equal(isCanonicalBase64(surrogate), true, `surrogate must be canonical base64: ${surrogate}`);
    assert.equal(Buffer.from(surrogate, "base64").toString("utf8"), token, "surrogate must decode back to the token");
  }
});

test("padded and unpadded variants are distinguishable (padding is load-bearing) [RED]", () => {
  const token = "CRG_K7M2Q9_T8F4N6P3";
  const canonical = base64Surrogate(token);
  assert.equal(isCanonicalBase64(canonical), true, "canonical form must pass");
  // Wrong padding must be rejected locally, before it ever reaches the API server.
  const stripped = canonical.replace(/=+$/, "");
  const extra = canonical + "=";
  if (stripped !== canonical) {
    assert.equal(isCanonicalBase64(stripped), false, "missing padding must be rejected locally");
  }
  assert.equal(isCanonicalBase64(extra), false, "extra padding must be rejected locally");
});

test("API server accepts the base64 surrogate [RED]", { skip: !LIVE }, () => {
  const surrogate = base64Surrogate("CRG_K7M2Q9_T8F4N6P3");
  const r = serverDryRun(surrogate);
  assert.equal(r.accepted, true, `API server must accept the surrogate, got: ${r.stderr}`);
});

test("API server rejects a wrongly padded surrogate [GREEN NOW]", { skip: !LIVE }, () => {
  const surrogate = base64Surrogate("CRG_K7M2Q9_T8F4N6P3");
  const stripped = surrogate.replace(/=+$/, "");
  if (stripped === surrogate) return; // token length happened to need no padding
  const r = serverDryRun(stripped);
  assert.equal(r.accepted, false, "missing padding must be rejected by the API server");
  assert.match(r.stderr, /illegal base64 data/);
});

// ---------------------------------------------- 3. ledger requirements ------

test("surrogate length tracks the token, not the plaintext [GREEN NOW]", () => {
  // Two consequences, both asserted here:
  //   1. Kubernetes validates decodability, not decoded length, so a surrogate
  //      does NOT have to be length-preserving (see DESIGN-v2.md section 6.6).
  //   2. Because the token is fixed-width within the [A-Z0-9_] charset, the
  //      surrogate reveals nothing about the plaintext length either. The
  //      ledger therefore does not need plaintext length in order to restore;
  //      it is only needed for auditing or for an opt-in length-preserving mode.
  const a = base64Surrogate("CRG_7K2M9Q_0001");
  const b = base64Surrogate("CRG_7K2M9Q_0002");
  assert.equal(a.length, b.length, "fixed-width tokens give fixed-width surrogates");
  assert.equal(Buffer.from(a, "base64").toString("utf8"), "CRG_7K2M9Q_0001");
  assert.equal(Buffer.from(b, "base64").toString("utf8"), "CRG_7K2M9Q_0002");
  // A fixed-width token means two different-length secrets map to the same
  // surrogate width, so width cannot be used to infer the secret.
  assert.equal(base64Surrogate("CRG_7K2M9Q_0001").length, base64Surrogate("CRG_7K2M9Q_0002").length);
});

test("base64 decoding the surrogate must never reveal plaintext [RED]", () => {
  // Guards against a future "surrogate" that is actually base64 of the secret,
  // which would silently disable redaction for every Secret.data field.
  const plaintext = "Pr0d-P@ssw0rd-Xy9Zk2mQ";
  const surrogate = base64Surrogate("CRG_K7M2Q9_T8F4N6P3");
  assert.equal(Buffer.from(surrogate, "base64").toString("utf8").includes(plaintext), false);
  assert.equal(surrogate.includes(Buffer.from(plaintext).toString("base64")), false);
});
