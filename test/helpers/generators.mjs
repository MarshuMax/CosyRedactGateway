// R1 -- deterministic generators for security-property testing.
//
// These build STRUCTURED inputs, not random bytes: a security property that only holds for
// random noise is not interesting. Each generator composes the shapes the gateway actually
// processes (assignments, references, host syntax, credentials, infrastructure identifiers),
// and the composition itself is drawn from the seeded RNG so a failure is reproducible.

import { makeRng } from "./property.mjs";

// Credentials chosen so a detector really claims them. A fixture secret that no rule matches
// would make every property vacuously true -- the failure mode this whole session kept hitting.
export const CREDENTIALS = Object.freeze([
  "wJalrXUtnFEMIK7MDENGbPxRfiCY",                 // AWS secret access key shape
  // NOT `AKIAIOSFODNN7EXAMPLE`: the gitleaks rule carries allowRegexes:[/.+EXAMPLE$/] for that
  // exact placeholder, so a rule that is working correctly reports nothing for it. Using it as a
  // "must be caught" fixture produces a property failure that says nothing about the gateway.
  "AKIAZ3Q7X2N5M8P4R6T1",                          // AWS access key id, not allowlisted
  "ghp_16C7e42F292c6912E7710c838347Ae178B4a",      // GitHub PAT
  "cGFzc3dvcmQxMjM0NTY3OA==",                      // base64 blob
  "Pr0d-P@ssw0rd-Xy9Zk2mQ",                        // symbol-bearing password
  // Built at runtime rather than written out: a literal `sk_live_…` is itself a Stripe
  // secret-scanning signature, so committing one trips push protection and every future push
  // fails. What matters for the test is only that the DETECTOR sees this shape.
  "sk_" + "live_" + "51H8xQ2KZvN9pQrStUvWxYzAb",
]);

// Values that LOOK like this layer's token but were never minted by the request.
export const UNREGISTERED_TOKENS = Object.freeze([
  "CRG_AAAA_AAAA",
  "CRG_UNKNOWN_0001",
  "CRG_123456_9999",
]);

// Infrastructure identifiers, mixed certainty.
export const INFRA_VALUES = Object.freeze([
  "i-0a1b2c3d4e5f67890",
  "subnet-0a1b2c3d4e5f67890",
  "sg-0a1b2c3d4e5f67890",
  "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
  "4bf92f3577b34da6a3ce929d0e0e4736",
  "sha256:7031c1b283388d2c2e09b57badb803c05ebed362dc88d84b480cc47f72a21097",
  "arn:aws:iam::123456789012:role/eks-nodegroup-role",
]);

export const STRONG_KEYS = Object.freeze([
  "DB_PASSWORD", "PASSWORD", "SECRET_KEY", "API_TOKEN", "ACCESS_TOKEN", "PRIVATE_KEY", "VAULT_TOKEN",
]);

export const WEAK_KEYS = Object.freeze(["cache_key", "commit", "trace_id", "instance", "notes", "image", "blob"]);

export const SEPARATORS = Object.freeze(["=", ": ", " = ", "= "]);

/** Reference constructs, including the ones the scanner is known to size correctly. */
export const REFERENCES = Object.freeze([
  "${SECRET}", "${{ secrets.DB_PASSWORD }}", "{{ vault_password }}", "$(op read op://vault/db/pw)",
  "%DB_PASSWORD%", "<DB_PASSWORD>", "{db_password}", "${{ a: {b:1} }}", "${{a:{b:{c:1}}}}",
]);

// Surrounding host syntax, so a property is exercised with quotes and comments present.
export const WRAPPERS = Object.freeze([
  (v) => v,
  (v) => `"${v}"`,
  (v) => `'${v}'`,
  (v) => `${v}  # rotate quarterly`,
  (v) => `"${v}"  # note`,
  (v) => `  ${v}  `,
]);

/** A random line that MIGHT carry a secret: key, separator, value, optional wrapper. */
export function genAssignment(rng) {
  const strong = rng.bool(0.7);
  const key = rng.pick(strong ? STRONG_KEYS : WEAK_KEYS);
  const roll = rng.float();
  let value;
  if (roll < 0.4) value = rng.pick(CREDENTIALS);
  else if (roll < 0.6) value = rng.pick(INFRA_VALUES);
  else if (roll < 0.75) value = rng.pick(UNREGISTERED_TOKENS);
  else if (roll < 0.9) value = rng.pick(REFERENCES);
  else value = rng.pick(["hunter2", "changeme", "aGVsbG8=", "plain-text-value"]);
  const sep = rng.pick(SEPARATORS);
  const wrap = rng.pick(WRAPPERS);
  return `${key}${sep}${wrap(value)}`;
}

/** Several lines joined, so multi-line structure and block scalars appear. */
export function genDocument(rng, minLines = 1, maxLines = 4) {
  const n = rng.int(minLines, maxLines);
  const lines = [];
  for (let i = 0; i < n; i++) {
    if (rng.bool(0.12)) lines.push(`${rng.pick(WEAK_KEYS)}: |`);
    if (rng.bool(0.08)) lines.push("");
    if (rng.bool(0.06)) lines.push("# a comment line");
    lines.push(genAssignment(rng));
  }
  return lines.join("\n");
}

/** A K8s Secret document, whose `data` values get base64 surrogates. */
export function genK8sSecret(rng) {
  const key = rng.pick(["password", "token", "api-key"]);
  const value = rng.pick(["cGFzc3dvcmQxMjM0NTY3OA==", "dG9rZW4tYWJjZGVmZ2g=", "aGVsbG8td29ybGQ="]);
  return ["apiVersion: v1", "kind: Secret", "metadata:", "  name: app", "data:", `  ${key}: ${value}`].join("\n");
}

/** Round-trip workload: an input plus the flag set to run it under. */
export function genWorkload(rng) {
  const roll = rng.float();
  const text = roll < 0.15 ? genK8sSecret(rng) : genDocument(rng);
  const flags = {
    gitleaks: true,
    highEntropy: rng.bool(0.85),
    email: rng.bool(0.5),
    phone: rng.bool(0.4),
    secret: rng.bool(0.5),
    identity: rng.bool(0.4),
    bank: rng.bool(0.4),
  };
  return { text, flags };
}

export { makeRng };
