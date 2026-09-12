// R3-BODY-002 -- the reference containment filter, and the invariant that made it removable.
//
// What happened: referenceEnvelopes() ended with
//
//   out.filter((env) => !out.some((other) => ... contains ...))
//
// which is O(|out|^2). On a document with one reference construct per line -- ordinary config text
// -- that was 9.5 seconds out of 9.8 at 4 MiB, 97% of the function, and it removed nothing.
//
// Why it removed nothing: on success the scanner sets `i = envelope.end`, and on failure it advances
// `i` by one without pushing. Every pushed envelope therefore starts at or after the previous one's
// end, so the output is sorted and strictly DISJOINT. Containment needs overlap, so containment is
// impossible.
//
// These tests pin the INVARIANT rather than the deletion, so a future change that reintroduces
// overlap fails here rather than silently becoming quadratic again.

import test from "node:test";
import assert from "node:assert/strict";
import { referenceEnvelopes, findSensitiveSpans } from "../worker.js";

const shapes = (env) => env.map((e) => [e.start, e.end, e.opener]);

/** The invariant the deleted filter depended on. */
function assertSortedDisjoint(text, envs) {
  for (let i = 0; i < envs.length; i++) {
    assert.ok(envs[i].end > envs[i].start, `empty/negative envelope in ${JSON.stringify(text)}`);
    if (i > 0) {
      assert.ok(
        envs[i].start >= envs[i - 1].end,
        `envelopes must be disjoint and sorted; ${JSON.stringify(text)} has [${envs[i - 1].start},${envs[i - 1].end}] then [${envs[i].start},${envs[i].end}]`
      );
    }
  }
}

test("R3-BODY-002: envelopes are sorted and strictly disjoint [GREEN NOW]", () => {
  const cases = [
    "", "plain text", "${A}", "${A}${B}", "${A}${B}${C}${D}",
    "${{ a: {b:1}}}", "${${${x}}}", "{{x}", "${({}", "${a} {{b}} %C% <D> {e}",
    "}}}${a}", "${unclosed and then ${valid}", "%A%${b}%C%", "{{{}}}", "${${}}", "$($())",
    "CRG_AAAAAA_0001 ${A} CRG_AAAAAA_0002", "${\n  a: 1\n}",
    Array.from({ length: 200 }, (_, i) => `k${i}: "\${V_${i}}"`).join("\n"),
  ];
  for (const text of cases) assertSortedDisjoint(text, referenceEnvelopes(text));
});

test("R3-BODY-002: the one-construct-per-line corpus stays disjoint at scale [GREEN NOW]", () => {
  // The shape that exposed the quadratic filter.
  const lines = Array.from({ length: 2000 }, (_, i) => `service_${i}: { host: svc-${i}.internal, port: ${1000 + i}, password: "\${VAULT_${i}}" }`);
  const text = lines.join("\n");
  const envs = referenceEnvelopes(text);
  assert.equal(envs.length, 2000, "one envelope per line");
  assertSortedDisjoint(text, envs);
});

test("R3-BODY-002: no envelope is contained in another, over the exhaustive short corpus [GREEN NOW]", () => {
  // The deleted filter's only job. Every string of length 0..5 on a 10-character alphabet.
  const ALPHA = ["{", "}", "$", "(", ")", "%", "<", ">", "x", "_"];
  let checked = 0;
  const walk = (prefix, depth) => {
    if (depth === 0) {
      const envs = referenceEnvelopes(prefix);
      checked++;
      for (const env of envs) {
        for (const other of envs) {
          if (other === env) continue;
          const contains = other.start <= env.start && other.end >= env.end && (other.end - other.start) > (env.end - env.start);
          assert.equal(contains, false, `${JSON.stringify(prefix)}: [${other.start},${other.end}] contains [${env.start},${env.end}]`);
        }
      }
      return;
    }
    for (const ch of ALPHA) walk(prefix + ch, depth - 1);
  };
  for (let L = 0; L <= 5; L++) walk("", L);
  // 10^0 + ... + 10^5 = 111111. An earlier version wrote 0..4 and expected 111111, which is the
  // count for 0..5 -- the assertion was right for the corpus I meant to build, not the one I built.
  assert.equal(checked, 111111, "the exhaustive corpus is the expected size");
});

test("R3-BODY-002: the nested case yields a single envelope, not a contained pair [GREEN NOW]", () => {
  // The nearest thing to a counterexample: the balanced scan consumes the inner construct, so there
  // is no inner envelope left for an outer one to contain.
  assert.deepEqual(shapes(referenceEnvelopes("${{ a: {b:1}}}")), [[0, 14, "${{"]]);
});

test("R3-BODY-002: a many-construct document is linear, not quadratic [GREEN NOW]", () => {
  // A BOUNDED reproducer for the ordinary suite. The heavy sweep stays in perf:redos; this only has
  // to fail loudly if the quadratic term comes back.
  //
  // Correctness alone cannot catch this: the deleted filter never changed the RESULT, so every
  // assertion above passed while the function was 36x slower than it needed to be. Only a timing
  // check can, which is why one lives in the ordinary suite at a size that costs milliseconds.
  const mk = (lines) => Array.from({ length: lines }, (_, i) => `k${i}: "\${V_${i}}"`).join("\n");
  const small = mk(2000);
  const large = mk(8000); // 4x the construct count
  const time = (text) => {
    const t0 = process.hrtime.bigint();
    referenceEnvelopes(text);
    return Number(process.hrtime.bigint() - t0) / 1e6;
  };
  time(small); // warm
  const t1 = time(small);
  const t2 = time(large);
  // 4x the input: linear expects ~4x, the deleted quadratic term gave ~16x. 12 leaves room for
  // scheduler noise while still failing on any return of the quadratic behaviour.
  assert.ok(
    t2 < Math.max(t1 * 12, 50),
    `4x the constructs took ${(t2 / Math.max(t1, 1e-3)).toFixed(1)}x the time (${t1.toFixed(1)}ms -> ${t2.toFixed(1)}ms); a quadratic containment step is back`
  );
});

// =====================================================================================
// R3-BODY-004 -- the three disjoint fast paths, and the argument each one rests on
// =====================================================================================

test("R3-BODY-004: disjoint implies no CONTAINMENT only when no span is zero-width [GREEN NOW]", () => {
  // The containment fast path is argued from "disjoint => no containment". That argument is FALSE
  // for zero-width spans, because the inner test is bounds-containment while disjointness is
  // established with overlaps():
  //
  //   outer [0,5], inner [0,0]  -> the legacy code absorbs [0,0], yet overlaps() says false
  //   outer [0,5], inner [5,5]  -> same, at the right boundary
  //
  // Exhaustive over every bounds pair in a small range, so the guard's justification is checked
  // rather than asserted.
  const overlaps = (a, b) => a.start < b.end && a.end > b.start;
  const contains = (outer, inner) => inner !== outer
    && inner.start >= outer.start && inner.end <= outer.end
    && !(inner.start === outer.start && inner.end === outer.end);
  let violations = 0;
  let zeroWidthViolations = 0;
  for (let i = 0; i < 8; i++) for (let j = i; j < 8; j++) {
    for (let a = 0; a < 8; a++) for (let b = a; b < 8; b++) {
      const outer = { start: i, end: j };
      const inner = { start: a, end: b };
      if (outer.start === inner.start && outer.end === inner.end) continue;
      if (overlaps(outer, inner) || !contains(outer, inner)) continue;
      // A containment exists despite disjointness -> the only escape must be zero width.
      if (outer.start === outer.end || inner.start === inner.end) zeroWidthViolations++;
      else violations++;
    }
  }
  assert.equal(violations, 0, "no NON-zero-width pair may be contained while disjoint");
  assert.ok(zeroWidthViolations > 0, "and zero-width pairs must be exactly the ones that are, which is why the guard exists");
});

test("R3-BODY-004: the disjoint detectors agree with a pairwise overlaps oracle [GREEN NOW]", () => {
  // The same entry condition guards the containment merge, the selected-overlap pass and the final
  // remerge. It sorts by start with END ASC as an explicit tie-break and tests next.start >= prev.end;
  // END ASC is load-bearing because overlaps() has its own behaviour at equal starts and zero widths.
  const overlaps = (a, b) => a.start < b.end && a.end > b.start;
  const oracleDisjoint = (spans) => {
    for (let i = 0; i < spans.length; i++) {
      for (let j = i + 1; j < spans.length; j++) if (overlaps(spans[i], spans[j])) return false;
    }
    return true;
  };
  const detectorDisjoint = (spans) => {
    const byStart = spans.slice().sort((a, b) => a.start - b.start || a.end - b.end);
    for (let i = 1; i < byStart.length; i++) if (byStart[i].start < byStart[i - 1].end) return false;
    return true;
  };
  const shapes = [
    [{ start: 0, end: 10 }, { start: 5, end: 5 }],
    [{ start: 0, end: 10 }, { start: 0, end: 0 }],
    [{ start: 0, end: 10 }, { start: 10, end: 10 }],
    [{ start: 5, end: 5 }, { start: 5, end: 5 }],
    [{ start: 5, end: 5 }, { start: 5, end: 10 }],
    [{ start: 5, end: 10 }, { start: 5, end: 10 }],
    [{ start: 0, end: 5 }, { start: 5, end: 10 }],
    [{ start: 1, end: 1 }, { start: 2, end: 2 }, { start: 3, end: 3 }],
    [],
  ];
  for (const spans of shapes) {
    assert.equal(detectorDisjoint(spans), oracleDisjoint(spans), `verdict differs for ${JSON.stringify(spans)}`);
  }
  // Seeded.
  let seed = 0x5151abcd;
  const rnd = () => { seed ^= seed << 13; seed >>>= 0; seed ^= seed >> 17; seed ^= seed << 5; seed >>>= 0; return seed / 4294967296; };
  for (let i = 0; i < 50000; i++) {
    const n = Math.floor(rnd() * 5);
    const spans = [];
    for (let j = 0; j < n; j++) { const s = Math.floor(rnd() * 12); spans.push({ start: s, end: s + Math.floor(rnd() * 5) }); }
    assert.equal(detectorDisjoint(spans), oracleDisjoint(spans), `verdict differs for ${JSON.stringify(spans)}`);
  }
});

test("R3-BODY-004: the span pipeline stays linear in span density [GREEN NOW]", () => {
  // Correctness cannot catch this class of defect: all three fast paths replaced passes that
  // PROVABLY reproduced their own input, so every semantic assertion passed while the pipeline was
  // quadratic. Only a scaling check can, which is why a bounded one lives in the ordinary suite.
  //
  // Regression it pins: at m=16000 this corpus took 8785.8ms with a rising us/span curve. After the
  // three fast paths it is ~334ms with us/span FALLING.
  const mk = (m) => Array.from({ length: m }, (_, i) => `cfg_${i}: { cred: "wJalrXUtnFEMI${String(i).padStart(8, "0")}" }`).join(String.fromCharCode(10));
  const time = (text) => {
    const t0 = process.hrtime.bigint();
    findSensitiveSpans(text, { gitleaks: true, highEntropy: true, email: true });
    return Number(process.hrtime.bigint() - t0) / 1e6;
  };
  const small = mk(2000);
  const large = mk(8000);
  time(small);
  const t1 = time(small);
  const t2 = time(large);
  // 4x the spans. Linear is ~4x; the quadratic passes gave ~9-16x. 8 leaves room for noise and still
  // fails loudly on any return of quadratic behaviour.
  assert.ok(
    t2 < Math.max(t1 * 8, 80),
    `4x the span density took ${(t2 / Math.max(t1, 1e-3)).toFixed(1)}x the time (${t1.toFixed(1)}ms -> ${t2.toFixed(1)}ms); a quadratic span pass is back`
  );
});
