import { describe, expect, it } from "vitest";

import {
  ALL_STATIC_PROBES,
  CONCATENATION_TEMPLATE,
  CONCATENATORS,
  JSON_KEY_TEMPLATE,
  JSON_VALUE_TEMPLATE,
  LANGUAGE_PROBES,
  MAGIC_VALUES,
  MONGO_TEMPLATE,
  NGINX_ALIAS_TEMPLATE,
  TRANSFORM_DECODE_PAYLOADS,
  TRANSFORM_METACHARACTERS,
  corruptMagicValue,
} from "../src/probes/catalogue.ts";
import { equalisePair, padNumericLiteral, padWithFiller } from "../src/probes/pad.ts";
import { QUERY_VALUE_CODEC } from "../src/request/codecs.ts";
import { asciiBytes as bytes } from "../src/request/template.ts";
import type { ProbePair } from "../src/probes/types.ts";

function allEscapeMembers(pair: ProbePair): string[] {
  return pair.escapeSets.flatMap((set) => [...set]);
}

function lengths(values: readonly string[]): number[] {
  return [...new Set(values.map((v) => v.length))].sort((a, b) => a - b);
}

describe("catalogue structural invariants", () => {
  it("has unique probe ids", () => {
    const ids = ALL_STATIC_PROBES.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("never has an empty break list", () => {
    for (const pair of ALL_STATIC_PROBES) {
      expect(pair.breaks.length, pair.id).toBeGreaterThan(0);
    }
  });

  it("never has an empty escape set or an empty alternative within a set", () => {
    // The original engine indexed into the escape list without checking, so a pair defined
    // with no escapes would have thrown at scan time.
    for (const pair of ALL_STATIC_PROBES) {
      expect(pair.escapeSets.length, pair.id).toBeGreaterThan(0);
      for (const set of pair.escapeSets) {
        expect(set.length, `${pair.id} has an empty alternative set`).toBeGreaterThan(0);
        for (const member of set) {
          expect(member.length, `${pair.id} has a zero-length escape`).toBeGreaterThan(0);
        }
      }
    }
  });

  it("never uses the same string as both a break and an escape", () => {
    // Such a pair can never produce evidence: both arms send identical bytes.
    for (const pair of ALL_STATIC_PROBES) {
      const escapes = new Set(allEscapeMembers(pair));
      for (const brk of pair.breaks) {
        expect(escapes.has(brk), `${pair.id}: ${JSON.stringify(brk)} is both arms`).toBe(
          false,
        );
      }
    }
  });

  it("declares a delimiter exactly for the pairs that identify one", () => {
    for (const pair of ALL_STATIC_PROBES) {
      if (pair.delimiter !== undefined) {
        expect(pair.stage, pair.id).toBe("delimiter");
      }
    }
  });

  it("disables the random anchor for value-shape-sensitive stages", () => {
    // Inserting a random alphanumeric anchor between the value and the payload destroys a
    // numeric or identifier context, so arithmetic, order-by and path families must not.
    for (const pair of ALL_STATIC_PROBES) {
      if (
        pair.stage === "arithmetic" ||
        pair.stage === "order-by" ||
        pair.stage === "path"
      ) {
        expect(pair.anchor, `${pair.id} must not use an anchor`).toBe(false);
      }
    }
  });
});

describe("catalogue length-parity claims are truthful", () => {
  it('pairs claiming "equal" really are all the same length', () => {
    for (const pair of ALL_STATIC_PROBES) {
      if (pair.parity !== "equal") continue;
      const all = [...pair.breaks, ...allEscapeMembers(pair)];
      expect(lengths(all), `${pair.id} claims equal parity`).toHaveLength(1);
    }
  });

  it('pairs claiming "pad-filler" are within a small, closable delta', () => {
    // A large delta means padding would dominate the payload and change its character; such
    // a pair should be marked impossible and handled by length neutralisation instead.
    for (const pair of ALL_STATIC_PROBES) {
      if (pair.parity !== "pad-filler") continue;
      const all = [...pair.breaks, ...allEscapeMembers(pair)];
      const spread = Math.max(...all.map((v) => v.length)) - Math.min(...all.map((v) => v.length));
      expect(spread, `${pair.id} spread`).toBeLessThanOrEqual(6);
    }
  });

  it('pairs claiming "impossible" genuinely cannot be equalised meaningfully', () => {
    const impossible = ALL_STATIC_PROBES.filter((p) => p.parity === "impossible");
    expect(impossible.map((p) => p.id)).toEqual([
      "delim.backslash",
      "path.dotslash-normalised",
    ]);
  });

  it("every break/escape combination can be equalised or is explicitly exempt", () => {
    for (const pair of ALL_STATIC_PROBES) {
      const strategy =
        pair.parity === "pad-numeric"
          ? "numeric"
          : pair.parity === "pad-filler"
            ? "filler"
            : "none";
      for (const brk of pair.breaks) {
        for (const esc of allEscapeMembers(pair)) {
          const result = equalisePair(brk, esc, strategy);
          if (pair.parity === "equal") {
            expect(result.equal, `${pair.id}`).toBe(true);
            expect(result.strategy).toBe("none");
          } else if (pair.parity !== "impossible") {
            expect(result.equal, `${pair.id}: ${brk} vs ${esc}`).toBe(true);
            expect(result.breakPayload.length).toBe(result.escapePayload.length);
          }
        }
      }
    }
  });
});

describe("language probes", () => {
  it("has unique ids", () => {
    const ids = LANGUAGE_PROBES.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("puts the cheap generic gate first so aborting the cascade is actually cheap", () => {
    // In the original this sat at index 5, so Ruby, Python, JavaScript and shell were each
    // fully probed before the gate that aborts on "no function call evaluates" could fire.
    expect(LANGUAGE_PROBES[0]!.id).toBe("fn.basic");
  });

  it("never reuses the valid call as one of its own invalid variants", () => {
    for (const probe of LANGUAGE_PROBES) {
      expect(probe.invalid, probe.id).not.toContain(probe.valid);
    }
  });

  it("has at least two invalid variants per language", () => {
    // One misspelling can coincidentally be a real symbol in some other language; two
    // independent misspellings that both fail is much stronger evidence.
    for (const probe of LANGUAGE_PROBES) {
      expect(probe.invalid.length, probe.id).toBeGreaterThanOrEqual(2);
    }
  });

  it("can equalise every valid/invalid combination", () => {
    for (const probe of LANGUAGE_PROBES) {
      for (const invalid of probe.invalid) {
        const result = equalisePair(invalid, probe.valid, probe.padNumeric ? "numeric" : "filler");
        expect(result.equal, `${probe.id}: ${invalid} vs ${probe.valid}`).toBe(true);
        expect(result.breakPayload.length).toBe(result.escapePayload.length);
      }
    }
  });

  it("marks padNumeric only where a numeric literal exists to widen", () => {
    for (const probe of LANGUAGE_PROBES) {
      if (probe.padNumeric) {
        expect(padNumericLiteral(probe.valid, 1), probe.id).toBeDefined();
      }
    }
  });

  it("sets padNumeric false exactly where lengths already match", () => {
    for (const probe of LANGUAGE_PROBES) {
      const equal = lengths([probe.valid, ...probe.invalid]).length === 1;
      expect(probe.padNumeric, `${probe.id} equal=${equal}`).toBe(!equal);
    }
  });
});

describe("templated probes", () => {
  it("concatenation pairs are equalisable for every delimiter and operator", () => {
    // Not equal as written: the break carries one extra filler byte. What matters is that
    // runtime equalisation closes the gap for every combination, including multi-character
    // operators and a backslash delimiter.
    for (const delimiter of ["'", '"', "`", "\\"]) {
      for (const concat of CONCATENATORS) {
        const pair = CONCATENATION_TEMPLATE.build({ delimiter, concat });
        expect(pair.parity, `${delimiter}${concat}`).toBe("pad-filler");
        for (const brk of pair.breaks) {
          for (const esc of allEscapeMembers(pair)) {
            const result = equalisePair(brk, esc, "filler");
            expect(result.equal, `${delimiter}${concat}: ${brk} vs ${esc}`).toBe(true);
            expect(result.breakPayload.length).toBe(result.escapePayload.length);
          }
        }
      }
    }
  });

  it("concatenation ids are unique across all delimiter and operator combinations", () => {
    const ids = new Set<string>();
    for (const delimiter of ["'", '"', "`", "\\", ",", "+"]) {
      for (const concat of CONCATENATORS) {
        ids.add(CONCATENATION_TEMPLATE.build({ delimiter, concat }).id);
      }
    }
    expect(ids.size).toBe(6 * CONCATENATORS.length);
  });

  it("json templates are length-clean", () => {
    for (const delimiter of ["'", '"']) {
      for (const template of [JSON_VALUE_TEMPLATE, JSON_KEY_TEMPLATE]) {
        const pair = template.build({ delimiter });
        expect(lengths([...pair.breaks, ...allEscapeMembers(pair)]), template.id).toHaveLength(1);
      }
    }
  });

  it("mongo template is length-clean", () => {
    const pair = MONGO_TEMPLATE.build({ prefix: "z','$where':", suffix: "" });
    expect(lengths([...pair.breaks, ...allEscapeMembers(pair)])).toHaveLength(1);
  });

  it("nginx alias template produces distinct escapes even for a one-character value", () => {
    // The original derived escapes by mutating the first and last character of the value,
    // which for a single-character value produced two identical strings.
    const pair = NGINX_ALIAS_TEMPLATE.build({ baseValue: "a" });
    const escapes = allEscapeMembers(pair);
    expect(new Set(escapes).size, JSON.stringify(escapes)).toBe(escapes.length);
  });

  it("nginx alias template handles an empty value without producing empty payloads", () => {
    const pair = NGINX_ALIAS_TEMPLATE.build({ baseValue: "" });
    for (const member of allEscapeMembers(pair)) {
      expect(member.length).toBeGreaterThan(0);
    }
    for (const brk of pair.breaks) {
      expect(brk.length).toBeGreaterThan(0);
    }
  });
});

describe("magic value corruption", () => {
  it("never returns duplicates", () => {
    for (const value of MAGIC_VALUES) {
      const corrupted = corruptMagicValue(value);
      expect(new Set(corrupted).size, value).toBe(corrupted.length);
    }
  });

  it("never returns the original value", () => {
    for (const value of MAGIC_VALUES) {
      expect(corruptMagicValue(value), value).not.toContain(value);
    }
  });

  it("handles an empty value instead of dividing by zero", () => {
    // The magic list is a user-editable comma-separated setting, so a trailing comma yields
    // an empty entry. The original computed i % value.length on it.
    expect(corruptMagicValue("")).toEqual([]);
  });

  it("handles values shorter than four characters without duplicating corruptions", () => {
    const corrupted = corruptMagicValue("abc");
    expect(new Set(corrupted).size).toBe(corrupted.length);
    expect(corrupted).toContain("zbc");
    expect(corrupted).toContain("azc");
    expect(corrupted).toContain("abz");
  });

  it("handles a single-character value", () => {
    expect(corruptMagicValue("x")).toEqual(["z", "help"]);
  });

  it("includes a real word to filter plausible-user-input contexts", () => {
    expect(corruptMagicValue("null")).toContain("help");
  });
});

describe("transformation payloads", () => {
  it("has no duplicate metacharacters", () => {
    // The original list contained ";" twice, wasting one probe round per parameter.
    expect(new Set(TRANSFORM_METACHARACTERS).size).toBe(TRANSFORM_METACHARACTERS.length);
  });

  it("has no duplicate decode payloads", () => {
    expect(new Set(TRANSFORM_DECODE_PAYLOADS).size).toBe(TRANSFORM_DECODE_PAYLOADS.length);
  });

  it("contains every metacharacter the original probed", () => {
    const original = "'\"{}()[]$`/@#;%&|^?".split("");
    for (const c of original) {
      expect(TRANSFORM_METACHARACTERS, c).toContain(c);
    }
  });
});

describe("padding primitives", () => {
  it("widens a numeric literal without changing its value", () => {
    expect(padNumericLiteral("abs(1)", 2)).toBe("abs(001)");
    expect(padNumericLiteral("power(unix_timestamp(),0)", 1)).toBe(
      "power(unix_timestamp(),00)",
    );
  });

  it("widens the FIRST numeric literal", () => {
    expect(padNumericLiteral("min(sqlite_version(),1)", 1)).toBe("min(sqlite_version(),01)");
  });

  it("returns undefined when there is no numeric literal", () => {
    expect(padNumericLiteral("abc", 1)).toBeUndefined();
  });

  it("is a no-op for a non-positive delta", () => {
    expect(padNumericLiteral("abs(1)", 0)).toBe("abs(1)");
    expect(padWithFiller("abc", 0)).toBe("abc");
  });

  it("falls back to filler when numeric padding is impossible", () => {
    const result = equalisePair("abcdef", "abc", "numeric");
    expect(result.equal).toBe(true);
    expect(result.strategy).toBe("filler");
    expect(result.escapePayload).toBe("abczzz");
  });

  it("pads the break side when the escape is longer", () => {
    const result = equalisePair("ab", "abcd", "filler");
    expect(result.breakPayload).toBe("abzz");
    expect(result.escapePayload).toBe("abcd");
  });

  it("reports inequality rather than lying when strategy is none", () => {
    const result = equalisePair("\\", "\\\\", "none");
    expect(result.equal).toBe(false);
    expect(result.breakPayload).toBe("\\");
    expect(result.escapePayload).toBe("\\\\");
  });
});

describe("percent-significant payloads reach the server intact", () => {
  const asText = (u: Uint8Array): string => {
    let out = "";
    for (const b of u) out += String.fromCharCode(b);
    return out;
  };

  function encodeWith(pair: ProbePair, payload: string): string {
    const result = QUERY_VALUE_CODEC.encode(bytes(payload), pair.wireForm ?? "literal");
    if (!result.ok) throw new Error(`refused: ${result.reason}`);
    return asText(result.bytes);
  }

  it("keeps ERB delimiters raw on a query surface", () => {
    // The bug this guards: with % encoded, "<%z" went out as "<%25z" and "z%>" as "z%25>", so the
    // syntax under test never reached the template engine and a plain ERB injection was invisible.
    const erb = ALL_STATIC_PROBES.find((p) => p.id === "interp.erb")!;
    expect(encodeWith(erb, "<%z")).toBe("<%z");
    expect(encodeWith(erb, "z%>")).toBe("z%>");
  });

  it("keeps the ERB evaluation probe intact apart from the space", () => {
    const evalProbe = ALL_STATIC_PROBES.find((p) => p.id === "interp.erb-eval")!;
    // Space still has to be encoded: it would truncate the parameter otherwise.
    expect(encodeWith(evalProbe, "<%= 7/0 %>")).toBe("<%=%207/0%20%>");
    expect(encodeWith(evalProbe, "<%= 7*1 %>")).toBe("<%=%207*1%20%>");
  });

  it("keeps the Struts/OGNL percent-brace form raw", () => {
    // interp.percent shipped broken: %{{41 was encoded to %25{{41 and could never fire.
    const percent = ALL_STATIC_PROBES.find((p) => p.id === "interp.percent")!;
    expect(encodeWith(percent, "%{{41")).toBe("%{{41");
    expect(encodeWith(percent, "%}}")).toBe("%}}");
  });

  it("still encodes a literal percent for probes that do not declare it significant", () => {
    const apostrophe = ALL_STATIC_PROBES.find((p) => p.id === "delim.apostrophe")!;
    expect(apostrophe.wireForm).toBeUndefined();
    expect(encodeWith(apostrophe, "100%")).toBe("100%25");
  });

  it("never exempts a byte that would break the container", () => {
    // Only % may be exempted. These would split the parameter or the request line.
    const erb = ALL_STATIC_PROBES.find((p) => p.id === "interp.erb")!;
    expect(encodeWith(erb, "a&b")).toBe("a%26b");
    expect(encodeWith(erb, "a b")).toBe("a%20b");
    expect(encodeWith(erb, "a#b")).toBe("a%23b");
    expect(encodeWith(erb, "a\r\nb")).toBe("a%0D%0Ab");
  });

  it("covers the ERB/EJS/JSP/ASP delimiter family that the original omitted entirely", () => {
    const ids = ALL_STATIC_PROBES.map((p) => p.id);
    expect(ids).toContain("interp.erb");
    expect(ids).toContain("interp.erb-eval");
  });

  it("pairs every interpolation family with an evaluation probe", () => {
    // A delimiter probe only asks whether an unbalanced tag upsets the parser. Engines that tolerate
    // that, or applications that swallow template errors, are invisible to it -- which is how a
    // Tornado lab went undetected with interp.curly present and passing.
    const ids = ALL_STATIC_PROBES.map((p) => p.id);
    for (const family of ["curly", "dollar", "percent", "erb"]) {
      expect(ids, family).toContain(`interp.${family}`);
      expect(ids, family).toContain(`interp.${family}-eval`);
    }
  });

  it("never uses a leading-zero literal in a template-expression payload", () => {
    // 007 is a SyntaxError in Python and in JavaScript strict mode, so an escape arm built from it
    // would throw exactly like the break arm and hide the difference being measured. 7*1 is valid in
    // every language these probes target.
    //
    // Scoped to the interpolation stage on purpose. The arithmetic family appends /01 and -00 to a
    // numeric parameter, which is fine in the SQL integer contexts it aims at, even though it too
    // would be a SyntaxError were a Python expression evaluator on the other end. Worth knowing as a
    // latent limitation of that family rather than asserting against it here.
    for (const probe of ALL_STATIC_PROBES.filter((p) => p.stage === "interpolation")) {
      for (const payload of [...probe.breaks, ...probe.escapeSets.flat()]) {
        expect(payload, probe.id).not.toMatch(/\b0[0-9]+\b/);
      }
    }
  });
});
