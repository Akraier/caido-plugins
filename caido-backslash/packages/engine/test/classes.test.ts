import { describe, expect, it } from "vitest";

import {
  ByteClass,
  CLASS_COUNT,
  CLASS_TABLE,
  SKELETON_TABLE,
  SPECIAL_CLASSES,
  SkeletonClass,
  classDelta,
  classProfile,
} from "../src/response/classes.ts";

describe("class table", () => {
  it("assigns every byte exactly one class within range", () => {
    expect(CLASS_TABLE.length).toBe(256);
    for (let b = 0; b < 256; b++) {
      const cls = CLASS_TABLE[b]!;
      expect(cls, `byte ${b}`).toBeGreaterThanOrEqual(0);
      expect(cls, `byte ${b}`).toBeLessThan(CLASS_COUNT);
    }
  });

  it("uses all 32 classes, so none is dead weight in the profile vector", () => {
    const used = new Set(Array.from(CLASS_TABLE));
    expect(used.size).toBe(CLASS_COUNT);
  });

  it("gives every character the probe catalogue manipulates its own class", () => {
    // Each of these appears as a load-bearing metacharacter in the ported catalogue, so the
    // explainability veto must be able to tell them apart.
    const expected: ReadonlyArray<readonly [string, number]> = [
      ["\\", ByteClass.BACKSLASH],
      ["'", ByteClass.QUOTE],
      ['"', ByteClass.DQUOTE],
      ["`", ByteClass.BACKTICK],
      [",", ByteClass.COMMA],
      [";", ByteClass.SEMICOLON],
      [":", ByteClass.COLON],
      ["/", ByteClass.SLASH],
      ["(", ByteClass.PAREN_OPEN],
      [")", ByteClass.PAREN_CLOSE],
      ["{", ByteClass.BRACE_OPEN],
      ["}", ByteClass.BRACE_CLOSE],
      ["[", ByteClass.BRACKET_OPEN],
      ["]", ByteClass.BRACKET_CLOSE],
      ["<", ByteClass.LT],
      [">", ByteClass.GT],
      ["=", ByteClass.EQUALS],
      [".", ByteClass.DOT],
      ["-", ByteClass.HYPHEN],
      ["_", ByteClass.UNDERSCORE],
    ];
    for (const [char, cls] of expected) {
      expect(CLASS_TABLE[char.charCodeAt(0)], char).toBe(cls);
    }
  });

  it("separates letter case and digits", () => {
    expect(CLASS_TABLE[0x41]).toBe(ByteClass.UPPER);
    expect(CLASS_TABLE[0x61]).toBe(ByteClass.LOWER);
    expect(CLASS_TABLE[0x39]).toBe(ByteClass.DIGIT);
  });

  it("separates the newline kinds, since they are structural in HTTP", () => {
    expect(CLASS_TABLE[0x0a]).toBe(ByteClass.LF);
    expect(CLASS_TABLE[0x0d]).toBe(ByteClass.CR);
    expect(CLASS_TABLE[0x09]).toBe(ByteClass.TAB);
    expect(CLASS_TABLE[0x20]).toBe(ByteClass.SPACE);
  });

  it("classifies NUL separately from other control bytes", () => {
    // NUL is a probe payload in its own right in the transformation family.
    expect(CLASS_TABLE[0x00]).toBe(ByteClass.NUL);
    expect(CLASS_TABLE[0x01]).toBe(ByteClass.CONTROL);
  });

  it("classifies all high-bit bytes together", () => {
    for (const b of [0x80, 0xc3, 0xff]) expect(CLASS_TABLE[b]).toBe(ByteClass.HIGH_BIT);
  });

  it("treats alphanumerics as non-special", () => {
    for (const cls of [ByteClass.LOWER, ByteClass.UPPER, ByteClass.DIGIT, ByteClass.SPACE]) {
      expect(SPECIAL_CLASSES.has(cls)).toBe(false);
    }
  });

  it("treats every syntax character as special", () => {
    for (const char of "\\'\"`,;:/(){}[]<>=&%$#@") {
      expect(SPECIAL_CLASSES.has(CLASS_TABLE[char.charCodeAt(0)]!), char).toBe(true);
    }
  });

  it("gives the interpolation and pollution sigils their own class", () => {
    // These drive whole probe stages: ${{ and %{{ for interpolation, & for backend parameter
    // pollution. The veto must distinguish them from generic punctuation.
    for (const char of "$%&") {
      expect(CLASS_TABLE[char.charCodeAt(0)], char).toBe(ByteClass.INTERPOLATION);
    }
    for (const char of "#@!?*+~^|") {
      expect(CLASS_TABLE[char.charCodeAt(0)], char).toBe(ByteClass.SPECIAL_MISC);
    }
  });
});

describe("class profile", () => {
  it("counts by class", () => {
    const profile = classProfile("ab'cd'");
    expect(profile[ByteClass.LOWER]).toBe(4);
    expect(profile[ByteClass.QUOTE]).toBe(2);
    expect(profile[ByteClass.DIGIT]).toBe(0);
  });

  it("returns a full-width vector", () => {
    expect(classProfile("").length).toBe(CLASS_COUNT);
  });
});

describe("class delta drives the explainability veto", () => {
  it("identifies the classes in which two payloads differ", () => {
    // From the catalogue: the order-by function pair. They differ in digits and commas only.
    const delta = classDelta(",abs(0,1)", ",abs(1)");
    expect(delta.has(ByteClass.COMMA)).toBe(true);
    expect(delta.has(ByteClass.DIGIT)).toBe(true);
    expect(delta.has(ByteClass.LOWER)).toBe(false);
    expect(delta.has(ByteClass.PAREN_OPEN)).toBe(false);
  });

  it("identifies the quote-doubling pair as differing only in quotes and backslashes", () => {
    const delta = classDelta("z\\'z", "z''z");
    expect(delta.has(ByteClass.BACKSLASH)).toBe(true);
    expect(delta.has(ByteClass.QUOTE)).toBe(true);
    expect(delta.has(ByteClass.LOWER)).toBe(false);
  });

  it("identifies the backslash family as differing only in backslashes", () => {
    // The pair whose lengths cannot be equalised. The veto is the only defence available, which
    // is exactly why it must be precise here.
    const delta = classDelta("\\\\\\", "\\\\\\\\");
    expect([...delta]).toEqual([ByteClass.BACKSLASH]);
  });

  it("is empty for identical payloads", () => {
    expect(classDelta("abc", "abc").size).toBe(0);
  });

  it("is empty for a permutation, since it counts rather than orders", () => {
    // A witness that survives a permutation is about position, not content. The veto is
    // deliberately content-only; positional artefacts are removed by the Dz control arm instead.
    expect(classDelta("a'b", "b'a").size).toBe(0);
  });
});

describe("skeleton table", () => {
  it("collapses alphanumerics and word punctuation to WORD", () => {
    for (const char of "abzABZ019_-.") {
      expect(SKELETON_TABLE[char.charCodeAt(0)], char).toBe(SkeletonClass.WORD);
    }
  });

  it("classifies whitespace as WS", () => {
    for (const b of [0x20, 0x09, 0x0a, 0x0d]) {
      expect(SKELETON_TABLE[b]).toBe(SkeletonClass.WS);
    }
  });

  it("classifies structural punctuation as STRUCT", () => {
    for (const char of "<>{}[]()\"',;:=/\\") {
      expect(SKELETON_TABLE[char.charCodeAt(0)], char).toBe(SkeletonClass.STRUCT);
    }
  });

  it("treats high-bit bytes as WORD, so UTF-8 text does not read as structure", () => {
    expect(SKELETON_TABLE[0xc3]).toBe(SkeletonClass.WORD);
  });

  it("assigns every byte a valid skeleton class", () => {
    expect(SKELETON_TABLE.length).toBe(256);
    for (let b = 0; b < 256; b++) {
      expect(SKELETON_TABLE[b]!).toBeLessThanOrEqual(SkeletonClass.STRUCT);
    }
  });
});
