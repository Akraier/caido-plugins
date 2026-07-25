/**
 * The 32-way byte-class partition (`CLASS32`).
 *
 * Two mechanisms depend on this, and both are false-positive controls:
 *
 * 1. The payload-delta explainability veto. If every feature that differs between the break and
 *    escape arms lies within the byte classes in which the two payload strings *themselves*
 *    differ, the difference is explained by the payloads not being the same string, and is
 *    therefore not evidence. That test needs a partition fine enough to distinguish "they differ
 *    in commas" from "they differ in quotes".
 * 2. The `Ds` control arm, which must match the break's class profile *outside* the specials, so
 *    that a witness surviving `Ds` cannot be attributed to ordinary punctuation sensitivity.
 *
 * The partition is therefore chosen so that every character class the probe catalogue actually
 * manipulates gets its own class. Note the spec's own constraint: the whole feature set is
 * derived in one pass with a 256-entry lookup, so this must be a flat table, not a predicate
 * chain.
 *
 * Confidence: the surviving specification names `CLASS32` and confirms "32 class sums", but the
 * exact partition was in a lost section. This assignment is a reconstruction. It is stable and
 * asserted by tests, so it can be treated as authoritative going forward, but it is not the
 * original.
 */

export const ByteClass = {
  NUL: 0,
  CONTROL: 1,
  TAB: 2,
  LF: 3,
  CR: 4,
  SPACE: 5,
  DIGIT: 6,
  UPPER: 7,
  LOWER: 8,
  UNDERSCORE: 9,
  HYPHEN: 10,
  DOT: 11,
  SLASH: 12,
  BACKSLASH: 13,
  COLON: 14,
  SEMICOLON: 15,
  COMMA: 16,
  QUOTE: 17,
  DQUOTE: 18,
  BACKTICK: 19,
  PAREN_OPEN: 20,
  PAREN_CLOSE: 21,
  BRACE_OPEN: 22,
  BRACE_CLOSE: 23,
  BRACKET_OPEN: 24,
  BRACKET_CLOSE: 25,
  LT: 26,
  GT: 27,
  EQUALS: 28,
  /** # @ ! ? * + ~ ^ | : the remaining metacharacters, none individually load-bearing. */
  SPECIAL_MISC: 29,
  /**
   * `$` `%` `&`. Given their own class because they drive two whole probe stages: interpolation
   * (`${{`, `%{{`) and backend parameter pollution (`&`). The explainability veto needs to
   * distinguish "differs in an interpolation sigil" from "differs in some punctuation".
   */
  INTERPOLATION: 30,
  HIGH_BIT: 31,
} as const;

export type ByteClass = (typeof ByteClass)[keyof typeof ByteClass];

export const CLASS_COUNT = 32;

/**
 * Classes that count as "special" for the purposes of the `Ds` control arm and the
 * explainability veto: those a server-side parser might treat as syntax rather than data.
 */
export const SPECIAL_CLASSES: ReadonlySet<number> = new Set([
  ByteClass.SLASH,
  ByteClass.BACKSLASH,
  ByteClass.COLON,
  ByteClass.SEMICOLON,
  ByteClass.COMMA,
  ByteClass.QUOTE,
  ByteClass.DQUOTE,
  ByteClass.BACKTICK,
  ByteClass.PAREN_OPEN,
  ByteClass.PAREN_CLOSE,
  ByteClass.BRACE_OPEN,
  ByteClass.BRACE_CLOSE,
  ByteClass.BRACKET_OPEN,
  ByteClass.BRACKET_CLOSE,
  ByteClass.LT,
  ByteClass.GT,
  ByteClass.EQUALS,
  ByteClass.SPECIAL_MISC,
  ByteClass.INTERPOLATION,
]);

function buildClassTable(): Uint8Array {
  // Default is SPECIAL_MISC: every byte is in fact assigned explicitly below, but an unclassified
  // printable byte is far more like miscellaneous punctuation than like a word character, so a
  // future addition that forgets a case fails safe rather than diluting the word classes.
  const table = new Uint8Array(256).fill(ByteClass.SPECIAL_MISC);

  for (let b = 0; b < 32; b++) table[b] = ByteClass.CONTROL;
  table[0x00] = ByteClass.NUL;
  table[0x09] = ByteClass.TAB;
  table[0x0a] = ByteClass.LF;
  table[0x0d] = ByteClass.CR;
  table[0x7f] = ByteClass.CONTROL;
  table[0x20] = ByteClass.SPACE;

  for (let b = 0x30; b <= 0x39; b++) table[b] = ByteClass.DIGIT;
  for (let b = 0x41; b <= 0x5a; b++) table[b] = ByteClass.UPPER;
  for (let b = 0x61; b <= 0x7a; b++) table[b] = ByteClass.LOWER;

  const single: ReadonlyArray<readonly [number, number]> = [
    [0x5f, ByteClass.UNDERSCORE],
    [0x2d, ByteClass.HYPHEN],
    [0x2e, ByteClass.DOT],
    [0x2f, ByteClass.SLASH],
    [0x5c, ByteClass.BACKSLASH],
    [0x3a, ByteClass.COLON],
    [0x3b, ByteClass.SEMICOLON],
    [0x2c, ByteClass.COMMA],
    [0x27, ByteClass.QUOTE],
    [0x22, ByteClass.DQUOTE],
    [0x60, ByteClass.BACKTICK],
    [0x28, ByteClass.PAREN_OPEN],
    [0x29, ByteClass.PAREN_CLOSE],
    [0x7b, ByteClass.BRACE_OPEN],
    [0x7d, ByteClass.BRACE_CLOSE],
    [0x5b, ByteClass.BRACKET_OPEN],
    [0x5d, ByteClass.BRACKET_CLOSE],
    [0x3c, ByteClass.LT],
    [0x3e, ByteClass.GT],
    [0x3d, ByteClass.EQUALS],
  ];
  for (const [byte, cls] of single) table[byte] = cls;

  for (const byte of [0x23, 0x40, 0x21, 0x3f, 0x2a, 0x2b, 0x7e, 0x5e, 0x7c]) {
    table[byte] = ByteClass.SPECIAL_MISC;
  }
  for (const byte of [0x24, 0x25, 0x26]) table[byte] = ByteClass.INTERPOLATION;

  for (let b = 0x80; b <= 0xff; b++) table[b] = ByteClass.HIGH_BIT;

  return table;
}

/** Flat 256-entry lookup, built once. */
export const CLASS_TABLE: Uint8Array = buildClassTable();

/**
 * Coarse skeleton class, used by the run-length structural digest.
 *
 * Collapsing to three symbols is what makes the digest ignore nonces: a 32-character hex session
 * id and an 8-character username both become a single WORD token, so a response whose only change
 * is a fresh token digests identically. STRUCT keeps the punctuation that carries structure.
 */
export const SkeletonClass = {
  WORD: 0,
  WS: 1,
  STRUCT: 2,
} as const;

function buildSkeletonTable(): Uint8Array {
  const table = new Uint8Array(256).fill(SkeletonClass.STRUCT);
  for (let b = 0x30; b <= 0x39; b++) table[b] = SkeletonClass.WORD;
  for (let b = 0x41; b <= 0x5a; b++) table[b] = SkeletonClass.WORD;
  for (let b = 0x61; b <= 0x7a; b++) table[b] = SkeletonClass.WORD;
  for (const b of [0x5f, 0x2d, 0x2e]) table[b] = SkeletonClass.WORD;
  for (const b of [0x20, 0x09, 0x0a, 0x0d, 0x0b, 0x0c]) table[b] = SkeletonClass.WS;
  for (let b = 0x80; b <= 0xff; b++) table[b] = SkeletonClass.WORD;
  return table;
}

export const SKELETON_TABLE: Uint8Array = buildSkeletonTable();

/** FNV-1a-32 step. Kept here so every digest in the engine uses the same one. */
export function fnv1a(hash: number, byte: number): number {
  return Math.imul(hash ^ byte, 0x01000193) >>> 0;
}

export const FNV_OFFSET = 0x811c9dc5;

/**
 * Byte-class profile of a string, as a 32-slot count vector.
 *
 * Used on the request side to compute the class delta between a break payload and its escape,
 * which is the input to the explainability veto, and to build a `Ds` control arm with a matching
 * profile outside the specials.
 */
export function classProfile(text: string): Int32Array {
  const counts = new Int32Array(CLASS_COUNT);
  for (let i = 0; i < text.length; i++) {
    const cls = CLASS_TABLE[text.charCodeAt(i) & 0xff]!;
    counts[cls] = counts[cls]! + 1;
  }
  return counts;
}

/**
 * The set of classes in which two payloads differ.
 *
 * This is the veto's input: a witness whose feature is confined to these classes is explained by
 * the payloads not being the same string, and is not evidence of anything.
 */
export function classDelta(a: string, b: string): Set<number> {
  const pa = classProfile(a);
  const pb = classProfile(b);
  const differing = new Set<number>();
  for (let cls = 0; cls < CLASS_COUNT; cls++) {
    if (pa[cls] !== pb[cls]) differing.add(cls);
  }
  return differing;
}
