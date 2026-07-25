/**
 * Span-recording JSON scanner.
 *
 * Locates every injectable site in a JSON document and records its byte range. It does not parse
 * into a value tree, does not call `JSON.parse`, does not use a regular expression, and never
 * slices the body into a string. Those constraints are not stylistic:
 *
 * - `JSON.parse` followed by `JSON.stringify` is lossy in ways that correlate with content:
 *   int-like object keys get reordered, `1.0` becomes `1`, a 20-digit integer loses precision, and
 *   `A` and `\/` come back unescaped. Any of those differences could land on one arm and not
 *   the other, which is precisely the label-dependent difference that fabricates a finding.
 * - Regular expressions over a request body are a known performance trap in the QuickJS runtime.
 *
 * Two injection modes share every string range, and having both for free is the direct dividend of
 * working in byte offsets:
 *
 * - `string` sites take a JSON-escaped payload, testing the interpreter *behind* the JSON parser.
 * - `raw-span` sites take the payload verbatim, producing deliberately invalid JSON, testing the
 *   parser *itself*. This is the JSON key/value cascade edge, and it is unreachable through any
 *   library serialiser because a serialiser exists to produce valid output.
 */

import type { Range } from "./template.ts";

export type JsonSiteKind =
  /** Interior of a string value, between the quotes. Escaped payload. */
  | "string"
  /** A number literal. Verbatim payload: this is the integer context where blind SQLi hides. */
  | "number"
  /** A `true` or `false` literal. Verbatim payload. */
  | "bool"
  /** A `null` literal. Verbatim payload. */
  | "null"
  /** Interior of an object member name. Escaped payload. */
  | "key";

export interface JsonSite {
  readonly kind: JsonSiteKind;
  /**
   * Location in the document, in JSON Pointer style. Duplicate keys are disambiguated by an
   * occurrence index, e.g. `/a#1`, because a duplicate key is a distinct injectable site and
   * collapsing them would silently drop one.
   */
  readonly pointer: string;
  /**
   * The bytes an injected payload replaces. For a string or key this is the interior, excluding
   * the surrounding quotes; for a scalar literal it is the whole token.
   */
  readonly range: Range;
  /** For strings and keys, the range including the surrounding quotes. Used by `raw-span` mode. */
  readonly tokenRange: Range;
  /** Nesting depth, zero for a top-level scalar. */
  readonly depth: number;
}

export interface JsonScanResult {
  readonly sites: readonly JsonSite[];
  /** Set when scanning stopped early. The document is then treated as opaque. */
  readonly error?: string;
}

// A plain const object rather than a const enum: erasable-syntax-only runtimes (Node's type
// stripping, and any bundler configured for it) reject const enums, and the engine has to run
// unbundled in the CLI as well as bundled in the plugin.
const Ctx = { Array: 0, Object: 1 } as const;
type Ctx = (typeof Ctx)[keyof typeof Ctx];

interface Frame {
  readonly ctx: Ctx;
  /** Path prefix for children of this frame. */
  readonly prefix: string;
  /** Next array index, or the current key for an object. */
  index: number;
  /** Occurrence counts per key, so duplicates get distinct pointers. */
  readonly seen: Map<string, number>;
}

const MAX_DEPTH = 64;
const MAX_SITES = 512;

function isWs(byte: number): boolean {
  return byte === 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0d;
}

function isDigit(byte: number): boolean {
  return byte >= 0x30 && byte <= 0x39;
}

/** Escape a path token so a key containing `/` cannot forge a pointer boundary. */
function escapeToken(token: string): string {
  return token.replace(/~/g, "~0").replace(/\//g, "~1");
}

/**
 * Scan `bytes[from..to)` as a JSON document.
 *
 * Deliberately tolerant of trailing content and permissive about what follows a value: the goal is
 * to locate sites in real request bodies, not to validate. A document it cannot follow returns the
 * sites found so far plus an error, and the caller treats the body as opaque rather than guessing.
 */
export function scanJson(bytes: Uint8Array, from: number, to: number): JsonScanResult {
  const sites: JsonSite[] = [];
  const stack: Frame[] = [];
  let i = from;

  const fail = (message: string): JsonScanResult => ({
    sites,
    error: `${message} at offset ${i}`,
  });

  const skipWs = (): void => {
    while (i < to && isWs(bytes[i]!)) i++;
  };

  /** Consume a string token. Returns interior and token ranges, or undefined on malformed input. */
  const readString = (): { interior: Range; token: Range } | undefined => {
    if (bytes[i] !== 0x22) return undefined;
    const tokenStart = i;
    i++;
    const interiorStart = i;
    while (i < to) {
      const byte = bytes[i]!;
      if (byte === 0x5c) {
        // Skip the escape and whatever it escapes, without interpreting it.
        i += 2;
        continue;
      }
      if (byte === 0x22) {
        const interior: Range = { start: interiorStart, end: i };
        i++;
        return { interior, token: { start: tokenStart, end: i } };
      }
      i++;
    }
    return undefined;
  };

  const currentPrefix = (): string =>
    stack.length === 0 ? "" : stack[stack.length - 1]!.prefix;

  const pushSite = (site: JsonSite): boolean => {
    if (sites.length >= MAX_SITES) return false;
    sites.push(site);
    return true;
  };

  /** Read one value. `pointer` is where it lives. */
  const readValue = (pointer: string): JsonScanResult | undefined => {
    skipWs();
    if (i >= to) return fail("unexpected end of document");
    const byte = bytes[i]!;
    const depth = stack.length;

    if (byte === 0x7b || byte === 0x5b) {
      if (stack.length >= MAX_DEPTH) return fail("maximum nesting depth exceeded");
      stack.push({
        ctx: byte === 0x7b ? Ctx.Object : Ctx.Array,
        prefix: pointer,
        index: 0,
        seen: new Map(),
      });
      i++;
      return undefined;
    }

    if (byte === 0x22) {
      const read = readString();
      if (read === undefined) return fail("unterminated string");
      pushSite({
        kind: "string",
        pointer,
        range: read.interior,
        tokenRange: read.token,
        depth,
      });
      return undefined;
    }

    if (byte === 0x2d || isDigit(byte)) {
      const start = i;
      if (bytes[i] === 0x2d) i++;
      while (i < to && isDigit(bytes[i]!)) i++;
      if (i < to && bytes[i] === 0x2e) {
        i++;
        while (i < to && isDigit(bytes[i]!)) i++;
      }
      if (i < to && (bytes[i] === 0x65 || bytes[i] === 0x45)) {
        i++;
        if (i < to && (bytes[i] === 0x2b || bytes[i] === 0x2d)) i++;
        while (i < to && isDigit(bytes[i]!)) i++;
      }
      const range: Range = { start, end: i };
      if (range.end === range.start) return fail("malformed number");
      pushSite({ kind: "number", pointer, range, tokenRange: range, depth });
      return undefined;
    }

    const literal = matchLiteral(bytes, i, to);
    if (literal !== undefined) {
      const range: Range = { start: i, end: i + literal.length };
      i += literal.length;
      pushSite({
        kind: literal === "null" ? "null" : "bool",
        pointer,
        range,
        tokenRange: range,
        depth,
      });
      return undefined;
    }

    return fail(`unexpected byte 0x${byte.toString(16)}`);
  };

  skipWs();
  if (i >= to) return { sites, error: "empty document" };

  // Top-level value.
  const firstByte = bytes[i]!;
  if (firstByte !== 0x7b && firstByte !== 0x5b) {
    const result = readValue("");
    return result ?? { sites };
  }

  const opened = readValue("");
  if (opened !== undefined) return opened;

  // Iterative walk. Each turn either closes the current frame or reads one member/element.
  for (;;) {
    skipWs();
    if (i >= to) return fail("unexpected end of document");
    const frame = stack[stack.length - 1];
    if (frame === undefined) break;

    const byte = bytes[i]!;

    if ((frame.ctx === Ctx.Object && byte === 0x7d) || (frame.ctx === Ctx.Array && byte === 0x5d)) {
      i++;
      stack.pop();
      if (stack.length === 0) break;
      skipWs();
      // A separator after a closed container is consumed on the next turn.
      if (i < to && bytes[i] === 0x2c) i++;
      continue;
    }

    if (byte === 0x2c) {
      i++;
      continue;
    }

    if (frame.ctx === Ctx.Object) {
      const key = readString();
      if (key === undefined) return fail("expected an object key");
      let keyText = "";
      for (let k = key.interior.start; k < key.interior.end; k++) {
        keyText += String.fromCharCode(bytes[k]!);
      }
      const occurrence = frame.seen.get(keyText) ?? 0;
      frame.seen.set(keyText, occurrence + 1);
      const suffix = occurrence === 0 ? "" : `#${occurrence}`;
      const pointer = `${frame.prefix}/${escapeToken(keyText)}${suffix}`;

      pushSite({
        kind: "key",
        pointer,
        range: key.interior,
        tokenRange: key.token,
        depth: stack.length,
      });

      skipWs();
      if (i >= to || bytes[i] !== 0x3a) return fail("expected a colon after an object key");
      i++;
      const failure = readValue(pointer);
      if (failure !== undefined) return failure;
      continue;
    }

    const pointer = `${frame.prefix}/${frame.index}`;
    frame.index += 1;
    const failure = readValue(pointer);
    if (failure !== undefined) return failure;
  }

  return { sites };
}

function matchLiteral(bytes: Uint8Array, at: number, to: number): string | undefined {
  for (const literal of ["true", "false", "null"]) {
    if (at + literal.length > to) continue;
    let matched = true;
    for (let k = 0; k < literal.length; k++) {
      if (bytes[at + k] !== literal.charCodeAt(k)) {
        matched = false;
        break;
      }
    }
    if (matched) return literal;
  }
  return undefined;
}
