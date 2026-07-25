/**
 * Reflected-span excision.
 *
 * Every payload is framed as `base + L + payload + R`, where L and R are fresh random
 * alphanumeric tokens per request. Wherever that frame is echoed in the response, those bytes
 * are excluded from every structural, histogram, depth and lexeme computation.
 *
 * This is the highest-value false-positive control in the whole technique, and it is worth being
 * precise about why. Break and escape payloads are not the same string: they differ in
 * punctuation by construction. Two examples straight out of the ported catalogue, `,abs(0,1)`
 * against `,abs(1)`, and `z\'z` against `z''z`. On any parameter whose value is reflected, an
 * un-excised comma or quote counter separates the two arms deterministically in *every single
 * send*. No amount of statistical machinery helps: the difference is real, perfectly
 * reproducible, and has nothing whatever to do with server-side parsing. Excising the echo is
 * what removes it.
 *
 * The excision is bounded, which is the second half of the mechanism. If the closing R canary is
 * missing, the naive implementation redacts everything from L to the end of the document, and
 * that unbounded rollback is itself a false-positive generator: it silently deletes real
 * evidence and the deletion span depends on the payload. Instead, mask only the located L token
 * and raise a flag saying the body-derived features are unreliable for this response.
 */

/** A half-open byte range. */
export interface Span {
  readonly start: number;
  readonly end: number;
}

export interface CanaryFrame {
  /** Opening token, placed before the payload. */
  readonly left: string;
  /**
   * Closing token, placed after the payload. Omitted for END-ANCHORED probes.
   *
   * This is a real conflict between two requirements, discovered by running a probe end to end.
   * Excision wants the payload bracketed so its extent is known exactly. But a whole probe family
   * depends on the payload being the LAST thing in the value: a trailing backslash is an
   * unterminated escape, whereas the same backslash followed by a closing canary merely escapes the
   * canary's first letter, which is a different test entirely. The original tool placed its single
   * anchor BEFORE the payload for exactly this reason.
   *
   * When `right` is absent the echo extent has to be estimated, so excision is coarser: see
   * {@link LEFT_ONLY_SLACK}. That is the price of testing end-anchored semantics at all, and it is
   * paid only by the probes that need it.
   */
  readonly right?: string;
}

/**
 * Extra bytes excised past the payload length when there is no closing canary, to absorb modest
 * server-side expansion such as entity-escaping a quote.
 *
 * Deliberately small. Over-excising eats real evidence, and unlike the bracketed case there is no
 * marker to tell us where the echo actually ended.
 */
export const LEFT_ONLY_SLACK = 8;

/**
 * Maximum bytes redacted per echo site.
 *
 * Eight times the payload length covers the worst realistic expansion: HTML entity encoding
 * reaches six bytes per character (`&quot;`) and `\uXXXX` escaping six as well, so 8x leaves
 * margin. The absolute ceiling bounds the damage of a lost R canary to 4 KiB rather than the
 * whole document tail.
 */
export function capSpan(payloadLength: number): number {
  return Math.min(8 * payloadLength + 64, 4096);
}

export const EchoTransform = {
  /** Payload survived with a literal backslash intact. */
  RAW_BACKSLASH: 1 << 0,
  RAW_QUOTE: 1 << 1,
  RAW_DQUOTE: 1 << 2,
  RAW_ANGLE: 1 << 3,
  /** Server HTML-entity-encoded the payload. */
  HTML_ENTITY: 1 << 4,
  /** Server percent-encoded the payload. */
  URL_ENCODED: 1 << 5,
  /** Server doubled a backslash, i.e. it escaped our escape. */
  BACKSLASH_DOUBLED: 1 << 6,
  /** Server rewrote the payload as a unicode escape. */
  UNICODE_ESCAPED: 1 << 7,
  /** Echo is shorter than what was sent: something was stripped. */
  SHORTENED: 1 << 8,
  /** Echo is longer than what was sent: something was expanded or escaped. */
  LENGTHENED: 1 << 9,
  /** Echo is byte-identical to what was sent. */
  VERBATIM: 1 << 10,
} as const;

export type EchoState =
  /** The opening canary does not appear: the value is not reflected in the body. */
  | "absent"
  /** Every located site had a matching closing canary within the cap. */
  | "paired"
  /** At least one site lost its closing canary; body features are unreliable. */
  | "unpaired"
  /** No closing canary was sent (end-anchored probe); extent estimated from payload length. */
  | "left-only";

export interface EchoAnalysis {
  readonly state: EchoState;
  /** Ranges to exclude from feature computation, sorted and non-overlapping. */
  readonly spans: readonly Span[];
  /** Number of distinct echo sites found. */
  readonly siteCount: number;
  /** Bitmask of {@link EchoTransform}, from the first paired site. */
  readonly transformBits: number;
  /**
   * True when a closing canary was missing. Body-derived features must be treated as
   * unreliable for this response rather than compared as though excision had succeeded.
   */
  readonly unpaired: boolean;
  /** Bytes removed from consideration. */
  readonly excisedBytes: number;
}

/** Find every occurrence of `needle` in `haystack[from..to)`. Plain search; needles are short. */
function findAll(
  haystack: Uint8Array,
  needle: Uint8Array,
  from: number,
  to: number,
): number[] {
  const hits: number[] = [];
  if (needle.length === 0) return hits;
  const last = to - needle.length;
  outer: for (let i = Math.max(0, from); i <= last; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    hits.push(i);
  }
  return hits;
}

function indexOfFrom(
  haystack: Uint8Array,
  needle: Uint8Array,
  from: number,
  to: number,
): number {
  const last = to - needle.length;
  outer: for (let i = from; i <= last; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function toBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

/** Merge overlapping or touching spans so excision never double-counts. */
export function mergeSpans(spans: readonly Span[]): Span[] {
  if (spans.length === 0) return [];
  const sorted = [...spans].sort((a, b) => a.start - b.start);
  const merged: Span[] = [{ ...sorted[0]! }];
  for (let i = 1; i < sorted.length; i++) {
    const span = sorted[i]!;
    const tail = merged[merged.length - 1]!;
    if (span.start <= tail.end) {
      if (span.end > tail.end) merged[merged.length - 1] = { start: tail.start, end: span.end };
    } else {
      merged.push({ ...span });
    }
  }
  return merged;
}

/**
 * Subtract `holes` from `ranges`, returning the surviving ranges in order.
 *
 * Used to combine the head/tail scan windows with the echo spans, so the byte loop simply walks
 * a list of ranges and never tests "am I inside an echo" per byte.
 */
export function subtractSpans(
  ranges: readonly Span[],
  holes: readonly Span[],
): Span[] {
  if (holes.length === 0) return ranges.filter((r) => r.end > r.start).map((r) => ({ ...r }));
  const merged = mergeSpans(holes);
  const out: Span[] = [];
  for (const range of ranges) {
    let cursor = range.start;
    for (const hole of merged) {
      if (hole.end <= cursor) continue;
      if (hole.start >= range.end) break;
      if (hole.start > cursor) out.push({ start: cursor, end: Math.min(hole.start, range.end) });
      cursor = Math.max(cursor, hole.end);
      if (cursor >= range.end) break;
    }
    if (cursor < range.end) out.push({ start: cursor, end: range.end });
  }
  return out.filter((r) => r.end > r.start);
}

/**
 * Classify what the server did to the payload, from the bytes it echoed back.
 *
 * `sent` is the payload as transmitted, `echoed` the bytes strictly between the two canaries.
 */
export function classifyTransform(sent: Uint8Array, echoed: Uint8Array): number {
  let bits = 0;

  if (echoed.length === sent.length) {
    let identical = true;
    for (let i = 0; i < sent.length; i++) {
      if (sent[i] !== echoed[i]) {
        identical = false;
        break;
      }
    }
    if (identical) bits |= EchoTransform.VERBATIM;
  } else if (echoed.length < sent.length) {
    bits |= EchoTransform.SHORTENED;
  } else {
    bits |= EchoTransform.LENGTHENED;
  }

  for (let i = 0; i < echoed.length; i++) {
    const c = echoed[i]!;
    switch (c) {
      case 0x5c: {
        bits |= EchoTransform.RAW_BACKSLASH;
        const next = echoed[i + 1];
        if (next === 0x5c) bits |= EchoTransform.BACKSLASH_DOUBLED;
        // \u followed by four hex digits
        if (next === 0x75 && isHex(echoed[i + 2]) && isHex(echoed[i + 3])) {
          bits |= EchoTransform.UNICODE_ESCAPED;
        }
        break;
      }
      case 0x27:
        bits |= EchoTransform.RAW_QUOTE;
        break;
      case 0x22:
        bits |= EchoTransform.RAW_DQUOTE;
        break;
      case 0x3c:
      case 0x3e:
        bits |= EchoTransform.RAW_ANGLE;
        break;
      case 0x26: // '&' followed by '#' or a known entity name start
        if (echoed[i + 1] === 0x23) bits |= EchoTransform.HTML_ENTITY;
        else if (startsWithEntityName(echoed, i + 1)) bits |= EchoTransform.HTML_ENTITY;
        break;
      case 0x25: // '%' followed by two hex digits
        if (isHex(echoed[i + 1]) && isHex(echoed[i + 2])) bits |= EchoTransform.URL_ENCODED;
        break;
      default:
        break;
    }
  }

  return bits;
}

function isHex(byte: number | undefined): boolean {
  if (byte === undefined) return false;
  return (
    (byte >= 0x30 && byte <= 0x39) ||
    (byte >= 0x41 && byte <= 0x46) ||
    (byte >= 0x61 && byte <= 0x66)
  );
}

const ENTITY_NAMES = ["lt;", "gt;", "amp;", "quot;", "apos;", "#39;", "#x27;"].map(toBytes);

function startsWithEntityName(bytes: Uint8Array, at: number): boolean {
  outer: for (const name of ENTITY_NAMES) {
    if (at + name.length > bytes.length) continue;
    for (let j = 0; j < name.length; j++) {
      if (bytes[at + j] !== name[j]) continue outer;
    }
    return true;
  }
  return false;
}

export interface LocateEchoOptions {
  /** The payload as sent, used for transform classification and the span cap. */
  readonly sentPayload: string;
  /** Override the span cap, primarily for tests. */
  readonly capBytes?: number;
  /** Stop after this many sites. Bounds cost on a page that echoes input hundreds of times. */
  readonly maxSites?: number;
}

/** How many echo sites to locate before giving up and flagging the response. */
export const DEFAULT_MAX_SITES = 64;

/**
 * Locate the echoed payload frame and produce the excision spans.
 */
export function locateEcho(
  bytes: Uint8Array,
  bodyStart: number,
  bodyEnd: number,
  frame: CanaryFrame,
  options: LocateEchoOptions,
): EchoAnalysis {
  const left = toBytes(frame.left);
  const endAnchored = frame.right === undefined;
  const right = toBytes(frame.right ?? "");
  const sent = toBytes(options.sentPayload);
  const cap = options.capBytes ?? capSpan(sent.length);
  const maxSites = options.maxSites ?? DEFAULT_MAX_SITES;

  const starts = findAll(bytes, left, bodyStart, bodyEnd);
  if (starts.length === 0) {
    return {
      state: "absent",
      spans: [],
      siteCount: 0,
      transformBits: 0,
      unpaired: false,
      excisedBytes: 0,
    };
  }

  const spans: Span[] = [];
  let unpaired = false;
  let transformBits = 0;
  let transformSeen = false;

  const considered = starts.slice(0, maxSites);

  if (endAnchored) {
    // No closing marker, so the extent is estimated: the payload as sent, plus a small allowance
    // for server-side expansion. Coarser than bracketed excision by necessity.
    const extent = left.length + sent.length + LEFT_ONLY_SLACK;
    for (const start of considered) {
      spans.push({ start, end: Math.min(bodyEnd, start + extent) });
    }
    const mergedLeftOnly = mergeSpans(spans);
    let excised = 0;
    for (const span of mergedLeftOnly) excised += span.end - span.start;
    const firstStart = considered[0]!;
    const echoedFrom = firstStart + left.length;
    return {
      state: "left-only",
      spans: mergedLeftOnly,
      siteCount: starts.length,
      transformBits: classifyTransform(
        sent,
        bytes.subarray(echoedFrom, Math.min(bodyEnd, echoedFrom + sent.length)),
      ),
      unpaired: false,
      excisedBytes: excised,
    };
  }

  for (const start of considered) {
    const searchFrom = start + left.length;
    // Only look for the closing canary inside the cap, so a missing R cannot drag the span to
    // the end of the document.
    const searchTo = Math.min(bodyEnd, searchFrom + cap);
    const rightAt = indexOfFrom(bytes, right, searchFrom, searchTo);

    if (rightAt === -1) {
      // Mask the opening token only, and declare the body unreliable.
      spans.push({ start, end: start + left.length });
      unpaired = true;
      continue;
    }

    spans.push({ start, end: rightAt + right.length });
    if (!transformSeen) {
      transformBits = classifyTransform(sent, bytes.subarray(searchFrom, rightAt));
      transformSeen = true;
    }
  }

  const merged = mergeSpans(spans);
  let excisedBytes = 0;
  for (const span of merged) excisedBytes += span.end - span.start;

  return {
    state: unpaired ? "unpaired" : "paired",
    spans: merged,
    siteCount: starts.length,
    transformBits,
    unpaired,
    excisedBytes,
  };
}
