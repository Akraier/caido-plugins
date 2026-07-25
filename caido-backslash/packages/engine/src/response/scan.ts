/**
 * Single-pass response body scan.
 *
 * Every per-byte feature is computed in ONE loop. This is a hard requirement rather than a
 * micro-optimisation: the Caido backend is a single-threaded QuickJS runtime with no worker
 * threads, so time spent here is time the event loop cannot spend on in-flight requests.
 *
 * Measured under QuickJS-ng 0.15.1 (bench/fusedbench.js), the fused loop costs almost
 * exactly 103 microseconds per KiB scanned and is linear:
 *
 *     16 KiB   1.67 ms      128 KiB  13.40 ms
 *     32 KiB   3.34 ms      256 KiB  27.19 ms
 *     64 KiB   6.72 ms      512 KiB  53.25 ms
 *      2 MiB 214.68 ms
 *
 * Hence SCAN_CAP_BYTES. With a scheduler running ~10 concurrent requests against a target
 * with ~100 ms latency, the runtime sees on the order of 100 responses/second; at a 32 KiB
 * cap that is ~34% of one core, which leaves headroom. An uncapped 2 MiB body would cost
 * 215 ms of blocking CPU per response and is not viable at any concurrency.
 *
 * The cap is applied as a HEAD window plus a TAIL window rather than a single prefix.
 * Interpreter errors surface at either end in practice: a JSON error envelope or a fatal
 * error emitted before output appears at the top, while stack traces, debug footers and
 * appended warnings appear after a large page body. A head-only cap makes the latter class
 * invisible, which is a false-negative source for the same cost.
 */

import { type Span, subtractSpans } from "./echo.ts";
import { type KeywordAutomaton, defaultKeywordAutomaton } from "./keywords.ts";

/** Bigram histogram bucket count. Must be a power of two. */
export const BIGRAM_BUCKETS = 4096;
const BIGRAM_MASK = BIGRAM_BUCKETS - 1;

/**
 * Default total bytes of body examined per response, split across head and tail.
 *
 * 32 KiB is chosen from the measured cost curve above, not by taste. Raising it buys more
 * body coverage linearly and costs event-loop time linearly.
 */
export const SCAN_CAP_BYTES = 32 * 1024;

export interface ScanOptions {
  /** Total bytes to examine. Set to Infinity to scan the whole body. */
  readonly capBytes?: number;
  /** Override the keyword automaton, primarily for tests. */
  readonly automaton?: KeywordAutomaton;
  /**
   * Byte ranges to exclude entirely, in absolute coordinates.
   *
   * Normally the reflected-payload spans from {@link locateEcho}. Excluding them is what stops
   * the break and escape payloads' own punctuation from separating the two arms on any parameter
   * whose value is echoed. Ranges are subtracted from the scan windows up front, so the byte
   * loop never performs a per-byte containment test.
   */
  readonly excise?: readonly Span[];
}

/**
 * Raw per-byte measurements. This is deliberately a bag of primitives plus two typed
 * arrays: it is the input to feature extraction, not the feature vector itself. Deciding
 * which of these participate in a detection decision is a separate concern.
 */
export interface BodyScan {
  /** True body length in bytes, never capped. Free to compute and meaningful on its own. */
  readonly bodyLength: number;
  /** How many bytes were actually examined. Equals bodyLength when under the cap. */
  readonly scannedBytes: number;
  /** True when the body exceeded the cap and was sampled head+tail. */
  readonly truncated: boolean;
  /** Bytes inside the scan windows that were excluded as reflected payload. */
  readonly excisedBytes: number;

  readonly newlines: number;
  readonly spaces: number;
  readonly tags: number;
  readonly equals: number;
  readonly quotes: number;
  readonly commas: number;
  readonly digits: number;
  readonly semicolons: number;
  readonly braces: number;

  /** Counts per KEYWORDS index. */
  readonly keywords: Int32Array;
  /** Folded-byte bigram histogram, BIGRAM_BUCKETS wide. */
  readonly bigrams: Int32Array;
  /** FNV-1a over the sequence of HTML tag names only. 0 when no tags were seen. */
  readonly tagHash: number;
  /** Number of tag names contributing to tagHash, so callers can tell 0 from "no HTML". */
  readonly tagNameCount: number;
}

interface Window {
  readonly from: number;
  readonly to: number;
}

/**
 * Choose the byte ranges to examine. Returns one window when the body fits under the cap,
 * otherwise a head window and a tail window that together equal the cap and do not overlap.
 */
export function scanWindows(bodyLength: number, capBytes: number): Window[] {
  if (!(capBytes > 0)) return [];
  if (bodyLength <= capBytes) return [{ from: 0, to: bodyLength }];

  const head = Math.ceil(capBytes / 2);
  const tail = capBytes - head;
  const tailFrom = bodyLength - tail;
  // Guaranteed non-overlapping because bodyLength > capBytes = head + tail.
  return [
    { from: 0, to: head },
    { from: tailFrom, to: bodyLength },
  ];
}

/**
 * Scan `bytes[bodyStart..bodyEnd)` and return raw measurements.
 *
 * `bytes` is normally the whole raw response and `bodyStart` the offset just past the header
 * terminator, so no copy of the body is required.
 */
export function scanBody(
  bytes: Uint8Array,
  bodyStart: number,
  bodyEnd: number,
  options: ScanOptions = {},
): BodyScan {
  const automaton = options.automaton ?? defaultKeywordAutomaton();
  const capBytes = options.capBytes ?? SCAN_CAP_BYTES;

  const bodyLength = Math.max(0, bodyEnd - bodyStart);
  const windows = scanWindows(bodyLength, capBytes);
  const absolute: Span[] = windows.map((w) => ({
    start: bodyStart + w.from,
    end: bodyStart + w.to,
  }));
  const excise = options.excise;
  const ranges =
    excise === undefined || excise.length === 0 ? absolute : subtractSpans(absolute, excise);

  let windowBytes = 0;
  for (const range of absolute) windowBytes += range.end - range.start;
  let scannableBytes = 0;
  for (const range of ranges) scannableBytes += range.end - range.start;
  const excisedBytes = windowBytes - scannableBytes;

  // Width comes from the supplied automaton, not the module constant: a caller passing a
  // custom pattern set must get a vector matching that set, or the counts silently misalign.
  const keywords = new Int32Array(automaton.patternCount);
  const bigrams = new Int32Array(BIGRAM_BUCKETS);

  const next = automaton.next;
  const outIndex = automaton.outIndex;
  const outLists = automaton.outLists;

  let newlines = 0;
  let spaces = 0;
  let tags = 0;
  let equals = 0;
  let quotes = 0;
  let commas = 0;
  let digits = 0;
  let semicolons = 0;
  let braces = 0;

  let tagHash = 0x811c9dc5;
  let tagNameCount = 0;
  let scannedBytes = 0;

  for (const range of ranges) {
    const from = range.start;
    const to = range.end;
    scannedBytes += to - from;

    // Reset sequence-dependent state at each range boundary. Carrying automaton state or the
    // previous byte across an elided region -- whether the middle of a capped body or an excised
    // reflection -- would manufacture keyword matches and bigrams that do not exist in the
    // response. An excised payload is exactly where such a phantom would be most misleading.
    let state = 0;
    let prev = -1;
    let inTagName = false;

    for (let i = from; i < to; i++) {
      const raw = bytes[i]!;

      switch (raw) {
        case 0x0a:
          newlines++;
          break;
        case 0x20:
          spaces++;
          break;
        case 0x3c:
          tags++;
          break;
        case 0x3d:
          equals++;
          break;
        case 0x22:
          quotes++;
          break;
        case 0x2c:
          commas++;
          break;
        case 0x3b:
          semicolons++;
          break;
        case 0x7b:
        case 0x7d:
          braces++;
          break;
        default:
          if (raw >= 0x30 && raw <= 0x39) digits++;
          break;
      }

      // ASCII case fold once; both the automaton and the bigram histogram use folded bytes
      // so that a response differing only in letter case is not treated as different.
      const folded = raw >= 0x41 && raw <= 0x5a ? raw + 32 : raw;

      state = next[(state << 8) | folded]!;
      const emit = outIndex[state]!;
      if (emit !== -1) {
        const hits = outLists[emit]!;
        for (let h = 0; h < hits.length; h++) {
          const k = hits[h]!;
          keywords[k] = keywords[k]! + 1;
        }
      }

      if (prev !== -1) {
        const bucket = (prev * 31 + folded) & BIGRAM_MASK;
        bigrams[bucket] = bigrams[bucket]! + 1;
      }
      prev = folded;

      // Tag-name sequence: a cheap structural proxy. Caido's backend SDK ships no HTML
      // parser, and a real parse is far too expensive per response here, but the ordered
      // sequence of tag names captures layout changes that byte counters miss.
      if (raw === 0x3c) {
        inTagName = true;
        tagNameCount++;
      } else if (inTagName) {
        if (
          raw === 0x20 ||
          raw === 0x3e ||
          raw === 0x0a ||
          raw === 0x0d ||
          raw === 0x09
        ) {
          inTagName = false;
          tagHash = fnv1a(tagHash, 0x3e);
        } else {
          tagHash = fnv1a(tagHash, folded);
        }
      }
    }
  }

  return {
    bodyLength,
    scannedBytes,
    truncated: windows.length > 1,
    excisedBytes,
    newlines,
    spaces,
    tags,
    equals,
    quotes,
    commas,
    digits,
    semicolons,
    braces,
    keywords,
    bigrams,
    tagHash: tagNameCount === 0 ? 0 : tagHash >>> 0,
    tagNameCount,
  };
}

function fnv1a(hash: number, byte: number): number {
  return (Math.imul(hash ^ byte, 0x01000193) >>> 0) >>> 0;
}

/**
 * Cosine similarity between two bigram histograms, in [0, 1].
 *
 * Measured at 0.125 ms per comparison for 4096 buckets under QuickJS, versus 1.83 ms for
 * 65536 buckets, with no loss of discrimination on the cases tested (identical bodies score
 * 1.000000; an HTML page against a minified JSON document of the same size scores 0.073).
 * Hence 4096: fifteen times cheaper to compare and 16 KiB rather than 256 KiB to retain.
 */
export function bigramCosine(a: Int32Array, b: Int32Array): number {
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < BIGRAM_BUCKETS; i++) {
    const x = a[i]!;
    const y = b[i]!;
    if (x !== 0 || y !== 0) {
      dot += x * y;
      na += x * x;
      nb += y * y;
    }
  }
  if (na === 0 || nb === 0) return na === nb ? 1 : 0;
  return dot / Math.sqrt(na * nb);
}

/**
 * Offset of the first body byte in a raw HTTP response, i.e. just past the CRLFCRLF (or
 * LFLF) header terminator. Returns `bytes.length` when no terminator is present.
 */
export function findBodyStart(bytes: Uint8Array): number {
  let consecutiveNewlines = 0;
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i]!;
    if (c === 0x0a) {
      consecutiveNewlines++;
      if (consecutiveNewlines === 2) return i + 1;
    } else if (c !== 0x0d) {
      consecutiveNewlines = 0;
    }
  }
  return bytes.length;
}
