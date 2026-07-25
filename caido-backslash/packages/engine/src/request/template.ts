/**
 * Immutable request template and byte-exact assembly.
 *
 * A probe request is the original bytes with exactly one contiguous range replaced, and
 * `Content-Length` patched if the body length changed. Nothing else is touched: header order,
 * header casing, optional whitespace, line-ending style and any malformed framing all survive
 * untouched.
 *
 * That is a statistical requirement, not fastidiousness. The verdict rests on a permutation null
 * over M cross pairs whose validity assumes the break and escape sends differ *only* in the
 * payload bytes. A layer that re-serialises can introduce a difference correlated with the arm
 * label, and a label-dependent difference does not add noise, it fabricates a perfectly separated
 * witness with zero within-arm variance. Verified failures in the obvious library alternative
 * include truncating a query at the first space and turning `%3c` into `%253c` (see
 * docs/adr/002-request-layer.md).
 *
 * Parsing here therefore only ever *locates*. It never rebuilds.
 */

const CR = 0x0d;
const LF = 0x0a;
const SP = 0x20;
const HTAB = 0x09;
const COLON = 0x3a;

/** A half-open byte range within the template. */
export interface Range {
  readonly start: number;
  readonly end: number;
}

export interface HeaderField {
  /** Lowercased name, for lookup. */
  readonly name: string;
  /** Range of the name token. */
  readonly nameRange: Range;
  /**
   * Range of the value, with leading and trailing optional whitespace excluded but the original
   * bytes otherwise intact. Includes any obs-fold continuation lines.
   */
  readonly valueRange: Range;
  /** Range of the entire field including its line terminator. */
  readonly lineRange: Range;
  /** True when the field used obsolete line folding. */
  readonly folded: boolean;
}

/** Why body surfaces are unavailable on this request. */
export type BodyRestriction =
  | "chunked"
  | "content-encoded"
  | "no-body"
  | "malformed-framing";

export interface RequestTemplate {
  readonly raw: Uint8Array;
  readonly methodRange: Range;
  readonly targetRange: Range;
  readonly versionRange: Range;
  readonly headers: readonly HeaderField[];
  /** Offset of the first body byte. Equals `raw.length` when there is no body. */
  readonly bodyStart: number;
  readonly bodyRange: Range;
  /**
   * Set when the body must not be spliced. Query, cookie, header and path surfaces remain
   * available; body surfaces are skipped with this reason recorded, never silently.
   */
  readonly bodyRestriction?: BodyRestriction;
  /** Line terminator observed in the head: CRLF or bare LF. */
  readonly eol: "crlf" | "lf";
  /** Range of the Content-Length value, when present, so it can be patched in place. */
  readonly contentLengthValueRange?: Range;
}

export function rangeLength(range: Range): number {
  return range.end - range.start;
}

export function sliceText(raw: Uint8Array, range: Range): string {
  let out = "";
  for (let i = range.start; i < range.end; i++) out += String.fromCharCode(raw[i]!);
  return out;
}

/** Trim leading and trailing SP/HTAB from a range without copying. */
function trimOws(raw: Uint8Array, start: number, end: number): Range {
  let s = start;
  let e = end;
  while (s < e && (raw[s] === SP || raw[s] === HTAB)) s++;
  while (e > s && (raw[e - 1] === SP || raw[e - 1] === HTAB)) e--;
  return { start: s, end: e };
}

/**
 * Index just past the end of the line beginning at `from`, and the index of the line's last
 * content byte. Handles CRLF and bare LF. Returns -1 for `next` when no terminator is found.
 */
function lineEnd(raw: Uint8Array, from: number): { contentEnd: number; next: number } {
  let i = from;
  while (i < raw.length && raw[i] !== LF) i++;
  if (i >= raw.length) return { contentEnd: raw.length, next: -1 };
  // A CR immediately before the LF belongs to the terminator, not the content.
  const contentEnd = i > from && raw[i - 1] === CR ? i - 1 : i;
  return { contentEnd, next: i + 1 };
}

function isOwsByte(byte: number | undefined): boolean {
  return byte === SP || byte === HTAB;
}

export class MalformedRequestError extends Error {}

/**
 * Locate the structure of a raw HTTP/1.x request.
 *
 * Deliberately permissive: a request that a strict parser would reject is still probeable, and
 * refusing to scan it would be a false negative. Only genuinely unusable input throws.
 */
export function locate(raw: Uint8Array): RequestTemplate {
  if (raw.length === 0) throw new MalformedRequestError("empty request");

  // ---- request line ----
  const first = lineEnd(raw, 0);
  if (first.next === -1) throw new MalformedRequestError("no line terminator in request line");

  let cursor = 0;
  while (cursor < first.contentEnd && raw[cursor] !== SP) cursor++;
  const methodRange: Range = { start: 0, end: cursor };
  if (rangeLength(methodRange) === 0) throw new MalformedRequestError("empty method");

  while (cursor < first.contentEnd && raw[cursor] === SP) cursor++;
  const targetStart = cursor;
  // The target ends at the LAST space on the line, so a target containing a raw space -- which is
  // illegal but occurs, and which the obvious library truncates at -- keeps its full extent.
  let lastSpace = -1;
  for (let i = targetStart; i < first.contentEnd; i++) {
    if (raw[i] === SP) lastSpace = i;
  }
  const targetEnd = lastSpace === -1 ? first.contentEnd : lastSpace;
  const targetRange: Range = { start: targetStart, end: targetEnd };
  const versionRange: Range =
    lastSpace === -1
      ? { start: first.contentEnd, end: first.contentEnd }
      : { start: lastSpace + 1, end: first.contentEnd };

  const eol: "crlf" | "lf" = first.contentEnd < first.next - 1 ? "crlf" : "lf";

  // ---- header fields ----
  const headers: HeaderField[] = [];
  let pos = first.next;
  let bodyStart = raw.length;

  while (pos < raw.length) {
    const line = lineEnd(raw, pos);
    const contentEnd = line.contentEnd;

    // A line whose content is empty terminates the head. Note the deliberate strictness: a line
    // containing only spaces is NOT a terminator, it is a malformed header line. Treating it as a
    // terminator is the verified V2 defect, which mislocated the body by two bytes and made
    // getHeader return null.
    if (contentEnd === pos) {
      bodyStart = line.next === -1 ? raw.length : line.next;
      break;
    }

    if (line.next === -1) {
      // Head ran to end of input with no blank line: no body.
      const fieldEnd = contentEnd;
      pushField(raw, headers, pos, fieldEnd, raw.length, false);
      pos = raw.length;
      bodyStart = raw.length;
      break;
    }

    // Obsolete line folding: a continuation line starts with SP or HTAB.
    let fieldContentEnd = contentEnd;
    let nextPos = line.next;
    let folded = false;
    while (nextPos < raw.length && isOwsByte(raw[nextPos])) {
      folded = true;
      const cont = lineEnd(raw, nextPos);
      fieldContentEnd = cont.contentEnd;
      if (cont.next === -1) {
        nextPos = raw.length;
        break;
      }
      nextPos = cont.next;
    }

    pushField(raw, headers, pos, fieldContentEnd, nextPos, folded);
    pos = nextPos;
    if (pos >= raw.length) bodyStart = raw.length;
  }

  const bodyRange: Range = { start: bodyStart, end: raw.length };

  const template: {
    -readonly [K in keyof RequestTemplate]: RequestTemplate[K];
  } = {
    raw,
    methodRange,
    targetRange,
    versionRange,
    headers,
    bodyStart,
    bodyRange,
    eol,
  };

  const contentLength = findHeader(headers, "content-length");
  if (contentLength !== undefined) {
    template.contentLengthValueRange = contentLength.valueRange;
  }

  const restriction = classifyBody(raw, headers, bodyRange);
  if (restriction !== undefined) template.bodyRestriction = restriction;

  return template as RequestTemplate;
}

function pushField(
  raw: Uint8Array,
  into: HeaderField[],
  lineStart: number,
  contentEnd: number,
  lineEndExclusive: number,
  folded: boolean,
): void {
  let colon = -1;
  for (let i = lineStart; i < contentEnd; i++) {
    if (raw[i] === COLON) {
      colon = i;
      break;
    }
  }
  if (colon === -1) {
    // A header line with no colon is malformed. Record it with an empty value rather than
    // dropping it, so it still contributes to the header-name digest.
    into.push({
      name: sliceText(raw, { start: lineStart, end: contentEnd }).toLowerCase(),
      nameRange: { start: lineStart, end: contentEnd },
      valueRange: { start: contentEnd, end: contentEnd },
      lineRange: { start: lineStart, end: lineEndExclusive },
      folded,
    });
    return;
  }
  const nameRange: Range = { start: lineStart, end: colon };
  const valueRange = trimOws(raw, colon + 1, contentEnd);
  into.push({
    name: sliceText(raw, nameRange).toLowerCase(),
    nameRange,
    valueRange,
    lineRange: { start: lineStart, end: lineEndExclusive },
    folded,
  });
}

export function findHeader(
  headers: readonly HeaderField[],
  name: string,
): HeaderField | undefined {
  const wanted = name.toLowerCase();
  return headers.find((h) => h.name === wanted);
}

export function headerValue(
  template: RequestTemplate,
  name: string,
): string | undefined {
  const field = findHeader(template.headers, name);
  return field === undefined ? undefined : sliceText(template.raw, field.valueRange);
}

function classifyBody(
  raw: Uint8Array,
  headers: readonly HeaderField[],
  bodyRange: Range,
): BodyRestriction | undefined {
  const te = findHeader(headers, "transfer-encoding");
  if (te !== undefined) {
    const value = sliceText(raw, te.valueRange).toLowerCase();
    // Splicing into chunk data would require rewriting chunk sizes. Refuse and say so.
    if (value.includes("chunked")) return "chunked";
  }
  const ce = findHeader(headers, "content-encoding");
  if (ce !== undefined && sliceText(raw, ce.valueRange).trim() !== "") {
    return "content-encoded";
  }
  if (rangeLength(bodyRange) === 0) return "no-body";
  return undefined;
}

/** A single replacement: substitute `bytes` for `range`. */
export interface Edit {
  readonly range: Range;
  readonly bytes: Uint8Array;
}

export interface AssembleOptions {
  /**
   * Patch Content-Length to the resulting body length. Default true.
   *
   * Turning this off is a probe in its own right, so it is a parameter rather than always-on.
   */
  readonly patchContentLength?: boolean;
}

/**
 * Produce the probe request bytes.
 *
 * Edits must not overlap. They are applied in a single pass over the original buffer, so the
 * output is byte-identical to the input outside the edited ranges by construction.
 */
export function assemble(
  template: RequestTemplate,
  edits: readonly Edit[],
  options: AssembleOptions = {},
): Uint8Array {
  const ordered = [...edits].sort((a, b) => a.range.start - b.range.start);
  for (let i = 1; i < ordered.length; i++) {
    if (ordered[i]!.range.start < ordered[i - 1]!.range.end) {
      throw new Error("overlapping edits");
    }
  }
  for (const edit of ordered) {
    if (edit.range.start < 0 || edit.range.end > template.raw.length) {
      throw new Error("edit out of bounds");
    }
    if (edit.range.end < edit.range.start) throw new Error("inverted edit range");
  }

  const spliced = splice(template.raw, ordered);

  if (options.patchContentLength === false) return spliced;

  const clRange = template.contentLengthValueRange;
  if (clRange === undefined) return spliced;

  // Body length after the edits: original body length plus the net delta of edits that fall
  // inside the body.
  let delta = 0;
  for (const edit of ordered) {
    if (edit.range.start >= template.bodyStart) {
      delta += edit.bytes.length - rangeLength(edit.range);
    }
  }
  if (delta === 0) return spliced;

  const newBodyLength = rangeLength(template.bodyRange) + delta;

  // The Content-Length value may itself have shifted if an edit preceded it.
  let shift = 0;
  for (const edit of ordered) {
    if (edit.range.end <= clRange.start) shift += edit.bytes.length - rangeLength(edit.range);
  }
  const target: Range = { start: clRange.start + shift, end: clRange.end + shift };

  return splice(spliced, [{ range: target, bytes: asciiBytes(String(newBodyLength)) }]);
}

function splice(source: Uint8Array, edits: readonly Edit[]): Uint8Array {
  let size = source.length;
  for (const edit of edits) size += edit.bytes.length - rangeLength(edit.range);

  const out = new Uint8Array(size);
  let read = 0;
  let write = 0;
  for (const edit of edits) {
    const head = edit.range.start - read;
    out.set(source.subarray(read, edit.range.start), write);
    write += head;
    out.set(edit.bytes, write);
    write += edit.bytes.length;
    read = edit.range.end;
  }
  out.set(source.subarray(read), write);
  return out;
}

export function asciiBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}
