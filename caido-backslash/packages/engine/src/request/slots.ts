/**
 * Slot enumeration.
 *
 * A slot is one injectable byte range in a {@link RequestTemplate}, plus the codec that governs
 * what may be written into it. Enumeration only ever locates ranges; it never rewrites the request,
 * and it never decodes a value in order to find it. Decoding to locate is how the library
 * alternative ended up truncating a query at the first space.
 *
 * Day-one surfaces are the URL, form body, cookie, header and path families. JSON document paths
 * and multipart parts are enumerated in a later commit; until then they are reported as deferred
 * rather than silently omitted.
 */

import {
  COOKIE_VALUE_CODEC,
  CTL_ONLY,
  type Codec,
  FORM_VALUE_CODEC,
  IDENTITY,
  JSON_ESCAPE,
  PATH_SEGMENT_CODEC,
  QUERY_NAME_CODEC,
  QUERY_VALUE_CODEC,
} from "./codecs.ts";
import { scanJson } from "./json.ts";
import {
  type Range,
  type RequestTemplate,
  findHeader,
  rangeLength,
  sliceText,
} from "./template.ts";

export type SurfaceKind =
  | "query-value"
  | "query-name"
  | "form-value"
  | "cookie-value"
  | "header-value"
  | "new-header"
  | "path-segment"
  | "path-suffix"
  /** Interior of a JSON string. Escaped payload: tests the interpreter behind the parser. */
  | "json-string"
  /**
   * The same string including its quotes, spliced verbatim. Produces deliberately invalid JSON and
   * tests the parser itself. This is the JSON key/value cascade edge, and it is unreachable through
   * any library serialiser because a serialiser exists to produce valid output.
   */
  | "json-raw-span"
  /** A JSON number literal. The integer context where blind SQL injection lives. */
  | "json-number"
  | "json-bool"
  | "json-key";

/**
 * Families gate independently, so a crude-syntax rejection on one surface does not suppress the
 * others. This is what keeps an integer-valued parameter testable even when the syntax family has
 * already been dismissed for the endpoint.
 */
export type SurfaceFamily = "url" | "body" | "cookie" | "header" | "path";

export interface Slot {
  readonly kind: SurfaceKind;
  readonly family: SurfaceFamily;
  /** Human-facing identifier, stable for a given request, used in findings and diagnostics. */
  readonly name: string;
  /** The byte range replaced by an injected payload. Zero-width for insertion slots. */
  readonly range: Range;
  /** The parameter's existing value as raw text, empty for insertion slots. */
  readonly baseValue: string;
  readonly codec: Codec;
  /**
   * True where the value's shape carries meaning, so a random anchor must not be inserted and the
   * probe families that need a bare integer or identifier remain applicable.
   */
  readonly positional: boolean;
}

export interface DeferredSurface {
  readonly kind: string;
  readonly reason: string;
}

export interface SlotEnumeration {
  readonly slots: readonly Slot[];
  /** Surfaces present on this request but not yet injectable. Reported, never silently dropped. */
  readonly deferred: readonly DeferredSurface[];
}

/** Headers that must never be treated as injectable, because doing so breaks the exchange. */
const HEADER_DENYLIST: ReadonlySet<string> = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "upgrade",
  "expect",
  "cookie", // enumerated per crumb instead
]);

/**
 * Header names whose value is integrity-protected, so probing them is wasted traffic: every arm
 * invalidates the signature equally and the surface degenerates to a stable rejection.
 */
const INTEGRITY_HEADERS: readonly string[] = [
  "authorization",
  "x-signature",
  "x-hub-signature",
  "x-amz-signature",
  "signature",
  "x-csrf-token",
  "x-xsrf-token",
];

function isIntegrityProtected(name: string): boolean {
  return INTEGRITY_HEADERS.some((h) => name === h || name.startsWith(`${h}-`));
}

/** Split a `name=value&...` region into value and name ranges without decoding anything. */
function enumerateFormEncoded(
  template: RequestTemplate,
  region: Range,
  kind: "query" | "form",
): Slot[] {
  const slots: Slot[] = [];
  const raw = template.raw;
  let cursor = region.start;

  while (cursor < region.end) {
    let sep = cursor;
    while (sep < region.end && raw[sep] !== 0x26) sep++; // '&'

    let eq = cursor;
    while (eq < sep && raw[eq] !== 0x3d) eq++; // '='

    const nameRange: Range = { start: cursor, end: eq };
    const hasEquals = eq < sep;
    const valueRange: Range = hasEquals ? { start: eq + 1, end: sep } : { start: sep, end: sep };

    if (rangeLength(nameRange) > 0) {
      const name = sliceText(raw, nameRange);
      const baseValue = sliceText(raw, valueRange);
      slots.push({
        kind: kind === "query" ? "query-value" : "form-value",
        family: kind === "query" ? "url" : "body",
        name,
        range: valueRange,
        baseValue,
        codec: kind === "query" ? QUERY_VALUE_CODEC : FORM_VALUE_CODEC,
        positional: looksPositional(baseValue),
      });
      if (kind === "query") {
        slots.push({
          kind: "query-name",
          family: "url",
          name: `${name} (name)`,
          range: nameRange,
          baseValue: name,
          codec: QUERY_NAME_CODEC,
          positional: false,
        });
      }
    }

    cursor = sep + 1;
  }

  return slots;
}

/**
 * Whether a value's shape carries meaning.
 *
 * A bare integer or a plain identifier is the context where arithmetic and order-by probes live, so
 * inserting a random anchor would destroy the very property being tested. Twenty probes in the
 * catalogue disable the anchor for exactly this reason.
 */
export function looksPositional(value: string): boolean {
  if (value === "") return false;
  return /^[A-Za-z0-9._:$-]+$/.test(value);
}

function enumerateJson(template: RequestTemplate): {
  slots: Slot[];
  deferred: DeferredSurface[];
} {
  const slots: Slot[] = [];
  const deferred: DeferredSurface[] = [];
  const result = scanJson(template.raw, template.bodyRange.start, template.bodyRange.end);

  if (result.error !== undefined && result.sites.length === 0) {
    deferred.push({
      kind: "body:json",
      reason: `not parseable as JSON (${result.error}); body treated as opaque`,
    });
    return { slots, deferred };
  }
  if (result.error !== undefined) {
    deferred.push({
      kind: "body:json:partial",
      reason: `scan stopped early (${result.error}); sites after that point were not enumerated`,
    });
  }

  for (const site of result.sites) {
    switch (site.kind) {
      case "string":
        slots.push({
          kind: "json-string",
          family: "body",
          name: site.pointer,
          range: site.range,
          baseValue: sliceText(template.raw, site.range),
          codec: JSON_ESCAPE,
          positional: false,
        });
        // Same content, second mode: splice over the quotes to attack the parser itself.
        slots.push({
          kind: "json-raw-span",
          family: "body",
          name: `${site.pointer} (raw)`,
          range: site.tokenRange,
          baseValue: sliceText(template.raw, site.tokenRange),
          codec: IDENTITY,
          positional: false,
        });
        break;
      case "number":
        slots.push({
          kind: "json-number",
          family: "body",
          name: site.pointer,
          range: site.range,
          baseValue: sliceText(template.raw, site.range),
          codec: IDENTITY,
          positional: true,
        });
        break;
      case "bool":
      case "null":
        slots.push({
          kind: "json-bool",
          family: "body",
          name: site.pointer,
          range: site.range,
          baseValue: sliceText(template.raw, site.range),
          codec: IDENTITY,
          positional: true,
        });
        break;
      case "key":
        slots.push({
          kind: "json-key",
          family: "body",
          name: `${site.pointer} (key)`,
          range: site.range,
          baseValue: sliceText(template.raw, site.range),
          codec: JSON_ESCAPE,
          positional: false,
        });
        break;
    }
  }

  return { slots, deferred };
}

function enumerateCookies(template: RequestTemplate): Slot[] {
  const slots: Slot[] = [];
  const raw = template.raw;
  for (const field of template.headers) {
    if (field.name !== "cookie") continue;
    let cursor = field.valueRange.start;
    const end = field.valueRange.end;
    while (cursor < end) {
      let sep = cursor;
      while (sep < end && raw[sep] !== 0x3b) sep++; // ';'
      // Skip optional whitespace after the previous separator without shifting the value range.
      let crumbStart = cursor;
      while (crumbStart < sep && (raw[crumbStart] === 0x20 || raw[crumbStart] === 0x09)) {
        crumbStart++;
      }
      let eq = crumbStart;
      while (eq < sep && raw[eq] !== 0x3d) eq++;
      if (eq < sep) {
        const name = sliceText(raw, { start: crumbStart, end: eq });
        const valueRange: Range = { start: eq + 1, end: sep };
        slots.push({
          kind: "cookie-value",
          family: "cookie",
          name,
          range: valueRange,
          baseValue: sliceText(raw, valueRange),
          codec: COOKIE_VALUE_CODEC,
          positional: looksPositional(sliceText(raw, valueRange)),
        });
      }
      cursor = sep + 1;
    }
  }
  return slots;
}

function enumeratePath(template: RequestTemplate): Slot[] {
  const slots: Slot[] = [];
  const raw = template.raw;
  const target = template.targetRange;

  // The path ends at the first '?' or '#'; everything after is query or fragment.
  let pathEnd = target.end;
  for (let i = target.start; i < target.end; i++) {
    const byte = raw[i]!;
    if (byte === 0x3f || byte === 0x23) {
      pathEnd = i;
      break;
    }
  }

  let cursor = target.start;
  // Skip a leading slash so the first segment is not an empty one.
  if (cursor < pathEnd && raw[cursor] === 0x2f) cursor++;

  let index = 0;
  while (cursor <= pathEnd) {
    let sep = cursor;
    while (sep < pathEnd && raw[sep] !== 0x2f) sep++;
    if (sep > cursor) {
      const range: Range = { start: cursor, end: sep };
      slots.push({
        kind: "path-segment",
        family: "path",
        name: `segment[${index}]`,
        range,
        baseValue: sliceText(raw, range),
        codec: PATH_SEGMENT_CODEC,
        positional: true,
      });
      index++;
    }
    if (sep >= pathEnd) break;
    cursor = sep + 1;
  }

  // Zero-width slot at the end of the path, for the traversal and alias-escape families which
  // append rather than replace.
  slots.push({
    kind: "path-suffix",
    family: "path",
    name: "path-suffix",
    range: { start: pathEnd, end: pathEnd },
    baseValue: "",
    codec: PATH_SEGMENT_CODEC,
    positional: true,
  });

  return slots;
}

function enumerateHeaders(template: RequestTemplate): {
  slots: Slot[];
  deferred: DeferredSurface[];
} {
  const slots: Slot[] = [];
  const deferred: DeferredSurface[] = [];
  for (const field of template.headers) {
    if (HEADER_DENYLIST.has(field.name)) continue;
    if (isIntegrityProtected(field.name)) {
      deferred.push({
        kind: `header:${field.name}`,
        reason:
          "integrity-protected: every arm invalidates the signature equally, so the surface " +
          "degenerates to a stable rejection and probing it is wasted traffic",
      });
      continue;
    }
    if (field.folded) {
      deferred.push({
        kind: `header:${field.name}`,
        reason: "obsolete line folding: splicing a folded value needs its own fixture set",
      });
      continue;
    }
    slots.push({
      kind: "header-value",
      family: "header",
      name: field.name,
      range: field.valueRange,
      baseValue: sliceText(template.raw, field.valueRange),
      codec: CTL_ONLY,
      positional: false,
    });
  }
  return { slots, deferred };
}

export interface EnumerateOptions {
  /** Include query and form parameter NAME slots. Noisier, so gated. */
  readonly includeNames?: boolean;
  /** Include a zero-width slot for injecting a fresh header, used by calibration tripwires. */
  readonly includeNewHeader?: boolean;
}

export function enumerateSlots(
  template: RequestTemplate,
  options: EnumerateOptions = {},
): SlotEnumeration {
  const slots: Slot[] = [];
  const deferred: DeferredSurface[] = [];
  const raw = template.raw;

  // ---- query ----
  let queryStart = -1;
  for (let i = template.targetRange.start; i < template.targetRange.end; i++) {
    if (raw[i] === 0x3f) {
      queryStart = i + 1;
      break;
    }
  }
  if (queryStart !== -1) {
    let queryEnd = template.targetRange.end;
    for (let i = queryStart; i < template.targetRange.end; i++) {
      if (raw[i] === 0x23) {
        queryEnd = i;
        break;
      }
    }
    slots.push(...enumerateFormEncoded(template, { start: queryStart, end: queryEnd }, "query"));
  }

  // ---- body ----
  if (template.bodyRestriction === undefined) {
    const contentType = findHeader(template.headers, "content-type");
    const type =
      contentType === undefined
        ? ""
        : sliceText(raw, contentType.valueRange).toLowerCase();
    if (type.includes("application/x-www-form-urlencoded")) {
      slots.push(...enumerateFormEncoded(template, template.bodyRange, "form"));
    } else if (type.includes("json")) {
      const json = enumerateJson(template);
      slots.push(...json.slots);
      deferred.push(...json.deferred);
    } else if (type.includes("multipart/form-data")) {
      deferred.push({
        kind: "body:multipart",
        reason: "multipart part injection needs boundary-collision detection and its own fixtures",
      });
    } else if (rangeLength(template.bodyRange) > 0) {
      deferred.push({
        kind: `body:${type === "" ? "unknown" : type}`,
        reason: "no grammar for this content type; body surfaces skipped",
      });
    }
  } else if (template.bodyRestriction !== "no-body") {
    deferred.push({
      kind: "body",
      reason: `body not injectable: ${template.bodyRestriction}`,
    });
  }

  // ---- cookies, headers, path ----
  slots.push(...enumerateCookies(template));
  const headerResult = enumerateHeaders(template);
  slots.push(...headerResult.slots);
  deferred.push(...headerResult.deferred);
  slots.push(...enumeratePath(template));

  if (options.includeNewHeader === true) {
    // Just before the blank line that terminates the head.
    const at = Math.max(template.bodyStart - (template.eol === "crlf" ? 2 : 1), 0);
    slots.push({
      kind: "new-header",
      family: "header",
      name: "new-header",
      range: { start: at, end: at },
      baseValue: "",
      codec: CTL_ONLY,
      positional: false,
    });
  }

  // Name-position slots are noisy: injecting into a parameter or member name frequently breaks
  // routing or deserialisation for reasons unrelated to an interpreter, so they are opt-in.
  const filtered =
    options.includeNames === true
      ? slots
      : slots.filter((s) => s.kind !== "query-name" && s.kind !== "json-key");

  return { slots: filtered, deferred };
}
