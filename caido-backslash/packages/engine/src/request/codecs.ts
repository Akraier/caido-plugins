/**
 * Per-surface payload encoding.
 *
 * Three rules govern everything here.
 *
 * 1. **Encode as little as possible.** Every byte we rewrite is a byte the server-side
 *    interpreter does not see as we intended. The prior Java tool encoded only
 *    `% NUL & # SP ; + LF CR` and the high range, and that minimalism was correct.
 *
 * 2. **Never silently mangle.** Where a byte cannot be delivered on a surface at all -- CR, LF and
 *    NUL in a header value are structurally impossible -- the probe is REFUSED with a named
 *    reason and the refusal is reported. Quietly substituting something deliverable would turn a
 *    false negative into an invisible one.
 *
 * 3. **Both arms take the identical code path.** The break and its escape are encoded by the same
 *    codec with the same table, and a refusal is evaluated over both arms together so it is
 *    symmetric. If one arm were encoded differently from the other, the encoder itself would
 *    manufacture the label-dependent difference the whole design exists to avoid.
 */

/** Why a payload cannot be delivered on a surface. */
export type RefusalReason =
  /** CR, LF or NUL on a surface whose framing cannot carry it. */
  | "undeliverable-control-byte"
  /** The payload contains the multipart boundary token. */
  | "payload-collides-with-framing"
  /** The surface cannot represent this payload shape at all, e.g. text in a JSON number. */
  | "surface-inapplicable";

export type EncodeResult =
  | { readonly ok: true; readonly bytes: Uint8Array }
  | { readonly ok: false; readonly reason: RefusalReason; readonly detail: string };

/**
 * How the payload's own bytes should be read.
 *
 * `literal` means the payload is the exact character sequence the interpreter should receive, so a
 * `%` in it is a literal percent sign and must be encoded to survive.
 *
 * `pre-encoded` means the catalogue already wrote the payload in wire form. The backend parameter
 * pollution family does this: its payloads are strings like `%3c%61%60%27%22%24%7b%7b%5c`.
 * Encoding those again produces `%253c...`, which is a verified defect of the library alternative
 * and silently destroys the family. Pre-encoded payloads pass through untouched.
 */
export type WireForm = "literal" | "pre-encoded";

const NUL = 0x00;
const LF = 0x0a;
const CR = 0x0d;

function table(mustEncode: readonly number[]): Uint8Array {
  const flags = new Uint8Array(256);
  for (const byte of mustEncode) flags[byte] = 1;
  return flags;
}

const HEX = "0123456789ABCDEF";

function percentEncode(payload: Uint8Array, flags: Uint8Array): Uint8Array {
  let extra = 0;
  for (const byte of payload) if (flags[byte] === 1) extra += 2;
  if (extra === 0) return payload;

  const out = new Uint8Array(payload.length + extra);
  let w = 0;
  for (const byte of payload) {
    if (flags[byte] === 1) {
      out[w++] = 0x25;
      out[w++] = HEX.charCodeAt(byte >> 4);
      out[w++] = HEX.charCodeAt(byte & 0x0f);
    } else {
      out[w++] = byte;
    }
  }
  return out;
}

/**
 * Query string values.
 *
 * `+` is encoded deliberately. On a query surface a raw `+` decodes to a space, which is a
 * verified collapse: the catalogue tries both `+` and `" "` as concatenation operators, and
 * without this they arrive identically, wasting a whole probe pair and losing the ability to tell
 * which operator actually worked. `%` is encoded so a literal percent survives; `=` is not, since
 * a value may legitimately contain one.
 */
export const QUERY_VALUE_FLAGS = table([NUL, CR, LF, 0x20, 0x26, 0x23, 0x2b, 0x25]);

/** Query parameter names additionally cannot carry a raw `=`. */
export const QUERY_NAME_FLAGS = table([NUL, CR, LF, 0x20, 0x26, 0x23, 0x2b, 0x25, 0x3d]);

/** urlencoded body values. Same grammar as the query. */
export const FORM_VALUE_FLAGS = QUERY_VALUE_FLAGS;

/** Cookie values: `;` and SP terminate a crumb, `,` splits on some stacks. */
export const COOKIE_VALUE_FLAGS = table([NUL, CR, LF, 0x20, 0x3b, 0x2c, 0x25]);

/**
 * Path segments.
 *
 * `/` and `.` are deliberately NOT encoded. The entire path family exists to send `../`, `..;/`
 * and `x/../xyz`; encoding the separator turns those into `..%2F`, which is a different test
 * entirely and neuters the family. Verified: that is exactly what happens when the reserved set is
 * applied naively to a path segment.
 */
export const PATH_SEGMENT_FLAGS = table([NUL, CR, LF, 0x20, 0x3f, 0x23, 0x25]);

export interface Codec {
  readonly name: string;
  encode(payload: Uint8Array, wireForm: WireForm): EncodeResult;
}

function percentCodec(name: string, flags: Uint8Array): Codec {
  return {
    name,
    encode(payload, wireForm) {
      if (wireForm === "pre-encoded") {
        // Already wire-form. Still refuse raw control bytes, which no amount of prior encoding
        // could have intended.
        for (const byte of payload) {
          if (byte === NUL || byte === CR || byte === LF) {
            return {
              ok: false,
              reason: "undeliverable-control-byte",
              detail: `pre-encoded payload contains a raw control byte 0x${byte.toString(16)}`,
            };
          }
        }
        return { ok: true, bytes: payload };
      }
      return { ok: true, bytes: percentEncode(payload, flags) };
    },
  };
}

/**
 * Header values, and any surface whose framing is line-based.
 *
 * CR, LF and NUL are refused rather than encoded: there is no encoding of them that a header value
 * can carry, and percent-encoding would be meaningless because nothing decodes a header value.
 */
export const CTL_ONLY: Codec = {
  name: "ctl-only",
  encode(payload) {
    for (let i = 0; i < payload.length; i++) {
      const byte = payload[i]!;
      if (byte === NUL || byte === CR || byte === LF) {
        return {
          ok: false,
          reason: "undeliverable-control-byte",
          detail: `byte 0x${byte.toString(16).padStart(2, "0")} at offset ${i} cannot be carried by a header value`,
        };
      }
    }
    return { ok: true, bytes: payload };
  },
};

/** Verbatim. Used where the surface imposes no framing constraint, e.g. a multipart text part. */
export const IDENTITY: Codec = {
  name: "identity",
  encode(payload) {
    return { ok: true, bytes: payload };
  },
};

/**
 * A JSON string interior.
 *
 * Escapes only what RFC 8259 requires, so the payload reaches the interpreter *behind* the JSON
 * parser intact. Note this is one of two modes over the same byte range: the other splices the
 * payload verbatim to produce deliberately invalid JSON and test the parser itself.
 */
export const JSON_ESCAPE: Codec = {
  name: "json-escape",
  encode(payload) {
    const out: number[] = [];
    for (const byte of payload) {
      switch (byte) {
        case 0x22:
          out.push(0x5c, 0x22);
          break;
        case 0x5c:
          out.push(0x5c, 0x5c);
          break;
        case 0x08:
          out.push(0x5c, 0x62);
          break;
        case 0x0c:
          out.push(0x5c, 0x66);
          break;
        case LF:
          out.push(0x5c, 0x6e);
          break;
        case CR:
          out.push(0x5c, 0x72);
          break;
        case 0x09:
          out.push(0x5c, 0x74);
          break;
        default:
          if (byte < 0x20) {
            const hex = byte.toString(16).padStart(4, "0");
            out.push(0x5c, 0x75);
            for (const ch of hex) out.push(ch.charCodeAt(0));
          } else {
            out.push(byte);
          }
          break;
      }
    }
    return { ok: true, bytes: Uint8Array.from(out) };
  },
};

export const QUERY_VALUE_CODEC = percentCodec("pct-query-value", QUERY_VALUE_FLAGS);
export const QUERY_NAME_CODEC = percentCodec("pct-query-name", QUERY_NAME_FLAGS);
export const FORM_VALUE_CODEC = percentCodec("pct-form-value", FORM_VALUE_FLAGS);
export const COOKIE_VALUE_CODEC = percentCodec("pct-cookie-value", COOKIE_VALUE_FLAGS);
export const PATH_SEGMENT_CODEC = percentCodec("pct-path-segment", PATH_SEGMENT_FLAGS);

/**
 * Encode both arms of a probe pair together.
 *
 * Symmetry is the point. If either arm is undeliverable the pair is refused as a whole, because
 * running only one arm compares a payload against nothing and any resulting difference would be
 * attributable to the missing send rather than the payload.
 */
export function encodePair(
  codec: Codec,
  breakPayload: Uint8Array,
  escapePayload: Uint8Array,
  wireForm: WireForm = "literal",
):
  | {
      readonly ok: true;
      readonly breakBytes: Uint8Array;
      readonly escapeBytes: Uint8Array;
    }
  | { readonly ok: false; readonly reason: RefusalReason; readonly detail: string } {
  const encodedBreak = codec.encode(breakPayload, wireForm);
  if (!encodedBreak.ok) return encodedBreak;
  const encodedEscape = codec.encode(escapePayload, wireForm);
  if (!encodedEscape.ok) return encodedEscape;
  return { ok: true, breakBytes: encodedBreak.bytes, escapeBytes: encodedEscape.bytes };
}
