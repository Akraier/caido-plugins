/**
 * Length equalisation for probe payloads.
 *
 * When a parameter's value is reflected in the response, any length difference between a
 * break payload and its escape payload propagates into every length- and byte-count-derived
 * feature. The response then differs for a reason that has nothing to do with server-side
 * parsing, and the detection rule sees evidence where there is none.
 *
 * Two defences are used together. The decision rule neutralises length-derived features
 * when the observed delta matches what reflection alone predicts (necessary, because for the
 * backslash family odd and even escape counts cannot be the same length by construction).
 * This module supplies the second: make the payloads the same length in the first place,
 * wherever that is possible without changing what they mean.
 */

/** The inert filler character. Alphanumeric so it cannot itself be syntactically special. */
export const FILLER_CHAR = "z";

/** Matches the first run of decimal digits in a payload. */
const FIRST_DIGITS = /\d+/;

/**
 * Widen the first numeric literal with leading zeros so the payload grows by `extra` bytes
 * while its numeric value is unchanged.
 *
 * `abs(1)` widened by 2 becomes `abs(001)`. Returns undefined when there is no numeric
 * literal to widen, so callers can fall back to filler padding.
 */
export function padNumericLiteral(payload: string, extra: number): string | undefined {
  if (extra <= 0) return payload;
  const match = FIRST_DIGITS.exec(payload);
  if (match === null) return undefined;
  const at = match.index;
  return payload.slice(0, at) + "0".repeat(extra) + payload.slice(at);
}

/**
 * Append filler characters. Safe only where trailing alphanumerics cannot change how the
 * payload parses, which is why the caller decides rather than this function.
 */
export function padWithFiller(payload: string, extra: number): string {
  return extra <= 0 ? payload : payload + FILLER_CHAR.repeat(extra);
}

export type PadStrategy = "numeric" | "filler" | "none";

export interface EqualisedPair {
  readonly breakPayload: string;
  readonly escapePayload: string;
  /** How the shorter side was grown, or "none" when they already matched. */
  readonly strategy: PadStrategy;
  /**
   * True when the pair is the same length after equalisation. When false the caller MUST
   * rely on length neutralisation in the decision rule, and should record that it did.
   */
  readonly equal: boolean;
}

/**
 * Make one break payload and one escape payload the same length.
 *
 * Only the SHORTER side is grown, never the longer one shortened, because shortening would
 * require removing characters that carry the meaning of the probe. `numeric` is preferred
 * over `filler` where a numeric literal exists, since widening a literal with leading zeros
 * is value-preserving in every language in the catalogue, whereas appending filler is only
 * safe in some syntactic positions.
 */
export function equalisePair(
  breakPayload: string,
  escapePayload: string,
  preferred: PadStrategy,
): EqualisedPair {
  const delta = breakPayload.length - escapePayload.length;
  if (delta === 0) {
    return { breakPayload, escapePayload, strategy: "none", equal: true };
  }
  if (preferred === "none") {
    return { breakPayload, escapePayload, strategy: "none", equal: false };
  }

  const shorter = delta > 0 ? escapePayload : breakPayload;
  const extra = Math.abs(delta);

  let grown: string | undefined;
  let strategy: PadStrategy = preferred;
  if (preferred === "numeric") {
    grown = padNumericLiteral(shorter, extra);
    if (grown === undefined) {
      grown = padWithFiller(shorter, extra);
      strategy = "filler";
    }
  } else {
    grown = padWithFiller(shorter, extra);
  }

  const result =
    delta > 0
      ? { breakPayload, escapePayload: grown, strategy, equal: true }
      : { breakPayload: grown, escapePayload, strategy, equal: true };

  // Defensive: padding must have closed the gap exactly.
  if (result.breakPayload.length !== result.escapePayload.length) {
    return { breakPayload, escapePayload, strategy: "none", equal: false };
  }
  return result;
}
