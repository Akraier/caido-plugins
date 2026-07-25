/**
 * Probe catalogue types.
 *
 * This module is pure data description. It deliberately contains no execution semantics:
 * how many times a pair is repeated, how responses are compared, and when the cascade
 * escalates are all decisions for the engine, not properties of a payload.
 */

/** Where the payload goes relative to the parameter's original value. */
export type InsertionMode = "append" | "prepend" | "replace";

/**
 * Cascade stage. A stage only runs when its predecessor produced a result, which is what
 * keeps the request cost proportional to how interesting the parameter actually is.
 */
export type ProbeStage =
  | "triage" // is this parameter worth probing at all
  | "delimiter" // which quote or escape character has meaning
  | "escape-sequence" // backslash escapes, unicode escapes, regex metacharacters
  | "interpolation" // template/interpolation syntax
  | "concatenation" // which operator joins two string literals
  | "function" // is a function call actually evaluated
  | "arithmetic" // numeric contexts: division, sub-expressions
  | "order-by" // SQL ORDER BY specific syntax
  | "path" // filesystem and proxy path handling
  | "magic-value" // keywords that select a different code path
  | "structural"; // parameter pollution, JSON document structure

/**
 * How break and escape payloads within a pair can be made equal length.
 *
 * This matters more than it looks. When a parameter's value is reflected in the response,
 * a break payload that is one byte longer than its escape payload shifts every length- and
 * byte-count-derived feature by a predictable amount, for a reason that has nothing to do
 * with server-side parsing. Measured over the original catalogue, 23 of 42 pairs and 11 of
 * 14 language function triples had mismatched lengths, so this is the dominant systematic
 * false-positive mechanism in the whole technique.
 *
 * - "equal"        already equal, nothing to do
 * - "pad-filler"   append or embed an inert filler character to equalise
 * - "pad-numeric"  widen a numeric literal with leading zeros, preserving its value
 * - "impossible"   the semantics require different lengths (odd vs even backslash counts);
 *                  the engine MUST neutralise length-derived features instead of padding
 */
export type LengthParity = "equal" | "pad-filler" | "pad-numeric" | "impossible";

export interface ProbePair {
  /** Stable identifier. Findings reference this, so it must not change once released. */
  readonly id: string;
  readonly name: string;
  readonly stage: ProbeStage;

  /**
   * Payloads expected to break a server-side interpreter, producing a different response.
   */
  readonly breaks: readonly string[];

  /**
   * Alternative escape sets. Each inner array holds interchangeable variants of the same
   * idea (for example backslash-escaping versus doubling a quote); the members of one set
   * are alternatives, and the sets themselves are alternatives too.
   *
   * The engine must fix ONE set and ONE member for the whole verification of a pair and
   * record which. The original Java rotated a shared counter on every access, so the escape
   * payload used to confirm a finding was not the one that produced the difference.
   */
  readonly escapeSets: readonly (readonly string[])[];

  readonly mode: InsertionMode;
  readonly parity: LengthParity;

  /**
   * When this pair fires, the delimiter it proves is meaningful. Feeds the concatenation
   * stage. Undefined when the pair does not identify a delimiter.
   */
  readonly delimiter?: string;

  /**
   * Whether to place a random anchor between the original value and the payload. The anchor
   * enables counting how many times input is reflected, but it also changes the value's
   * shape, which breaks numeric and identifier contexts. Hence false for those.
   */
  readonly anchor: boolean;

  /**
   * Relative interest weight carried over from the original research, 0 to 9. Used only for
   * ranking and reporting, never as evidence.
   */
  readonly weight: number;

  /**
   * How the payload's own bytes should be read by the per-surface encoder.
   *
   * Defaults to plain literal. Set `literal-raw-percent` when the syntax under test contains a
   * percent sign, and `pre-encoded` when the catalogue already wrote the payload in wire form.
   */
  readonly wireForm?: "literal" | "literal-raw-percent" | "pre-encoded";

  /** Why this pair exists, or a defect corrected while porting it. */
  readonly notes?: string;
}

/**
 * A pair parameterised by what an earlier stage discovered. Roughly a third of the original
 * catalogue is of this kind: the concatenation, JSON, MongoDB and function-call families are
 * all functions of a delimiter and an operator that only the cascade knows.
 */
export interface ProbeTemplate<P> {
  readonly id: string;
  readonly name: string;
  readonly stage: ProbeStage;
  readonly build: (params: P) => ProbePair;
}

export interface DelimiterParams {
  /** The quote or escape character proven meaningful by the delimiter stage. */
  readonly delimiter: string;
}

export interface ConcatParams extends DelimiterParams {
  /** The operator proven to join two string literals. */
  readonly concat: string;
}

export interface WrapParams {
  /** Text placed before the injected expression, e.g. "${" or a delimiter plus operator. */
  readonly prefix: string;
  /** Text placed after the injected expression. */
  readonly suffix: string;
}

export interface ValueParams {
  /** The parameter's original value, needed by path and iterable-input families. */
  readonly baseValue: string;
}

/**
 * A language probe: one call that should evaluate and near-miss misspellings that should not.
 *
 * Detection here relies on the misspelling producing an error while the correct name does
 * not, which is why the pair is inverted relative to the rest of the catalogue: the VALID
 * call is the escape and the invalid ones are the breaks.
 */
export interface LanguageProbe {
  readonly id: string;
  readonly language: string;
  /** The call that should succeed when this language is the interpreter. */
  readonly valid: string;
  /** Near-miss names that should fail. */
  readonly invalid: readonly string[];
  /**
   * Whether padding the valid call's numeric literal can equalise lengths without changing
   * its value. Where true, the engine widens the literal rather than relying solely on
   * length neutralisation.
   */
  readonly padNumeric: boolean;
  /**
   * Only meaningful when a random anchor is in use. Two entries in the original catalogue
   * were gated on the anchor because they depend on the value being a bare integer.
   */
  readonly requiresAnchor?: boolean;
}
