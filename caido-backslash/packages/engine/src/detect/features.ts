/**
 * The comparable feature vector.
 *
 * Everything here is derived from one fused byte pass over the reflection-excised body, plus a few
 * O(1) reads off the response head. Each feature carries the byte class it is *about*, which is
 * what lets the payload-delta explainability veto ask the decisive question: does this feature
 * differ only in a class in which the two payloads themselves differ?
 */

import { type ByteClass, ByteClass as BC } from "../response/classes.ts";
import { type EchoState, locateEcho } from "../response/echo.ts";
import { KEYWORDS } from "../response/keywords.ts";
import { type BodyScan, bigramCosine, scanBody } from "../response/scan.ts";
import { type EngineResponse, header } from "../transport/types.ts";

/** Coarse grouping used by the FIRM confidence rule, which needs witnesses spanning two classes. */
export type FeatureClass = "status" | "size" | "structure" | "lexeme" | "echo" | "timing";

export interface FeatureSpec {
  readonly name: string;
  readonly featureClass: FeatureClass;
  /**
   * The byte class this feature counts, when it counts one. A counter over a class in which the two
   * payloads differ is explainable by the payloads not being the same string, and is not evidence.
   */
  readonly byteClass?: ByteClass;
  /** True when the feature is inherently sensitive to payload length. */
  readonly lengthSensitive?: boolean;
}

/**
 * Order is the vector layout and must not be reordered: witness reports and stored evidence index
 * into it.
 */
export const COUNTER_SPECS: readonly FeatureSpec[] = [
  { name: "newlines", featureClass: "structure", byteClass: BC.LF },
  { name: "spaces", featureClass: "structure", byteClass: BC.SPACE },
  { name: "tags", featureClass: "structure", byteClass: BC.LT },
  { name: "equals", featureClass: "structure", byteClass: BC.EQUALS },
  { name: "quotes", featureClass: "structure", byteClass: BC.DQUOTE },
  { name: "commas", featureClass: "structure", byteClass: BC.COMMA },
  { name: "digits", featureClass: "structure", byteClass: BC.DIGIT },
  { name: "semicolons", featureClass: "structure", byteClass: BC.SEMICOLON },
  { name: "braces", featureClass: "structure", byteClass: BC.BRACE_OPEN },
];

export interface FeatureVector {
  readonly status: number;
  readonly contentType: string;
  readonly locationHash: number;
  readonly bodyLength: number;
  readonly counters: Int32Array;
  readonly keywords: Int32Array;
  readonly tagHash: number;
  readonly tagNameCount: number;
  readonly bigrams: Int32Array;
  readonly rttMs: number;
  readonly echoState: EchoState;
  readonly echoTransformBits: number;
  /** True when the echo lost its closing canary, so body features cannot be trusted. */
  readonly bodyUnreliable: boolean;
  readonly truncated: boolean;
  readonly excisedBytes: number;
}

export interface FeaturiseOptions {
  /** `right` omitted for end-anchored probes; excision is then coarser. */
  readonly canary?: { readonly left: string; readonly right?: string };
  /** The payload as sent, for echo transform classification and the excision span cap. */
  readonly sentPayload?: string;
  readonly capBytes?: number;
}

function fnvString(text: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) hash = (Math.imul(hash ^ text.charCodeAt(i), 0x01000193) >>> 0);
  return hash >>> 0;
}

/**
 * Hash the Location header with the reflected input excised.
 *
 * Hashing it raw made every redirect that carries its input back -- `?next=`, `?returnUrl=`, an error
 * message parameter -- into a confident finding, because the two arms send different payloads and so
 * produce different Locations by construction. That is a reflection, not a statement about how the
 * server parsed anything.
 *
 * The delta veto cannot rescue this one: it reasons about byte-class counters, and a hash has no
 * classes left to reason about. So excise first, exactly as the body already does, using the same
 * canaries. The canary alphabet is alphanumeric, so it survives percent-encoding unchanged and a plain
 * substring search finds it whether the value was encoded or not.
 */
function locationFingerprint(
  location: string | undefined,
  canary?: { readonly left: string; readonly right?: string },
): number {
  if (location === undefined) return 0;
  if (canary === undefined) return fnvString(location);

  const start = location.indexOf(canary.left);
  if (start === -1) return fnvString(location);
  const head = location.slice(0, start);

  // End-anchored probes send no closing canary, so everything from the marker on is the echo.
  if (canary.right === undefined) return fnvString(`${head}<echo>`);

  const end = location.indexOf(canary.right, start + canary.left.length);
  // A missing closing canary could mean the value was truncated, which is arguably signal. Excising to
  // the end anyway is the conservative reading: losing a real witness costs less than a false one.
  if (end === -1) return fnvString(`${head}<echo>`);

  return fnvString(`${head}<echo>${location.slice(end + canary.right.length)}`);
}

export function featurise(
  response: EngineResponse,
  options: FeaturiseOptions = {},
): FeatureVector {
  const canary = options.canary;
  const sentPayload = options.sentPayload ?? "";

  let echoState: EchoState = "absent";
  let echoTransformBits = 0;
  let bodyUnreliable = false;
  let excise: ReturnType<typeof locateEcho>["spans"] = [];

  if (canary !== undefined) {
    const echo = locateEcho(
      response.raw,
      response.bodyStart,
      response.raw.length,
      canary.right === undefined
        ? { left: canary.left }
        : { left: canary.left, right: canary.right },
      { sentPayload },
    );
    echoState = echo.state;
    echoTransformBits = echo.transformBits;
    bodyUnreliable = echo.unpaired;
    excise = echo.spans;
  }

  const scan: BodyScan = scanBody(response.raw, response.bodyStart, response.raw.length, {
    ...(options.capBytes === undefined ? {} : { capBytes: options.capBytes }),
    excise,
  });

  const counters = Int32Array.of(
    scan.newlines,
    scan.spaces,
    scan.tags,
    scan.equals,
    scan.quotes,
    scan.commas,
    scan.digits,
    scan.semicolons,
    scan.braces,
  );

  const contentTypeRaw = header(response, "content-type") ?? "";
  const semicolon = contentTypeRaw.indexOf(";");
  const contentType = (semicolon === -1 ? contentTypeRaw : contentTypeRaw.slice(0, semicolon))
    .trim()
    .toLowerCase();

  // Evidence that a redirect changed. Still computed when redirects ARE being followed: the hop that
  // was taken is part of the measured behaviour, not a detail to discard.
  const location = header(response, "location");

  return {
    status: response.status,
    contentType,
    locationHash: locationFingerprint(location, options.canary),
    bodyLength: scan.bodyLength,
    counters,
    keywords: scan.keywords,
    tagHash: scan.tagHash,
    tagNameCount: scan.tagNameCount,
    bigrams: scan.bigrams,
    rttMs: response.roundtripMs,
    echoState,
    echoTransformBits,
    bodyUnreliable,
    truncated: scan.truncated,
    excisedBytes: scan.excisedBytes,
  };
}

/** A single observed difference between two vectors. */
export interface FeatureDiff {
  readonly name: string;
  readonly featureClass: FeatureClass;
  readonly byteClass?: ByteClass;
  readonly lengthSensitive: boolean;
  /** Sign of (break - escape). Zero for categorical features that merely differ. */
  readonly sign: number;
  readonly breakValue: number | string;
  readonly escapeValue: number | string;
}

/** Similarity below which the bigram profile counts as a difference. */
export const SIMILARITY_THRESHOLD = 0.95;

/**
 * Which features differ between the two arms.
 *
 * Categorical features report sign 0: they differ or they do not, and no magnitude is meaningful.
 * Numeric features report a sign, which the consistency rule then requires to agree across every
 * mini-pair. Sign agreement rather than magnitude is what makes a one-count comma change and a
 * forty-millisecond delay equally reportable.
 */
export function differingFeatures(
  breakVector: FeatureVector,
  escapeVector: FeatureVector,
): FeatureDiff[] {
  const diffs: FeatureDiff[] = [];

  const categorical = (
    name: string,
    featureClass: FeatureClass,
    a: number | string,
    b: number | string,
  ): void => {
    if (a !== b) {
      diffs.push({
        name,
        featureClass,
        lengthSensitive: false,
        sign: 0,
        breakValue: a,
        escapeValue: b,
      });
    }
  };

  const numeric = (
    name: string,
    featureClass: FeatureClass,
    a: number,
    b: number,
    spec?: { byteClass?: ByteClass; lengthSensitive?: boolean },
  ): void => {
    if (a === b) return;
    const diff: {
      -readonly [K in keyof FeatureDiff]: FeatureDiff[K];
    } = {
      name,
      featureClass,
      lengthSensitive: spec?.lengthSensitive === true,
      sign: a > b ? 1 : -1,
      breakValue: a,
      escapeValue: b,
    };
    if (spec?.byteClass !== undefined) diff.byteClass = spec.byteClass;
    diffs.push(diff as FeatureDiff);
  };

  categorical("status", "status", breakVector.status, escapeVector.status);
  categorical("contentType", "status", breakVector.contentType, escapeVector.contentType);
  categorical("locationHash", "status", breakVector.locationHash, escapeVector.locationHash);

  // echoTransformBits, and echoState in general, are deliberately NOT compared across arms.
  //
  // They describe what the server did to the payload, and the two arms send DIFFERENT payloads, so
  // a difference between them is guaranteed and meaningless: `\` and `\\` classify differently by
  // construction. Comparing them produced a witness on a target that merely echoed its input,
  // found by running the pipeline end to end. They remain on the vector because per-arm they are
  // valuable, feeding the separate "input transformed or stripped" report rather than a witness.
  //
  // ONE axis of echoState is exempt: whether the echo lost its closing canary.
  //
  // `unpaired` means the opening canary was found and the closing one was not, i.e. the server began
  // emitting the value and stopped partway. When that happens in one arm and not the other it is the
  // signature of an interpreter dying mid-render, which is the strongest evidence this technique can
  // produce -- and it was being thrown away. A template engine that aborts on `${7/0}` emits the text
  // before the payload and nothing after it, so the closing canary vanishes and every body feature is
  // declared unreliable; a blatant server-side template injection then reported "inconclusive".
  //
  // It is safe to compare where raw echoState is not, because payload lengths are equalised by the
  // parity step. Truncation at a byte limit therefore hits both arms identically, so an asymmetric
  // loss cannot be explained by one payload being longer. The canaries themselves are plain
  // alphanumerics, so no escaping or filtering rule treats them differently between arms. And the
  // control arms still adjudicate it: an application that merely reacts to punctuation loses the
  // canary on Ds and Bd too, which vetoes the witness.
  categorical(
    "echoTruncated",
    // Classed with status rather than the body features: this is an observation about whether the
    // response finished, not a measurement taken from its content, so it stays admissible in exactly
    // the case where body features do not.
    "status",
    breakVector.echoState === "unpaired" ? "truncated" : "intact",
    escapeVector.echoState === "unpaired" ? "truncated" : "intact",
  );

  numeric("bodyLength", "size", breakVector.bodyLength, escapeVector.bodyLength, {
    lengthSensitive: true,
  });

  for (let i = 0; i < COUNTER_SPECS.length; i++) {
    const spec = COUNTER_SPECS[i]!;
    numeric(spec.name, spec.featureClass, breakVector.counters[i]!, escapeVector.counters[i]!, {
      ...(spec.byteClass === undefined ? {} : { byteClass: spec.byteClass }),
      lengthSensitive: true,
    });
  }

  for (let i = 0; i < KEYWORDS.length; i++) {
    const a = breakVector.keywords[i]!;
    const b = escapeVector.keywords[i]!;
    if (a !== b) {
      numeric(`kw:${KEYWORDS[i]!}`, "lexeme", a, b);
    }
  }

  categorical("tagHash", "structure", breakVector.tagHash, escapeVector.tagHash);

  const similarity = bigramCosine(breakVector.bigrams, escapeVector.bigrams);
  if (similarity < SIMILARITY_THRESHOLD) {
    diffs.push({
      name: "bodySimilarity",
      featureClass: "structure",
      lengthSensitive: true,
      sign: -1,
      breakValue: Math.round(similarity * 1000) / 1000,
      escapeValue: 1,
    });
  }

  return diffs;
}
