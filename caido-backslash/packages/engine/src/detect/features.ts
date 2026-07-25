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

  // No redirect following, so the Location header is the only evidence a redirect changed.
  const location = header(response, "location");

  return {
    status: response.status,
    contentType,
    locationHash: location === undefined ? 0 : fnvString(location),
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

  // echoState and echoTransformBits are deliberately NOT compared across arms.
  //
  // They describe what the server did to the payload, and the two arms send DIFFERENT payloads, so
  // a difference between them is guaranteed and meaningless: `\` and `\\` classify differently by
  // construction. Comparing them produced a witness on a target that merely echoed its input,
  // found by running the pipeline end to end. They remain on the vector because per-arm they are
  // valuable, feeding the separate "input transformed or stripped" report rather than a witness.

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
