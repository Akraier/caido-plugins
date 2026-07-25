/**
 * S3 attribution: the control arms.
 *
 * A witness that survived the screening ladder is a difference that is real and reproducible. That
 * is not the same as evidence of server-side injection. Four alternative explanations remain, and
 * each has a control arm that tests it directly:
 *
 * | Arm | Payload | Vetoes the witness when the control behaves like the BREAK arm |
 * |-----|---------|----------------------------------------------------------------|
 * | Z0  | inert, same length | the baseline itself drifted, so the "difference" is time, not payload |
 * | Dz  | same length, no special characters | the app reacts to payload LENGTH or position, not syntax |
 * | Ds  | same length, same non-special profile, different punctuation | the app reacts to punctuation generally, not to THIS punctuation |
 * | Bd  | the break with its specials double-percent-encoded | something byte-level is reacting, typically a firewall |
 *
 * The statistic cannot do this work. A permutation test tells you a difference is unlikely to be
 * chance; it says nothing about which of these four causes produced it. This is where the false
 * positive rate is actually carried, which is why each arm is sent twice and vetoes only
 * unanimously: one request must never overturn a twelve-request measurement in either direction.
 */

import { CLASS_TABLE, SPECIAL_CLASSES } from "../response/classes.ts";

import { COUNTER_SPECS, type FeatureDiff, type FeatureVector } from "./features.ts";

export type ControlName = "Z0" | "Dz" | "Ds" | "Bd";

export interface ControlArm {
  readonly name: ControlName;
  readonly payload: string;
  /** What a break-side landing would mean, for the operator-facing explanation. */
  readonly explains: string;
}

/** Replicates per control arm. Unanimity is required, so a single blip cannot decide. */
export const CONTROL_REPLICATES = 2;

const INERT = "z";
/** A punctuation character that is in a special class but syntactically inert almost everywhere. */
const INERT_PUNCT = "~";
const INERT_PUNCT_ALT = "^";

function isSpecialChar(char: string): boolean {
  return SPECIAL_CLASSES.has(CLASS_TABLE[char.charCodeAt(0) & 0xff]!);
}

/** Same length as the break, containing no special characters at all. */
export function buildDz(breakPayload: string): string {
  return INERT.repeat(breakPayload.length);
}

/**
 * Same length as the break and the same profile in every NON-special class, but with the special
 * characters swapped for inert punctuation.
 *
 * The point is to keep everything about the payload the same except *which* punctuation it carries.
 * If the response still behaves as it did for the break arm, the application is reacting to
 * punctuation in general rather than to the specific syntax under test.
 */
export function buildDs(breakPayload: string): string {
  let out = "";
  for (const char of breakPayload) {
    if (!isSpecialChar(char)) {
      out += char;
      continue;
    }
    out += char === INERT_PUNCT ? INERT_PUNCT_ALT : INERT_PUNCT;
  }
  return out;
}

/**
 * The break payload with every special character double-percent-encoded.
 *
 * After one round of decoding the application sees `%27` rather than `'`, so the interpreter should
 * not be reached. A byte-level filter matching on the raw character will also not match. If the
 * response still behaves like the break arm, the cause was not the special character reaching an
 * interpreter.
 */
export function buildBd(breakPayload: string): string {
  let out = "";
  for (const char of breakPayload) {
    if (!isSpecialChar(char)) {
      out += char;
      continue;
    }
    const hex = char.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0");
    out += `%25${hex}`;
  }
  return out;
}

/** An inert value of the same length as the break, used to detect baseline drift. */
export function buildZ0(breakPayload: string, random: () => number): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < breakPayload.length; i++) {
    out += alphabet[Math.floor(random() * alphabet.length)] ?? "z";
  }
  return out;
}

export function buildControlArms(breakPayload: string, random: () => number): ControlArm[] {
  return [
    {
      name: "Z0",
      payload: buildZ0(breakPayload, random),
      explains: "the baseline drifted during the measurement",
    },
    {
      name: "Dz",
      payload: buildDz(breakPayload),
      explains: "the application reacts to payload length or position, not to syntax",
    },
    {
      name: "Ds",
      payload: buildDs(breakPayload),
      explains: "the application reacts to punctuation in general, not to this syntax",
    },
    {
      name: "Bd",
      payload: buildBd(breakPayload),
      explains: "something byte-level is reacting, most likely a filter or firewall",
    },
  ];
}

/** Read one feature's value out of a vector by the name used in a FeatureDiff. */
export function readFeature(
  vector: FeatureVector,
  name: string,
): number | string | undefined {
  switch (name) {
    case "status":
      return vector.status;
    case "contentType":
      return vector.contentType;
    case "locationHash":
      return vector.locationHash;
    case "bodyLength":
      return vector.bodyLength;
    case "tagHash":
      return vector.tagHash;
    case "rttMs":
      return vector.rttMs;
    default:
      break;
  }
  const counterIndex = COUNTER_SPECS.findIndex((spec) => spec.name === name);
  if (counterIndex !== -1) return vector.counters[counterIndex];
  if (name.startsWith("kw:")) {
    // Resolved by the caller via the keyword index, since the name carries the needle text.
    return undefined;
  }
  return undefined;
}

export type Side = "break" | "escape" | "neither";

/**
 * Which arm a control response resembles, for one witness.
 *
 * For a numeric witness the criterion is direction, not distance: the control lands on the break
 * side if it moved away from the escape value in the same direction the break did. Using distance
 * would make a control that overshot look like it landed on neither side.
 */
export function sideOf(
  witness: FeatureDiff,
  controlValue: number | string | undefined,
  breakValue: number | string,
  escapeValue: number | string,
): Side {
  if (controlValue === undefined) return "neither";

  if (witness.sign === 0) {
    // Categorical: it either matches one arm's value or neither.
    if (controlValue === breakValue) return "break";
    if (controlValue === escapeValue) return "escape";
    return "neither";
  }

  if (typeof controlValue !== "number" || typeof escapeValue !== "number") return "neither";
  const movement = controlValue - escapeValue;
  if (movement === 0) return "escape";
  return Math.sign(movement) === witness.sign ? "break" : "neither";
}

export interface ControlObservation {
  readonly name: ControlName;
  /** One entry per replicate. */
  readonly sides: readonly Side[];
}

export interface VetoResult {
  readonly survivors: readonly FeatureDiff[];
  readonly vetoed: readonly {
    readonly witness: FeatureDiff;
    readonly by: ControlName;
    readonly explains: string;
  }[];
  /** Set when Z0 drifted, which invalidates the whole measurement rather than one witness. */
  readonly drifted: boolean;
}

/**
 * Apply the control vetoes.
 *
 * Order matters. Z0 is checked first and is fatal to the measurement, not to a single witness: if
 * the inert baseline no longer looks like the escape arm, the reference has moved and nothing
 * measured against it can be trusted. The remaining arms remove witnesses individually.
 */
export function applyControlVetoes(
  witnesses: readonly FeatureDiff[],
  observations: readonly { readonly arm: ControlArm; readonly sides: readonly Side[][] }[],
): VetoResult {
  // observations[i].sides[w] is the per-replicate sides for witness w under arm i.
  const z0 = observations.find((o) => o.arm.name === "Z0");
  if (z0 !== undefined) {
    const anyDrift = witnesses.some((_, w) =>
      (z0.sides[w] ?? []).some((side) => side !== "escape"),
    );
    if (anyDrift) {
      return { survivors: [], vetoed: [], drifted: true };
    }
  }

  const survivors: FeatureDiff[] = [];
  const vetoed: {
    witness: FeatureDiff;
    by: ControlName;
    explains: string;
  }[] = [];

  for (let w = 0; w < witnesses.length; w++) {
    const witness = witnesses[w]!;
    let killedBy: ControlArm | undefined;

    for (const observation of observations) {
      if (observation.arm.name === "Z0") continue;
      const sides = observation.sides[w] ?? [];
      if (sides.length === 0) continue;
      // Unanimity: every replicate must land on the break side to veto.
      if (sides.every((side) => side === "break")) {
        killedBy = observation.arm;
        break;
      }
    }

    if (killedBy === undefined) survivors.push(witness);
    else vetoed.push({ witness, by: killedBy.name, explains: killedBy.explains });
  }

  return { survivors, vetoed, drifted: false };
}

export type Confidence = "firm" | "probable" | "tentative";

/**
 * Confidence from the surviving witnesses.
 *
 * FIRM requires breadth: at least two witnesses spanning at least two feature classes. A single
 * witness, however clean, is one mechanism away from being an artefact nobody thought of, and the
 * whole design's premise is that unknown artefacts exist.
 */
export function gradeConfidence(survivors: readonly FeatureDiff[]): Confidence {
  if (survivors.length === 0) return "tentative";
  const classes = new Set(survivors.map((w) => w.featureClass));
  const hasClean = survivors.some((w) => !w.lengthSensitive);
  if (survivors.length >= 2 && classes.size >= 2 && hasClean) return "firm";
  if (hasClean) return "probable";
  return "tentative";
}
