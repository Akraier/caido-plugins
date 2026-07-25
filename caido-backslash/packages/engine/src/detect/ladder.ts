/**
 * The screening ladder: S0 through S2.
 *
 * One probe pair, interleaved, escalating only while the evidence survives. A pair that reacts to
 * nothing costs two requests, which matters because that is 90 to 95 percent of all traffic.
 *
 * Consistency, not magnitude, is the criterion. A feature is a witness only if it differs in the
 * SAME DIRECTION in every single mini-pair. That is what makes a one-count comma change and a
 * forty-millisecond delay equally reportable, and it is why no effect-size threshold appears here.
 *
 * S3 attribution (the Dz / Ds / Bd / Z0 control arms) and S4 reporting with the permutation
 * statistic are not in this commit. What is here is the part that decides whether a pair is worth
 * spending control arms on at all, plus the payload-delta explainability veto, which is cheap
 * because it needs no extra requests.
 */

import { classDelta } from "../response/classes.ts";
import { type Admission, isUsable } from "../transport/admission.ts";
import { type ProbeTransport, isHalted } from "../transport/throttle.ts";
import type { EngineRequest, RandomSource } from "../transport/types.ts";

import { type FeatureDiff, type FeatureVector, differingFeatures, featurise } from "./features.ts";

export const M_SCREEN = 1;
export const M_FILTER = 3;
export const M_ESTABLISH = 6;

export type LadderOutcome =
  /** No feature differed, or none differed consistently. */
  | { readonly kind: "boring"; readonly stage: "S0" | "S1" | "S2"; readonly sends: number }
  /** Survived to S2 with at least one witness. Ready for attribution. */
  | {
      readonly kind: "candidate";
      readonly witnesses: readonly FeatureDiff[];
      readonly m: number;
      readonly sends: number;
    }
  /** Every witness was explainable by the payloads not being the same string. */
  | {
      readonly kind: "veto-payload-delta";
      readonly explained: readonly FeatureDiff[];
      readonly sends: number;
    }
  /** The measurement could not be completed. Never reported as a negative result. */
  | {
      readonly kind: "inconclusive";
      readonly reason: "blinded" | "halted" | "body-unreliable";
      readonly detail: string;
      readonly sends: number;
    };

export interface Canary {
  readonly left: string;
  /** Absent for end-anchored probes: see CanaryFrame in response/echo.ts. */
  readonly right?: string;
}

/** Builds the request bytes for one arm. Supplied by the request layer. */
export type ArmBuilder = (payload: string, canary: Canary) => EngineRequest;

export interface LadderDeps {
  readonly transport: ProbeTransport;
  readonly random: RandomSource;
  /** Fresh canary per send. Injected so the ladder is deterministic under test. */
  readonly canary: () => Canary;
}

export interface ProbeArms {
  readonly breakPayload: string;
  readonly escapePayload: string;
  readonly build: ArmBuilder;
  /**
   * True when the payload must be the last thing in the value, so no closing canary is sent.
   *
   * The backslash family needs this: a trailing backslash is an unterminated escape, whereas the
   * same backslash followed by a closing canary merely escapes the canary's first letter. Excision
   * is coarser as a result, which is the price of testing the semantics at all.
   */
  readonly endAnchored?: boolean;
  /** Tag recorded in the transport log, so a log line says which probe produced it. */
  readonly label?: string;
}

interface MiniPairResult {
  readonly ok: true;
  readonly diffs: FeatureDiff[];
  readonly breakVector: FeatureVector;
  readonly escapeVector: FeatureVector;
}

interface MiniPairFailure {
  readonly ok: false;
  readonly failure: Admission | "halted";
  readonly sends: number;
}

/**
 * Send one break and one escape back to back, in an order chosen by a coin.
 *
 * The coin matters: an application that alternates between two backends produces a difference
 * correlated with send order, and a fixed order would attribute that to the payload.
 */
async function sendMiniPair(
  deps: LadderDeps,
  arms: ProbeArms,
): Promise<MiniPairResult | MiniPairFailure> {
  const breakFirst = deps.random() < 0.5;
  const first = breakFirst ? arms.breakPayload : arms.escapePayload;
  const second = breakFirst ? arms.escapePayload : arms.breakPayload;

  const frame = (c: Canary): Canary =>
    arms.endAnchored === true ? { left: c.left } : c;

  const firstCanary = frame(deps.canary());
  const firstArm = breakFirst ? "break" : "escape";
  const firstResult = await deps.transport.send(arms.build(first, firstCanary), {
    label: `${arms.label ?? "probe"}:${firstArm}`,
  });
  if (isHalted(firstResult)) return { ok: false, failure: "halted", sends: 1 };
  if (!isUsable(firstResult)) return { ok: false, failure: firstResult, sends: 1 };

  const secondCanary = frame(deps.canary());
  const secondResult = await deps.transport.send(arms.build(second, secondCanary), {
    label: `${arms.label ?? "probe"}:${breakFirst ? "escape" : "break"}`,
  });
  if (isHalted(secondResult)) return { ok: false, failure: "halted", sends: 2 };
  if (!isUsable(secondResult)) return { ok: false, failure: secondResult, sends: 2 };

  const firstVector = featurise(firstResult.response, {
    canary: firstCanary,
    sentPayload: first,
  });
  const secondVector = featurise(secondResult.response, {
    canary: secondCanary,
    sentPayload: second,
  });

  const breakVector = breakFirst ? firstVector : secondVector;
  const escapeVector = breakFirst ? secondVector : firstVector;

  return {
    ok: true,
    diffs: differingFeatures(breakVector, escapeVector),
    breakVector,
    escapeVector,
  };
}

/**
 * Keep only features that differ consistently across every mini-pair.
 *
 * A feature must be present in all rounds AND agree in sign. Sign disagreement is the signature of
 * noise: a value that is sometimes larger and sometimes smaller in the break arm is churning, not
 * responding.
 */
function intersectConsistently(rounds: readonly FeatureDiff[][]): FeatureDiff[] {
  if (rounds.length === 0) return [];
  const first = rounds[0]!;
  return first.filter((candidate) =>
    rounds.every((round) =>
      round.some((diff) => diff.name === candidate.name && diff.sign === candidate.sign),
    ),
  );
}

/**
 * Remove witnesses that the payload difference alone explains.
 *
 * A counter over a byte class in which the two payloads themselves differ carries no information:
 * of course a payload with one more comma produces one more comma in a reflected response. The same
 * logic applies to every length-derived feature when the payloads are different lengths.
 *
 * This is a false-positive control that costs zero extra requests, and it is the only defence
 * available for the backslash family, whose two arms cannot be made the same length by
 * construction.
 */
export function applyDeltaVeto(
  witnesses: readonly FeatureDiff[],
  breakPayload: string,
  escapePayload: string,
  reflected: boolean,
): { readonly survivors: FeatureDiff[]; readonly explained: FeatureDiff[] } {
  if (!reflected) return { survivors: [...witnesses], explained: [] };

  const delta = classDelta(breakPayload, escapePayload);
  const lengthDiffers = breakPayload.length !== escapePayload.length;

  const survivors: FeatureDiff[] = [];
  const explained: FeatureDiff[] = [];
  for (const witness of witnesses) {
    const byClass = witness.byteClass !== undefined && delta.has(witness.byteClass);
    const byLength = witness.lengthSensitive && lengthDiffers;
    if (byClass || byLength) explained.push(witness);
    else survivors.push(witness);
  }
  return { survivors, explained };
}

/**
 * Run S0 to S2 for one probe pair.
 */
export async function runLadder(
  deps: LadderDeps,
  arms: ProbeArms,
): Promise<LadderOutcome> {
  const rounds: FeatureDiff[][] = [];
  let sends = 0;
  let reflected = false;
  let unreliable = false;

  const step = async (): Promise<LadderOutcome | undefined> => {
    const result = await sendMiniPair(deps, arms);
    if (!result.ok) {
      sends += result.sends;
      if (result.failure === "halted") {
        return {
          kind: "inconclusive",
          reason: "halted",
          detail: "transport halted: the target stopped answering usefully",
          sends,
        };
      }
      const admission = result.failure;
      const describe =
        admission.kind === "soft-fail"
          ? `soft-fail: ${admission.reason}${admission.signal === undefined ? "" : ` (${admission.signal})`}`
          : admission.kind === "hard-fail"
            ? `hard-fail: ${admission.failure}`
            : "unexpected usable admission on the failure path";
      return {
        kind: "inconclusive",
        reason: "blinded",
        detail: describe,
        sends,
      };
    }
    sends += 2;
    rounds.push(result.diffs);
    if (result.breakVector.echoState !== "absent" || result.escapeVector.echoState !== "absent") {
      reflected = true;
    }
    if (result.breakVector.bodyUnreliable || result.escapeVector.bodyUnreliable) {
      unreliable = true;
    }
    return undefined;
  };

  // ---- S0 screen: one mini-pair, and promote on any difference at all ----
  const s0 = await step();
  if (s0 !== undefined) return s0;
  if (rounds[0]!.length === 0) return { kind: "boring", stage: "S0", sends };

  // ---- S1 filter: two more, require consistency ----
  for (let i = 1; i < M_FILTER; i++) {
    const failure = await step();
    if (failure !== undefined) return failure;
  }
  if (intersectConsistently(rounds).length === 0) {
    return { kind: "boring", stage: "S1", sends };
  }

  // ---- S2 establish ----
  for (let i = M_FILTER; i < M_ESTABLISH; i++) {
    const failure = await step();
    if (failure !== undefined) return failure;
  }
  const consistent = intersectConsistently(rounds);
  if (consistent.length === 0) return { kind: "boring", stage: "S2", sends };

  const { survivors, explained } = applyDeltaVeto(
    consistent,
    arms.breakPayload,
    arms.escapePayload,
    reflected,
  );

  if (survivors.length === 0) {
    return { kind: "veto-payload-delta", explained, sends };
  }

  if (unreliable) {
    // An unpaired echo means the body features could not be excised reliably. Reporting a witness
    // derived from them would be reporting a measurement we know is contaminated.
    const nonBody = survivors.filter((w) => w.featureClass === "status" || w.featureClass === "timing");
    if (nonBody.length === 0) {
      return {
        kind: "inconclusive",
        reason: "body-unreliable",
        detail: "reflected payload lost its closing canary, so body features cannot be excised",
        sends,
      };
    }
    return { kind: "candidate", witnesses: nonBody, m: M_ESTABLISH, sends };
  }

  return { kind: "candidate", witnesses: survivors, m: M_ESTABLISH, sends };
}
