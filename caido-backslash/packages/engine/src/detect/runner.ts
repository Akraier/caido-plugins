/**
 * Host-agnostic probe-suite orchestration.
 *
 * Walks slots against probes, runs the screening ladder, spends control arms on survivors, and
 * emits findings and diagnostics. Both hosts drive this: the CLI and the Caido plugin differ only in
 * their transport and in what they do with the events.
 *
 * It lives here rather than in each host on purpose. The Java original kept a parallel WebSocket
 * copy of its scan logic which drifted 77 lines away from the HTTP one, so every probe fix had to be
 * applied twice and sometimes was not. One orchestration, many transports.
 */

import type { ProbePair } from "../probes/types.ts";
import { equalisePair } from "../probes/pad.ts";
import type { Slot } from "../request/slots.ts";
import { type RequestTemplate, asciiBytes, assemble, locate } from "../request/template.ts";
import type { EngineRequest, RandomSource } from "../transport/types.ts";
import { type ProbeTransport, isHalted } from "../transport/throttle.ts";
import { isUsable } from "../transport/admission.ts";

import {
  type ControlArm,
  type Side,
  applyControlVetoes,
  buildControlArms,
  gradeConfidence,
  readFeature,
  sideOf,
  type Confidence,
} from "./attribution.ts";
import { type FeatureDiff, type FeatureVector, differingFeatures, featurise } from "./features.ts";
import { KEYWORDS } from "../response/keywords.ts";
import { type Canary, type ProbeArms, runLadder } from "./ladder.ts";

/**
 * Probe stages whose semantics require the payload to be last in the value.
 *
 * A trailing backslash is only an unterminated escape if nothing follows it, so these send no
 * closing canary and accept coarser reflection excision in exchange.
 */
const END_ANCHORED_STAGES: ReadonlySet<string> = new Set(["delimiter", "escape-sequence"]);

export interface TargetCoordinates {
  readonly host: string;
  readonly port: number;
  readonly tls: boolean;
}

export interface SuiteFinding {
  readonly probeId: string;
  readonly probeName: string;
  readonly slot: Slot;
  readonly confidence: Confidence;
  readonly breakPayload: string;
  readonly escapePayload: string;
  readonly witnesses: readonly FeatureDiff[];
  readonly attributedElsewhere: readonly {
    readonly witness: FeatureDiff;
    readonly by: string;
    readonly explains: string;
  }[];
  /** Host reference for the saved evidence exchange, when the host could provide one. */
  readonly evidenceRequestId?: string;
}

export type DiagnosticKind =
  | "boring"
  | "inconclusive"
  | "veto-payload-delta"
  | "veto-control"
  | "drift";

export interface SuiteDiagnostic {
  readonly probeId: string;
  readonly slotName: string;
  readonly kind: DiagnosticKind;
  readonly detail: string;
}

export interface SuiteEvents {
  onFinding?: (finding: SuiteFinding) => void;
  onDiagnostic?: (diagnostic: SuiteDiagnostic) => void;
  onProgress?: (progress: {
    slotsDone: number;
    slotsTotal: number;
    probesDone: number;
    probesTotal: number;
    sends: number;
  }) => void;
}

export interface SuiteOptions {
  readonly template: RequestTemplate;
  readonly slots: readonly Slot[];
  readonly probes: readonly ProbePair[];
  readonly target: TargetCoordinates;
  readonly transport: ProbeTransport;
  readonly random: RandomSource;
  /** Should the run stop? Checked between probes so cancellation is prompt but not mid-pair. */
  readonly cancelled?: () => boolean;
}

export interface SuiteSummary {
  readonly findings: readonly SuiteFinding[];
  readonly diagnostics: readonly SuiteDiagnostic[];
  readonly sends: number;
  readonly haltReason?: string;
}

function randomToken(length: number, random: RandomSource): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[Math.floor(random() * alphabet.length)] ?? "z";
  return out;
}

/** Build the request bytes for one arm of one probe on one slot. */
function makeArmBuilder(
  options: SuiteOptions,
  slot: Slot,
): (payload: string, canary: Canary) => EngineRequest {
  const { template, target, random } = options;
  return (payload, canary) => {
    const framed =
      canary.right === undefined
        ? `${slot.baseValue}${canary.left}${payload}`
        : `${slot.baseValue}${canary.left}${payload}${canary.right}`;

    const encoded = slot.codec.encode(asciiBytes(framed), "literal");
    if (!encoded.ok) {
      throw new PayloadNotDeliverable(`${slot.name}: ${encoded.detail}`);
    }

    let raw = assemble(template, [{ range: slot.range, bytes: encoded.bytes }]);

    // Fixed-length buster, appended to the request target so a cached response cannot make a
    // difference look permanent.
    const buster = asciiBytes(`cb${randomToken(6, random)}=${randomToken(8, random)}`);
    // Re-parse after splicing so the buster is placed against current offsets.
    const rebuilt = locate(raw);
    const targetRange = rebuilt.targetRange;
    let hasQuery = false;
    for (let i = targetRange.start; i < targetRange.end; i++) {
      if (raw[i] === 0x3f) {
        hasQuery = true;
        break;
      }
    }
    const prefix = asciiBytes(hasQuery ? "&" : "?");
    const insertion = new Uint8Array(prefix.length + buster.length);
    insertion.set(prefix);
    insertion.set(buster, prefix.length);
    raw = assemble(rebuilt, [
      { range: { start: targetRange.end, end: targetRange.end }, bytes: insertion },
    ]);

    return { host: target.host, port: target.port, tls: target.tls, raw };
  };
}

export class PayloadNotDeliverable extends Error {}

const keywordIndex = (needle: string): number => KEYWORDS.indexOf(needle);

function readWitness(vector: FeatureVector, witness: FeatureDiff): number | string | undefined {
  if (witness.name.startsWith("kw:")) {
    const index = keywordIndex(witness.name.slice(3));
    return index === -1 ? undefined : vector.keywords[index];
  }
  return readFeature(vector, witness.name);
}

export async function runSuite(
  options: SuiteOptions,
  events: SuiteEvents = {},
): Promise<SuiteSummary> {
  const findings: SuiteFinding[] = [];
  const diagnostics: SuiteDiagnostic[] = [];
  const { transport, random } = options;

  let probesDone = 0;
  const probesTotal = options.slots.length * options.probes.length;

  const note = (diagnostic: SuiteDiagnostic): void => {
    diagnostics.push(diagnostic);
    events.onDiagnostic?.(diagnostic);
  };

  for (let s = 0; s < options.slots.length; s++) {
    const slot = options.slots[s]!;
    const build = makeArmBuilder(options, slot);

    for (const probe of options.probes) {
      if (options.cancelled?.() === true) break;
      if (transport.stats().state === "halted") break;

      probesDone += 1;
      events.onProgress?.({
        slotsDone: s,
        slotsTotal: options.slots.length,
        probesDone,
        probesTotal,
        sends: transport.stats().sent,
      });

      const endAnchored = END_ANCHORED_STAGES.has(probe.stage);
      const canaryFor = (): Canary =>
        endAnchored
          ? { left: `bs${randomToken(4, random)}` }
          : { left: `bs${randomToken(4, random)}`, right: `${randomToken(4, random)}se` };

      const breakPayload = probe.breaks[0]!;
      const escapePayload = probe.escapeSets[0]![0]!;
      const strategy =
        probe.parity === "pad-numeric"
          ? "numeric"
          : probe.parity === "pad-filler"
            ? "filler"
            : "none";
      const equalised = equalisePair(breakPayload, escapePayload, strategy);

      const arms: ProbeArms = {
        breakPayload: equalised.breakPayload,
        escapePayload: equalised.escapePayload,
        build,
        label: probe.id,
        ...(endAnchored ? { endAnchored: true } : {}),
      };

      let ladder;
      try {
        ladder = await runLadder({ transport, random, canary: canaryFor }, arms);
      } catch (error) {
        if (error instanceof PayloadNotDeliverable) {
          note({
            probeId: probe.id,
            slotName: slot.name,
            kind: "inconclusive",
            detail: `payload not deliverable on this surface: ${error.message}`,
          });
          continue;
        }
        throw error;
      }

      if (ladder.kind === "boring") {
        note({
          probeId: probe.id,
          slotName: slot.name,
          kind: "boring",
          detail: `no consistent difference (${ladder.stage}, ${ladder.sends} sends)`,
        });
        continue;
      }
      if (ladder.kind === "inconclusive") {
        note({
          probeId: probe.id,
          slotName: slot.name,
          kind: "inconclusive",
          detail: `${ladder.reason}: ${ladder.detail}`,
        });
        continue;
      }
      if (ladder.kind === "veto-payload-delta") {
        note({
          probeId: probe.id,
          slotName: slot.name,
          kind: "veto-payload-delta",
          detail: `explained by the payload delta: ${ladder.explained.map((w) => w.name).join(", ")}`,
        });
        continue;
      }

      // Candidate. Re-measure once so the control arms have a live reference, then spend them.
      const refCanary = canaryFor();
      const breakSend = await transport.send(build(arms.breakPayload, refCanary), {
        label: `${probe.id}:remeasure-break`,
      });
      const escapeSend = await transport.send(build(arms.escapePayload, refCanary), {
        label: `${probe.id}:remeasure-escape`,
      });
      if (
        isHalted(breakSend) ||
        !isUsable(breakSend) ||
        isHalted(escapeSend) ||
        !isUsable(escapeSend)
      ) {
        note({
          probeId: probe.id,
          slotName: slot.name,
          kind: "inconclusive",
          detail: "could not re-measure the pair for attribution",
        });
        continue;
      }

      const breakVector = featurise(breakSend.response, {
        canary: refCanary,
        sentPayload: arms.breakPayload,
      });
      const escapeVector = featurise(escapeSend.response, {
        canary: refCanary,
        sentPayload: arms.escapePayload,
      });

      const live = differingFeatures(breakVector, escapeVector).filter((d) =>
        ladder.witnesses.some((w) => w.name === d.name && w.sign === d.sign),
      );
      if (live.length === 0) {
        note({
          probeId: probe.id,
          slotName: slot.name,
          kind: "inconclusive",
          detail: "witnesses did not reproduce on re-measurement",
        });
        continue;
      }

      const controlArms = buildControlArms(arms.breakPayload, random);
      const observations: { arm: ControlArm; sides: Side[][] }[] = [];
      let controlFailed = false;

      for (const arm of controlArms) {
        const perWitness: Side[][] = live.map(() => []);
        for (let replicate = 0; replicate < 2; replicate++) {
          const canary = canaryFor();
          const result = await transport.send(build(arm.payload, canary), {
            label: `${probe.id}:control-${arm.name}`,
          });
          if (isHalted(result) || !isUsable(result)) {
            controlFailed = true;
            break;
          }
          const vector = featurise(result.response, { canary, sentPayload: arm.payload });
          for (let w = 0; w < live.length; w++) {
            const witness = live[w]!;
            perWitness[w]!.push(
              sideOf(
                witness,
                readWitness(vector, witness),
                readWitness(breakVector, witness) ?? witness.breakValue,
                readWitness(escapeVector, witness) ?? witness.escapeValue,
              ),
            );
          }
        }
        if (controlFailed) break;
        observations.push({ arm, sides: perWitness });
      }

      if (controlFailed) {
        note({
          probeId: probe.id,
          slotName: slot.name,
          kind: "inconclusive",
          detail: "a control arm could not be measured",
        });
        continue;
      }

      const veto = applyControlVetoes(live, observations);
      if (veto.drifted) {
        note({
          probeId: probe.id,
          slotName: slot.name,
          kind: "drift",
          detail: "the inert baseline drifted during attribution, so the reference moved",
        });
        continue;
      }
      if (veto.survivors.length === 0) {
        note({
          probeId: probe.id,
          slotName: slot.name,
          kind: "veto-control",
          detail: veto.vetoed
            .map((v) => `${v.witness.name} attributed to ${v.by} (${v.explains})`)
            .join("; "),
        });
        continue;
      }

      // Persisted evidence: re-send the winning break arm so a finding can cite the exact exchange
      // its claim was computed from.
      let evidenceRequestId: string | undefined;
      const evidence = await transport.send(build(arms.breakPayload, refCanary), {
        persist: true,
        label: `${probe.id}:evidence`,
      });
      if (!isHalted(evidence) && isUsable(evidence)) {
        evidenceRequestId = evidence.response.requestId;
      }

      const finding: SuiteFinding = {
        probeId: probe.id,
        probeName: probe.name,
        slot,
        confidence: gradeConfidence(veto.survivors),
        breakPayload: arms.breakPayload,
        escapePayload: arms.escapePayload,
        witnesses: veto.survivors,
        attributedElsewhere: veto.vetoed.map((v) => ({
          witness: v.witness,
          by: v.by,
          explains: v.explains,
        })),
        ...(evidenceRequestId === undefined ? {} : { evidenceRequestId }),
      };
      findings.push(finding);
      events.onFinding?.(finding);
    }
  }

  const stats = transport.stats();
  return {
    findings,
    diagnostics,
    sends: stats.sent,
    ...(stats.haltReason === undefined ? {} : { haltReason: stats.haltReason.kind }),
  };
}
