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
import { type RequestTemplate, asciiBytes, assemble, locate, sliceText } from "../request/template.ts";
import type { EngineRequest, RandomSource } from "../transport/types.ts";
import { type ProbeTransport, isHalted } from "../transport/throttle.ts";
import { isUsable } from "../transport/admission.ts";
import type { Observer } from "../transport/observe.ts";
import type { Located } from "../transport/url.ts";
import { type MeasureDeps, measure } from "./measure.ts";

import {
  type ControlArm,
  type Side,
  applyControlVetoes,
  buildControlArms,
  CONTROL_REPLICATES,
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
  /**
   * Where the measured response came from, when it was not the probe's own reply.
   *
   * Empty for a normal finding. For a second-order one it lists the hops walked, which is the
   * difference between "the payload broke this endpoint" and "the payload broke the page it redirects
   * to" -- a distinction the operator cannot recover from the finding otherwise.
   */
  readonly observedVia?: readonly string[];
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
  /**
   * How many independent probe pairs may be in flight at once.
   *
   * Within a pair the two arms are always sequential and adjacent; that is the defence against a
   * backend alternating between two responses. Across pairs there is no such constraint, and running
   * them one at a time made the whole scan sequential: only ever one request in flight, so the
   * transport's own concurrency cap did nothing and throughput was pinned at
   * 1/(latency + inter-request gap).
   *
   * Ignored when the observer plan requires serialisation: see `observer`.
   */
  readonly pairConcurrency?: number;
  /**
   * Measure a response other than the probe's own -- a redirect target, or a second-order sink.
   *
   * Threaded to every arm through `measure()`, including the control arms, because witnesses and the
   * vetoes that attribute them must describe the same response.
   */
  readonly observer?: Observer;
  /**
   * Force one probe pair at a time regardless of `pairConcurrency`.
   *
   * Required when the observed response is a shared resource rather than this request's own
   * continuation. Two pairs running concurrently would interleave as inject(A), inject(B), observe(),
   * and the observation would carry the other pair's payload. A shared mutable sink cannot be measured
   * in parallel, so the option is enforced here rather than trusted to the caller.
   */
  readonly serialiseProbes?: boolean;
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
  wireForm: "literal" | "literal-raw-percent" | "pre-encoded",
  random: RandomSource,
): (payload: string, canary: Canary) => EngineRequest {
  const { template, target } = options;
  return (payload, canary) => {
    const framed =
      canary.right === undefined
        ? `${slot.baseValue}${canary.left}${payload}`
        : `${slot.baseValue}${canary.left}${payload}${canary.right}`;

    const encoded = slot.codec.encode(asciiBytes(framed), wireForm);
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

/**
 * A deterministic PRNG seeded per work item.
 *
 * Concurrency and reproducibility conflict if workers share one generator: the sequence a given
 * probe pair observes would depend on how the interleaving happened to fall out, so the same scan
 * would not replay. Deriving an independent stream per item from the caller's seed keeps every pair
 * reproducible no matter how many run at once.
 */
function splitmix32(seed: number): RandomSource {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x9e3779b9) >>> 0;
    let z = state;
    z = Math.imul(z ^ (z >>> 16), 0x21f0aaad) >>> 0;
    z = Math.imul(z ^ (z >>> 15), 0x735a2d97) >>> 0;
    return ((z ^ (z >>> 15)) >>> 0) / 0x100000000;
  };
}

interface WorkItem {
  readonly slot: Slot;
  readonly probe: ProbePair;
  readonly index: number;
}

interface PairOutcome {
  readonly finding?: SuiteFinding;
  readonly diagnostics: readonly SuiteDiagnostic[];
}

/**
 * Screen, attribute and adjudicate one probe pair on one slot.
 *
 * The two arms of a mini-pair are still sent strictly back to back inside `runLadder`: their
 * temporal adjacency is what defends against a backend that alternates between two responses.
 * Independent pairs, however, may run concurrently, which is where the throughput comes from.
 */
async function runPair(
  options: SuiteOptions,
  item: WorkItem,
  random: RandomSource,
): Promise<PairOutcome> {
  const { transport } = options;
  const { slot, probe } = item;
  const diagnostics: SuiteDiagnostic[] = [];
  const note = (kind: DiagnosticKind, detail: string): PairOutcome => {
    diagnostics.push({ probeId: probe.id, slotName: slot.name, kind, detail });
    return { diagnostics };
  };

  // Built per probe, not per slot: the encoder's treatment of the payload depends on what the probe
  // declares about its own bytes.
  const build = makeArmBuilder(options, slot, probe.wireForm ?? "literal", random);

  /**
   * Base for resolving a relative `Location`.
   *
   * Deliberately the template's ORIGINAL target, not the spliced one. A relative redirect resolves
   * against the request's directory, so taking it from the payload-bearing target would make the two
   * arms resolve to different paths whenever the payload sits in the path itself -- turning the
   * measurement into a comparison of two different pages. Fixing the base keeps the payload the only
   * variable.
   */
  const base: Located = {
    origin: {
      host: options.target.host,
      port: options.target.port,
      tls: options.target.tls,
    },
    target: sliceText(options.template.raw, options.template.targetRange),
  };
  const measureDeps: MeasureDeps = {
    transport,
    base,
    ...(options.observer === undefined ? {} : { observer: options.observer }),
  };

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
    ladder = await runLadder(
      {
        transport,
        random,
        canary: canaryFor,
        base,
        ...(options.observer === undefined ? {} : { observer: options.observer }),
      },
      arms,
    );
  } catch (error) {
    if (error instanceof PayloadNotDeliverable) {
      return note("inconclusive", `payload not deliverable on this surface: ${error.message}`);
    }
    throw error;
  }

  if (ladder.kind === "boring") {
    return note("boring", `no consistent difference (${ladder.stage}, ${ladder.sends} sends)`);
  }
  if (ladder.kind === "inconclusive") {
    return note("inconclusive", `${ladder.reason}: ${ladder.detail}`);
  }
  if (ladder.kind === "veto-payload-delta") {
    return note(
      "veto-payload-delta",
      `explained by the payload delta: ${ladder.explained.map((w) => w.name).join(", ")}`,
    );
  }

  // Candidate. Re-measure once so the control arms have a live reference, then spend them.
  // Through measure(), like every other arm: the witnesses being attributed describe the OBSERVED
  // response, so the reference and the controls must describe it too.
  const refCanary = canaryFor();
  const breakSend = await measure(measureDeps, build(arms.breakPayload, refCanary), {
    label: `${probe.id}:remeasure-break`,
  });
  const escapeSend = await measure(measureDeps, build(arms.escapePayload, refCanary), {
    label: `${probe.id}:remeasure-escape`,
  });
  if (breakSend.kind !== "ok" || escapeSend.kind !== "ok") {
    const why =
      breakSend.kind === "observation-unusable"
        ? breakSend.detail
        : escapeSend.kind === "observation-unusable"
          ? escapeSend.detail
          : "the pair did not re-measure";
    return note("inconclusive", `could not re-measure the pair for attribution: ${why}`);
  }

  const breakVector = featurise(breakSend.measured, {
    canary: refCanary,
    sentPayload: arms.breakPayload,
  });
  const escapeVector = featurise(escapeSend.measured, {
    canary: refCanary,
    sentPayload: arms.escapePayload,
  });

  const live = differingFeatures(breakVector, escapeVector).filter((d) =>
    ladder.witnesses.some((w) => w.name === d.name && w.sign === d.sign),
  );
  if (live.length === 0) {
    return note("inconclusive", "witnesses did not reproduce on re-measurement");
  }

  const controlArms = buildControlArms(arms.breakPayload, random);
  const observations: { arm: ControlArm; sides: Side[][] }[] = [];

  for (const arm of controlArms) {
    const perWitness: Side[][] = live.map(() => []);
    let failed = false;
    for (let replicate = 0; replicate < CONTROL_REPLICATES; replicate++) {
      const canary = canaryFor();
      const result = await measure(measureDeps, build(arm.payload, canary), {
        label: `${probe.id}:control-${arm.name}`,
      });
      if (result.kind !== "ok") {
        failed = true;
        break;
      }
      const vector = featurise(result.measured, { canary, sentPayload: arm.payload });
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
    if (failed) return note("inconclusive", "a control arm could not be measured");
    observations.push({ arm, sides: perWitness });
  }

  const veto = applyControlVetoes(live, observations);
  if (veto.survivors.length === 0) {
    return note(
      "veto-control",
      veto.vetoed.map((v) => `${v.witness.name} attributed to ${v.by} (${v.explains})`).join("; "),
    );
  }

  // Persisted evidence: re-send the winning break arm so a finding cites the exact exchange its
  // claim was computed from.
  let evidenceRequestId: string | undefined;
  let observedVia: readonly string[] = [];
  const evidence = await measure(measureDeps, build(arms.breakPayload, refCanary), {
    persist: true,
    label: `${probe.id}:evidence`,
  });
  if (evidence.kind === "ok") {
    // Cite the exchange the claim was actually computed from. With an observer that is the observed
    // response, not the injection request -- pointing at the injection would show a 302 with nothing
    // in it and leave the operator to guess where the rendered payload was seen. `persist` propagates
    // to the observation leg, so both are in the database and either id is citable.
    evidenceRequestId = evidence.measured.requestId ?? evidence.probe.requestId;
    observedVia = evidence.via;
  }

  return {
    diagnostics,
    finding: {
      probeId: probe.id,
      probeName: probe.name,
      slot,
      confidence: gradeConfidence(veto.survivors),
      breakPayload: arms.breakPayload,
      escapePayload: arms.escapePayload,
      ...(observedVia.length === 0 ? {} : { observedVia }),
      witnesses: veto.survivors,
      attributedElsewhere: veto.vetoed.map((v) => ({
        witness: v.witness,
        by: v.by,
        explains: v.explains,
      })),
      ...(evidenceRequestId === undefined ? {} : { evidenceRequestId }),
    },
  };
}

export async function runSuite(
  options: SuiteOptions,
  events: SuiteEvents = {},
): Promise<SuiteSummary> {
  const { transport } = options;

  const items: WorkItem[] = [];
  for (const slot of options.slots) {
    for (const probe of options.probes) {
      items.push({ slot, probe, index: items.length });
    }
  }

  // One base seed drawn from the caller's generator, then an independent stream per item. This is
  // what lets pairs run concurrently while keeping each one reproducible.
  const baseSeed = Math.floor(options.random() * 0x100000000) >>> 0;

  const outcomes = new Array<PairOutcome | undefined>(items.length);
  let nextIndex = 0;
  let probesDone = 0;
  let stopReason: "cancelled" | "halted" | undefined;

  const worker = async (): Promise<void> => {
    for (;;) {
      if (stopReason !== undefined) return;
      if (options.cancelled?.() === true) {
        stopReason = "cancelled";
        return;
      }
      if (transport.stats().state === "halted") {
        stopReason = "halted";
        return;
      }

      const index = nextIndex;
      nextIndex += 1;
      if (index >= items.length) return;
      const item = items[index]!;

      outcomes[index] = await runPair(options, item, splitmix32(baseSeed ^ (index * 0x9e3779b9)));

      probesDone += 1;
      const outcome = outcomes[index]!;
      for (const diagnostic of outcome.diagnostics) events.onDiagnostic?.(diagnostic);
      if (outcome.finding !== undefined) events.onFinding?.(outcome.finding);

      events.onProgress?.({
        slotsDone: Math.min(options.slots.length, Math.floor(probesDone / Math.max(1, options.probes.length))),
        slotsTotal: options.slots.length,
        probesDone,
        probesTotal: items.length,
        sends: transport.stats().sent,
      });
    }
  };

  // Pairs run concurrently; the transport still governs the aggregate request rate through its own
  // concurrency cap and inter-request gap. Defaults to one so a caller that does not opt in keeps
  // strictly sequential, reproducible behaviour.
  // Serialisation wins over the requested width. A shared observation sink read by two concurrent
  // pairs returns the other pair's payload, which is a wrong answer rather than a slow one.
  const requested = options.serialiseProbes === true ? 1 : (options.pairConcurrency ?? 1);
  const width = Math.max(1, Math.min(requested, items.length || 1));
  await Promise.all(Array.from({ length: width }, () => worker()));

  // Collected in item order regardless of completion order, so the summary is deterministic.
  const findings: SuiteFinding[] = [];
  const diagnostics: SuiteDiagnostic[] = [];
  for (const outcome of outcomes) {
    if (outcome === undefined) continue;
    diagnostics.push(...outcome.diagnostics);
    if (outcome.finding !== undefined) findings.push(outcome.finding);
  }

  // One diagnostic for the stop, rather than one per probe that never ran.
  if (stopReason !== undefined) {
    const remaining = items.length - probesDone;
    const stopNote: SuiteDiagnostic = {
      probeId: "-",
      slotName: "-",
      kind: "inconclusive",
      detail:
        stopReason === "cancelled"
          ? `stopped by the operator with ${remaining} probe(s) not run`
          : `transport halted with ${remaining} probe(s) not run: the target stopped answering usefully`,
    };
    diagnostics.push(stopNote);
    events.onDiagnostic?.(stopNote);
  }

  const stats = transport.stats();
  return {
    findings,
    diagnostics,
    sends: stats.sent,
    ...(stats.haltReason !== undefined
      ? { haltReason: stats.haltReason.kind }
      : stopReason === "cancelled"
        ? { haltReason: "cancelled" }
        : {}),
  };
}
