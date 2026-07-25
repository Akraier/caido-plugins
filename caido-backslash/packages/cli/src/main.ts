/**
 * Command-line harness.
 *
 * Runs the engine against a real target so the detector can be exercised without Caido. Reads a raw
 * HTTP request from a file, enumerates its injectable slots, and runs the screening ladder plus
 * control-arm attribution for each probe on each slot.
 *
 * Scope guard: the host allowlist is enforced here, not in a UI. A scanner that can be pointed at
 * an arbitrary host by a typo is a liability during an engagement.
 */

import { readFileSync } from "node:fs";

import {
  ALL_STATIC_PROBES,
  DEFAULT_THROTTLE,
  type ProbeArms,
  type ProbePair,
  type Slot,
  applyControlVetoes,
  asciiBytes,
  assemble,
  buildControlArms,
  createProbeTransport,
  differingFeatures,
  enumerateSlots,
  equalisePair,
  featurise,
  gradeConfidence,
  isHalted,
  isUsable,
  locate,
  readFeature,
  runLadder,
  sideOf,
  type Canary,
  type ControlArm,
  type FeatureDiff,
  type FeatureVector,
  type ProbeTransport,
  type Side,
} from "@caido-backslash/engine";

import { createNodeProvider } from "./node-provider.ts";

interface Args {
  readonly requestFile: string;
  readonly host: string;
  readonly port: number;
  readonly tls: boolean;
  readonly allow: readonly string[];
  readonly insecure: boolean;
  readonly delayMs: number;
  readonly concurrency: number;
  readonly slotFilter?: string;
  readonly probeFilter?: string;
  readonly maxSlots: number;
}

function parseArgs(argv: readonly string[]): Args {
  const get = (flag: string): string | undefined => {
    const at = argv.indexOf(flag);
    return at === -1 ? undefined : argv[at + 1];
  };
  const requestFile = get("--request");
  const host = get("--host");
  if (requestFile === undefined || host === undefined) {
    throw new Error(
      "usage: backslash --request <raw-request-file> --host <host> [--port 443] [--no-tls]\n" +
        "                 [--allow host,host] [--insecure] [--delay-ms 0] [--concurrency 2]\n" +
        "                 [--slot <name>] [--probe <id>] [--max-slots 10]",
    );
  }
  const tls = !argv.includes("--no-tls");
  const allowRaw = get("--allow");
  const args: Args = {
    requestFile,
    host,
    port: Number.parseInt(get("--port") ?? (tls ? "443" : "80"), 10),
    tls,
    allow: allowRaw === undefined ? [host] : allowRaw.split(",").map((h) => h.trim()),
    insecure: argv.includes("--insecure"),
    delayMs: Number.parseInt(get("--delay-ms") ?? "0", 10),
    concurrency: Number.parseInt(get("--concurrency") ?? "2", 10),
    maxSlots: Number.parseInt(get("--max-slots") ?? "10", 10),
  };
  const slot = get("--slot");
  const probe = get("--probe");
  return {
    ...args,
    ...(slot === undefined ? {} : { slotFilter: slot }),
    ...(probe === undefined ? {} : { probeFilter: probe }),
  };
}

/** Probes whose semantics require the payload to be last in the value. */
const END_ANCHORED_STAGES = new Set(["delimiter", "escape-sequence"]);

function randomToken(length: number, random: () => number): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[Math.floor(random() * alphabet.length)] ?? "z";
  return out;
}

function makeArmBuilder(
  template: ReturnType<typeof locate>,
  slot: Slot,
  host: string,
  port: number,
  tls: boolean,
  random: () => number,
) {
  return (payload: string, canary: Canary) => {
    const framed =
      canary.right === undefined
        ? `${slot.baseValue}${canary.left}${payload}`
        : `${slot.baseValue}${canary.left}${payload}${canary.right}`;
    const encoded = slot.codec.encode(asciiBytes(framed), "literal");
    if (!encoded.ok) throw new Error(`payload not deliverable on ${slot.name}: ${encoded.detail}`);

    // Fixed-length cache buster: a variable-length one would reintroduce the length artefact that
    // excision exists to remove.
    const buster = `cb${randomToken(6, random)}=${randomToken(8, random)}`;
    const raw = assemble(template, [{ range: slot.range, bytes: encoded.bytes }]);
    const withBuster = injectCacheBuster(raw, buster);
    return { host, port, tls, raw: withBuster };
  };
}

/** Append a cache-busting parameter to the query, or create a query if there is none. */
function injectCacheBuster(raw: Uint8Array, buster: string): Uint8Array {
  const template = locate(raw);
  const target = template.targetRange;
  let hasQuery = false;
  for (let i = target.start; i < target.end; i++) {
    if (raw[i] === 0x3f) {
      hasQuery = true;
      break;
    }
  }
  const insertion = asciiBytes(hasQuery ? `&${buster}` : `?${buster}`);
  return assemble(template, [{ range: { start: target.end, end: target.end }, bytes: insertion }]);
}

/** Send one control arm twice and record which side it landed on for each witness. */
async function observeControl(
  transport: ProbeTransport,
  arm: ControlArm,
  build: ReturnType<typeof makeArmBuilder>,
  canaryFor: () => Canary,
  witnesses: readonly FeatureDiff[],
  breakVector: FeatureVector,
  escapeVector: FeatureVector,
  keywordIndex: (name: string) => number,
): Promise<{ arm: ControlArm; sides: Side[][] } | undefined> {
  const perWitness: Side[][] = witnesses.map(() => []);

  for (let replicate = 0; replicate < 2; replicate++) {
    const canary = canaryFor();
    const result = await transport.send(build(arm.payload, canary));
    if (isHalted(result) || !isUsable(result)) return undefined;
    const vector = featurise(result.response, { canary, sentPayload: arm.payload });

    for (let w = 0; w < witnesses.length; w++) {
      const witness = witnesses[w]!;
      const read = (v: FeatureVector): number | string | undefined => {
        if (witness.name.startsWith("kw:")) {
          const index = keywordIndex(witness.name.slice(3));
          return index === -1 ? undefined : v.keywords[index];
        }
        return readFeature(v, witness.name);
      };
      perWitness[w]!.push(
        sideOf(witness, read(vector), read(breakVector) ?? witness.breakValue, read(escapeVector) ?? witness.escapeValue),
      );
    }
  }

  return { arm, sides: perWitness };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (!args.allow.includes(args.host)) {
    throw new Error(
      `refusing to scan ${args.host}: not in the allowlist (${args.allow.join(", ")}). ` +
        "Pass --allow explicitly.",
    );
  }

  const raw = new Uint8Array(readFileSync(args.requestFile));
  const template = locate(raw);
  const { slots, deferred } = enumerateSlots(template);

  let seed = 0x2f6e2b1 >>> 0;
  const random = (): number => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    seed >>>= 0;
    return seed / 0xffffffff;
  };

  const transport = createProbeTransport(
    {
      provider: createNodeProvider({ insecure: args.insecure }),
      sleep: (ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)),
      now: () => Date.now(),
    },
    { ...DEFAULT_THROTTLE, minDelayMs: args.delayMs, maxConcurrent: args.concurrency },
  );

  const keywordNames = (await import("@caido-backslash/engine")).KEYWORDS;
  const keywordIndex = (needle: string): number => keywordNames.indexOf(needle);

  const chosenSlots = slots
    .filter((s) => args.slotFilter === undefined || s.name === args.slotFilter)
    .slice(0, args.maxSlots);
  const chosenProbes = ALL_STATIC_PROBES.filter(
    (p) => args.probeFilter === undefined || p.id === args.probeFilter,
  );

  console.log(`target      ${args.tls ? "https" : "http"}://${args.host}:${args.port}`);
  console.log(`request     ${args.requestFile} (${raw.length} bytes)`);
  console.log(`slots       ${chosenSlots.length} of ${slots.length} enumerated`);
  if (deferred.length > 0) {
    for (const item of deferred) console.log(`  deferred  ${item.kind}: ${item.reason}`);
  }
  console.log(`probes      ${chosenProbes.length}`);
  console.log("");

  let findings = 0;
  let totalSends = 0;

  for (const slot of chosenSlots) {
    for (const probe of chosenProbes) {
      if (transport.stats().state === "halted") break;

      const outcome = await runProbe(probe, slot);
      totalSends = transport.stats().sent;
      if (outcome !== undefined) findings += 1;
    }
  }

  console.log("");
  console.log(`sends       ${totalSends}`);
  console.log(`findings    ${findings}`);
  const stats = transport.stats();
  console.log(`transport   ${stats.state}${stats.haltReason === undefined ? "" : ` (${stats.haltReason.kind})`}`);
  if (stats.tally.softFail > 0 || stats.tally.hardFail > 0) {
    const reasons = [...stats.tally.reasons.entries()].map(([k, v]) => `${k}=${v}`).join(" ");
    console.log(`unusable    ${stats.tally.softFail} soft, ${stats.tally.hardFail} hard (${reasons})`);
  }

  async function runProbe(probe: ProbePair, slot: Slot): Promise<boolean | undefined> {
    const endAnchored = END_ANCHORED_STAGES.has(probe.stage);
    const build = makeArmBuilder(template, slot, args.host, args.port, args.tls, random);

    const canaryFor = (): Canary => ({
      left: `bs${randomToken(4, random)}`,
      right: `${randomToken(4, random)}se`,
    });

    // One representative pair from the probe, length-equalised where the catalogue permits.
    const breakPayload = probe.breaks[0]!;
    const escapePayload = probe.escapeSets[0]![0]!;
    const strategy =
      probe.parity === "pad-numeric" ? "numeric" : probe.parity === "pad-filler" ? "filler" : "none";
    const equalised = equalisePair(breakPayload, escapePayload, strategy);

    const arms: ProbeArms = {
      breakPayload: equalised.breakPayload,
      escapePayload: equalised.escapePayload,
      build,
      ...(endAnchored ? { endAnchored: true } : {}),
    };

    const ladder = await runLadder({ transport, random, canary: canaryFor }, arms);

    if (ladder.kind === "boring") return undefined;
    if (ladder.kind === "inconclusive") {
      console.log(`?  ${slot.name} / ${probe.id}: ${ladder.reason} — ${ladder.detail}`);
      return undefined;
    }
    if (ladder.kind === "veto-payload-delta") {
      console.log(
        `-  ${slot.name} / ${probe.id}: every difference explained by the payload delta ` +
          `(${ladder.explained.map((w) => w.name).join(", ")})`,
      );
      return undefined;
    }

    // Candidate: spend the control arms.
    const controlArms = buildControlArms(arms.breakPayload, random);
    const observations: { arm: ControlArm; sides: Side[][] }[] = [];

    // Re-derive reference vectors from one fresh pair so the controls have something to compare to.
    const refCanary = canaryFor();
    const refFrame = endAnchored ? { left: refCanary.left } : refCanary;
    const breakSend = await transport.send(build(arms.breakPayload, refFrame));
    const escapeSend = await transport.send(build(arms.escapePayload, refFrame));
    if (isHalted(breakSend) || !isUsable(breakSend) || isHalted(escapeSend) || !isUsable(escapeSend)) {
      console.log(`?  ${slot.name} / ${probe.id}: could not re-measure for attribution`);
      return undefined;
    }
    const breakVector = featurise(breakSend.response, {
      canary: refFrame,
      sentPayload: arms.breakPayload,
    });
    const escapeVector = featurise(escapeSend.response, {
      canary: refFrame,
      sentPayload: arms.escapePayload,
    });
    const liveWitnesses = differingFeatures(breakVector, escapeVector).filter((d) =>
      ladder.witnesses.some((w) => w.name === d.name),
    );
    if (liveWitnesses.length === 0) {
      console.log(`-  ${slot.name} / ${probe.id}: witnesses did not reproduce on re-measurement`);
      return undefined;
    }

    for (const arm of controlArms) {
      const observed = await observeControl(
        transport,
        arm,
        build,
        () => (endAnchored ? { left: canaryFor().left } : canaryFor()),
        liveWitnesses,
        breakVector,
        escapeVector,
        keywordIndex,
      );
      if (observed === undefined) {
        console.log(`?  ${slot.name} / ${probe.id}: control arm ${arm.name} could not be measured`);
        return undefined;
      }
      observations.push(observed);
    }

    const veto = applyControlVetoes(liveWitnesses, observations);
    if (veto.drifted) {
      console.log(`?  ${slot.name} / ${probe.id}: baseline drifted during attribution`);
      return undefined;
    }
    if (veto.survivors.length === 0) {
      const why = veto.vetoed.map((v) => `${v.witness.name} killed by ${v.by}`).join("; ");
      console.log(`-  ${slot.name} / ${probe.id}: all witnesses attributed elsewhere (${why})`);
      return undefined;
    }

    const confidence = gradeConfidence(veto.survivors);
    console.log("");
    console.log(`>> ${probe.name}  [${confidence.toUpperCase()}]`);
    console.log(`   surface   ${slot.kind} ${slot.name}`);
    console.log(`   break     ${JSON.stringify(arms.breakPayload)}`);
    console.log(`   escape    ${JSON.stringify(arms.escapePayload)}`);
    console.log(`   witnesses`);
    for (const w of veto.survivors) {
      console.log(`     ${w.name}: break=${String(w.breakValue)} escape=${String(w.escapeValue)}`);
    }
    if (veto.vetoed.length > 0) {
      console.log(`   attributed elsewhere`);
      for (const v of veto.vetoed) {
        console.log(`     ${v.witness.name}: ${v.by} — ${v.explains}`);
      }
    }
    console.log("");
    return true;
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
