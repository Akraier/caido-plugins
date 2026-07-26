/**
 * Command-line harness.
 *
 * Drives the engine against a real target without Caido, over raw sockets. It is deliberately thin:
 * the orchestration lives in the engine's `runSuite`, so the CLI and the Caido plugin execute the
 * *same* detection path.
 *
 * An earlier version of this file carried its own copy of that loop, and it had already drifted --
 * it hardcoded the payload encoding as plain literal, so it silently mangled every probe whose
 * syntax contains a percent sign. That is exactly the failure mode the original Java tool suffered
 * from with its parallel WebSocket scan, which drifted 77 lines from the HTTP one.
 *
 * Scope guard: the host allowlist is enforced here, not in a UI. A scanner that can be pointed at an
 * arbitrary host by a typo is a liability during an engagement.
 */

import { readFileSync } from "node:fs";

import {
  ALL_STATIC_PROBES,
  DEFAULT_THROTTLE,
  composeObservers,
  createProbeTransport,
  createRedirectObserver,
  createUrlObserver,
  enumerateSlots,
  formatLocated,
  locate,
  type ObserveSend,
  parseObservationUrl,
  runSuite,
  sameOrigin,
  type SendRecord,
  type SuiteDiagnostic,
  type SuiteFinding,
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
  readonly verbose: boolean;
  readonly followRedirects: boolean;
  readonly maxHops: number;
  readonly observeUrl?: string;
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
        "                 [--slot <name>] [--probe <id>] [--max-slots 10] [--verbose]\n" +
        "                 [--follow-redirects] [--max-hops 3] [--observe <url-or-path>]",
    );
  }
  const tls = !argv.includes("--no-tls");
  const allowRaw = get("--allow");
  const slot = get("--slot");
  const probe = get("--probe");
  const observe = get("--observe");
  return {
    followRedirects: argv.includes("--follow-redirects"),
    maxHops: Number.parseInt(get("--max-hops") ?? "3", 10),
    ...(observe === undefined ? {} : { observeUrl: observe }),
    requestFile,
    host,
    port: Number.parseInt(get("--port") ?? (tls ? "443" : "80"), 10),
    tls,
    allow: allowRaw === undefined ? [host] : allowRaw.split(",").map((h) => h.trim()),
    insecure: argv.includes("--insecure"),
    delayMs: Number.parseInt(get("--delay-ms") ?? "0", 10),
    concurrency: Number.parseInt(get("--concurrency") ?? "2", 10),
    maxSlots: Number.parseInt(get("--max-slots") ?? "10", 10),
    verbose: argv.includes("--verbose"),
    ...(slot === undefined ? {} : { slotFilter: slot }),
    ...(probe === undefined ? {} : { probeFilter: probe }),
  };
}

function printFinding(finding: SuiteFinding): void {
  console.log("");
  console.log(`>> ${finding.probeName}  [${finding.confidence.toUpperCase()}]`);
  console.log(`   surface   ${finding.slot.kind} ${finding.slot.name}`);
  console.log(`   break     ${JSON.stringify(finding.breakPayload)}`);
  console.log(`   escape    ${JSON.stringify(finding.escapePayload)}`);
  if (finding.observedVia !== undefined && finding.observedVia.length > 0) {
    console.log(`   MEASURED ON ANOTHER RESPONSE, not this endpoint's reply`);
    for (const hop of finding.observedVia) console.log(`     -> ${hop}`);
  }
  console.log(`   witnesses`);
  for (const w of finding.witnesses) {
    console.log(`     ${w.name}: break=${String(w.breakValue)} escape=${String(w.escapeValue)}`);
  }
  if (finding.attributedElsewhere.length > 0) {
    console.log(`   ruled out by a control arm`);
    for (const a of finding.attributedElsewhere) {
      console.log(`     ${a.witness.name}: ${a.by} — ${a.explains}`);
    }
  }
  console.log("");
}

function printDiagnostic(diagnostic: SuiteDiagnostic): void {
  // "boring" is the overwhelming majority and says nothing; everything else is worth seeing.
  if (diagnostic.kind === "boring") return;
  const marker = diagnostic.kind === "inconclusive" || diagnostic.kind === "drift" ? "?" : "-";
  console.log(`${marker}  ${diagnostic.slotName} / ${diagnostic.probeId}: ${diagnostic.detail}`);
}

function printSend(record: SendRecord): void {
  const status = record.status === undefined ? "---" : String(record.status);
  const size = record.bodyLength === undefined ? "" : `${record.bodyLength}b`;
  const rtt = record.rttMs === undefined ? "" : `${record.rttMs}ms`;
  const note = record.reason === undefined ? "" : ` ${record.reason}`;
  console.log(
    `   ${String(record.seq).padStart(5)}  ${status}  ${size.padStart(8)} ${rtt.padStart(7)}  ` +
      `${(record.label ?? "-").padEnd(32)} ${record.method} ${record.target}${note}`,
  );
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
  const enumeration = enumerateSlots(template);

  const slots = enumeration.slots
    .filter((s) => args.slotFilter === undefined || s.name === args.slotFilter)
    .slice(0, args.maxSlots);
  const probes = ALL_STATIC_PROBES.filter(
    (p) => args.probeFilter === undefined || p.id === args.probeFilter,
  );

  if (slots.length === 0) throw new Error("no matching injectable slots");
  if (probes.length === 0) throw new Error("no matching probes");

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
      ...(args.verbose ? { onSend: printSend } : {}),
    },
    { ...DEFAULT_THROTTLE, minDelayMs: args.delayMs, maxConcurrent: args.concurrency },
  );

  console.log(`target      ${args.tls ? "https" : "http"}://${args.host}:${args.port}`);
  console.log(`request     ${args.requestFile} (${raw.length} bytes)`);
  console.log(`slots       ${slots.length} of ${enumeration.slots.length} enumerated`);
  for (const item of enumeration.deferred) {
    console.log(`  deferred  ${item.kind}: ${item.reason}`);
  }
  console.log(`probes      ${probes.length}`);

  // Same construction as the Caido backend, deliberately: the CLI and the plugin must measure the
  // same response for the same flags, or one of them is testing something else.
  const origin = { host: args.host, port: args.port, tls: args.tls };
  const send: ObserveSend = (request, options) => transport.send(request, options);
  const observers = [];
  let serialiseProbes = false;

  if (args.followRedirects) {
    observers.push(
      createRedirectObserver({ template, send, maxHops: Math.max(1, Math.min(10, args.maxHops)) }),
    );
    console.log(`measuring   redirect target (<=${args.maxHops} same-origin hops)`);
  }
  if (args.observeUrl !== undefined) {
    const parsed = parseObservationUrl(args.observeUrl, origin);
    if (parsed.kind !== "ok") throw new Error(`--observe rejected: ${parsed.detail}`);
    if (!sameOrigin(parsed.located.origin, origin)) {
      console.log(`WARNING     observation URL is on a different origin than the scanned request`);
    }
    observers.push(createUrlObserver({ template, send, at: parsed.located }));
    serialiseProbes = true;
    console.log(`measuring   ${formatLocated(parsed.located)} after every probe`);
    console.log(`            pairs run one at a time (a shared sink cannot be measured in parallel)`);
  }
  const observer =
    observers.length === 0
      ? undefined
      : observers.length === 1
        ? observers[0]!
        : composeObservers(observers[0]!, observers[1]!);
  console.log("");

  const summary = await runSuite(
    {
      template,
      slots,
      probes,
      target: origin,
      transport,
      random,
      ...(observer === undefined ? {} : { observer }),
      ...(serialiseProbes ? { serialiseProbes: true } : {}),
      pairConcurrency: args.concurrency,
    },
    { onFinding: printFinding, onDiagnostic: printDiagnostic },
  );

  console.log("");
  console.log(`sends       ${summary.sends}`);
  console.log(`findings    ${summary.findings.length}`);
  const stats = transport.stats();
  console.log(
    `transport   ${stats.state}${summary.haltReason === undefined ? "" : ` (${summary.haltReason})`}`,
  );
  if (stats.tally.softFail > 0 || stats.tally.hardFail > 0) {
    const reasons = [...stats.tally.reasons.entries()].map(([k, v]) => `${k}=${v}`).join(" ");
    console.log(
      `unusable    ${stats.tally.softFail} soft, ${stats.tally.hardFail} hard (${reasons})`,
    );
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
