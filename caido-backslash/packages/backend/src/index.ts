/**
 * Caido backend plugin.
 *
 * Thin by design: it wires the host-agnostic engine to Caido's transport, findings and RPC. All the
 * detection logic, and all of its tests, live in the engine package and know nothing about Caido.
 */

import type { DefineAPI, DefineEvents, SDK } from "caido:plugin";

import {
  ALL_STATIC_PROBES,
  DEFAULT_THROTTLE,
  createProbeTransport,
  enumerateSlots,
  type SendRecord,
  locate,
  runSuite,
  type ProbeTransport,
  type SuiteFinding,
} from "@caido-backslash/engine";

import type {
  ApiResult,
  ScanFinding,
  ScanProgress,
  ScanRequestInput,
  ScanResult,
} from "../../shared/src/api.ts";
import type { SendLogEntry } from "../../shared/src/api.ts";
import {
  AGGRESSIVITY_BUDGET,
  EVENT_DONE,
  EVENT_FINDING,
  EVENT_PROGRESS,
  EVENT_SENDS,
} from "../../shared/src/api.ts";

import { createCaidoProvider } from "./caido-transport.ts";

/**
 * Events this backend emits. Must mirror BackslashEvents in the shared package; the literal keys are
 * spelled out because a computed key from a const is not usable in a type literal.
 */
export type Events = DefineEvents<{
  "backslash:progress": (progress: ScanProgress) => void;
  "backslash:sends": (batch: import("../../shared/src/api.ts").SendLogBatch) => void;
  "backslash:finding": (finding: ScanFinding) => void;
  "backslash:done": (result: ScanResult) => void;
}>;

/** The fully-typed SDK handle. Without the Events parameter, `sdk.api.send` narrows to never. */
type BackendSDK = SDK<API, Events>;



/**
 * Live scan state.
 *
 * `progress` is mutable and this object is mutated in place rather than replaced in the map. An
 * earlier version did `scans.set(scanId, { ...active, progress: next })` on every progress tick,
 * which put a shallow COPY in the map while runScan's closure still held the original. The effects
 * were silent and nasty: cancelScan flipped `cancelled` on the copy so the running scan never saw
 * it, and runScan assigned `result` to the original so getResult always returned null.
 */
interface ActiveScan {
  progress: ScanProgress;
  readonly transport: ProbeTransport;
  cancelled: boolean;
  result?: ScanResult;
}

const scans = new Map<string, ActiveScan>();
const sendLogs = new Map<string, { record: (r: SendRecord) => void; flush: () => void }>();
let scanCounter = 0;

/**
 * How many finished scans stay queryable through `getResult`.
 *
 * Neither map used to be pruned, which was survivable while a tab was single-use: one scan per tab,
 * a handful per session. Re-running inside a tab makes many scans per session the normal case, and
 * each retained entry holds a full result set plus a spent transport, so the ceiling matters now.
 */
const RETAINED_SCANS = 20;

/** Release what a completed scan no longer needs, and evict the oldest finished results. */
function retire(scanId: string): void {
  // The log buffer has just been flushed to the frontend, which owns the lines from here on.
  sendLogs.delete(scanId);
  // Insertion order is oldest-first. Running scans are never evicted, however old.
  const finished = [...scans.entries()].filter(([, scan]) => scan.result !== undefined);
  for (const [id] of finished.slice(0, Math.max(0, finished.length - RETAINED_SCANS))) {
    scans.delete(id);
  }
}

function ok<T>(value: T): ApiResult<T> {
  return { kind: "ok", value };
}

function err<T>(error: string): ApiResult<T> {
  return { kind: "error", error };
}

function toScanFinding(scanId: string, finding: SuiteFinding): ScanFinding {
  return {
    scanId,
    probeId: finding.probeId,
    probeName: finding.probeName,
    confidence: finding.confidence,
    surface: finding.slot.kind,
    slotName: finding.slot.name,
    breakPayload: finding.breakPayload,
    escapePayload: finding.escapePayload,
    witnesses: finding.witnesses.map((w) => ({
      name: w.name,
      featureClass: w.featureClass,
      breakValue: String(w.breakValue),
      escapeValue: String(w.escapeValue),
    })),
    attributedElsewhere: finding.attributedElsewhere.map((a) => ({
      witness: a.witness.name,
      by: a.by,
      explains: a.explains,
    })),
    sends: 0,
    ...(finding.evidenceRequestId === undefined
      ? {}
      : { evidenceRequestId: finding.evidenceRequestId }),
  };
}

/**
 * Render a finding for Caido's Findings page.
 *
 * Core `FindingSpec` is `{title, description, reporter, request}` with no severity field, so
 * confidence goes into the description. The community scanner does the same thing; it is a gap in
 * the SDK rather than a choice.
 */
function renderDescription(finding: SuiteFinding): string {
  const lines: string[] = [];
  lines.push(
    `Confidence: **${finding.confidence.toUpperCase()}**. The application reacts to this input in a way ` +
      `that survived every control arm, so the difference is not explained by payload length, ` +
      `punctuation in general, byte-level filtering, or baseline drift.`,
  );
  lines.push("");
  lines.push(`- Surface: \`${finding.slot.kind}\` \`${finding.slot.name}\``);
  lines.push(`- Break payload: \`${finding.breakPayload}\``);
  lines.push(`- Escape payload: \`${finding.escapePayload}\``);
  lines.push("");
  lines.push("## Evidence");
  lines.push("Response attributes that differed consistently across every interleaved repeat:");
  lines.push("");
  for (const w of finding.witnesses) {
    lines.push(`- \`${w.name}\` (${w.featureClass}): break \`${String(w.breakValue)}\`, escape \`${String(w.escapeValue)}\``);
  }
  if (finding.attributedElsewhere.length > 0) {
    lines.push("");
    lines.push("## Ruled out");
    lines.push("Differences a control arm explained, and therefore not counted as evidence:");
    lines.push("");
    for (const a of finding.attributedElsewhere) {
      lines.push(`- \`${a.witness.name}\`: attributed to ${a.by} — ${a.explains}`);
    }
  }
  lines.push("");
  lines.push("## Interpretation");
  lines.push(
    "This is a report of anomalous input handling, not a confirmed vulnerability class. The next " +
      "step is to determine which interpreter is reacting, by hand or by letting the cascade " +
      "escalate.",
  );
  return lines.join("\n");
}

async function runScan(sdk: BackendSDK, scanId: string, input: ScanRequestInput): Promise<void> {
  const active = scans.get(scanId);
  if (active === undefined) return;

  const findings: ScanFinding[] = [];

  try {
    const stored = await sdk.requests.get(input.requestId);
    if (stored === undefined) {
      active.result = {
        scanId,
        findings: [],
        diagnostics: [
          {
            scanId,
            slotName: "-",
            probeId: "-",
            kind: "inconclusive",
            detail: `request ${input.requestId} not found`,
          },
        ],
        sends: 0,
        deferredSurfaces: [],
      };
      sdk.api.send(EVENT_DONE, active.result);
      return;
    }

    const budget = AGGRESSIVITY_BUDGET[input.aggressivity] ?? AGGRESSIVITY_BUDGET.medium;
    const raw = stored.request.getRaw().toBytes();
    const template = locate(raw);
    const enumeration = enumerateSlots(template);

    const slots = enumeration.slots
      .filter((s) => input.slotFilter === undefined || s.name === input.slotFilter)
      .slice(0, budget.slots);
    // `probes: null` means the entire catalogue, so it cannot fall behind as probes are added.
    const probes =
      budget.probes === null ? ALL_STATIC_PROBES : ALL_STATIC_PROBES.slice(0, budget.probes);

    let seed = 0x9e3779b9 >>> 0;
    const random = (): number => {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      seed >>>= 0;
      return seed / 0xffffffff;
    };

    // Stated in the log so the resolved budget is observable rather than inferred from the UI.
    sdk.console.log(
      `[backslash] ${scanId} aggressivity=${input.aggressivity} ` +
        `probes=${probes.length}/${ALL_STATIC_PROBES.length} slots=${slots.length}/${enumeration.slots.length}`,
    );

    const summary = await runSuite(
      {
        template,
        slots,
        probes,
        target: {
          host: stored.request.getHost(),
          port: stored.request.getPort(),
          tls: stored.request.getTls(),
        },
        transport: active.transport,
        random,
        // Same knob governs both: each pair holds at most one in-flight request, so the number of
        // concurrent pairs is what actually determines how many requests are in flight.
        pairConcurrency: Math.max(1, input.maxConcurrent),
        cancelled: () => active.cancelled,
      },
      {
        onProgress: (progress) => {
          const next: ScanProgress = {
            scanId,
            phase: "screening",
            slotsTotal: progress.slotsTotal,
            slotsDone: progress.slotsDone,
            probesTotal: progress.probesTotal,
            probesDone: progress.probesDone,
            sends: progress.sends,
            findings: findings.length,
          };
          // Mutate in place: replacing the map entry would detach it from this closure.
          active.progress = next;
          sdk.api.send(EVENT_PROGRESS, next);
        },
        onFinding: (finding) => {
          const view = toScanFinding(scanId, finding);
          findings.push(view);
          sdk.api.send(EVENT_FINDING, view);

          // Only a saved request can be cited. The engine re-sends the winning arm with persistence
          // on for exactly this reason, so the attached exchange is the one the claim came from.
          void (async () => {
            try {
              const evidenceId = finding.evidenceRequestId;
              const target =
                evidenceId === undefined ? undefined : await sdk.requests.get(evidenceId);
              await sdk.findings.create({
                title: `Anomalous input handling: ${finding.probeName}`,
                description: renderDescription(finding),
                reporter: "Backslash",
                dedupeKey: `backslash:${finding.probeId}:${finding.slot.kind}:${finding.slot.name}`,
                request: (target ?? stored).request,
              });
            } catch (error) {
              sdk.console.error(
                `failed to create finding: ${error instanceof Error ? error.message : String(error)}`,
              );
            }
          })();
        },
        onDiagnostic: (diagnostic) => {
          // Diagnostics are not findings, but they must be visible: a measurement blinded by rate
          // limiting is not a clean result, and only the log distinguishes the two.
          if (diagnostic.kind !== "boring") {
            sdk.console.log(
              `[backslash] ${diagnostic.slotName} / ${diagnostic.probeId}: ${diagnostic.kind} — ${diagnostic.detail}`,
            );
          }
        },
      },
    );

    active.result = {
      scanId,
      findings,
      diagnostics: summary.diagnostics.map((d) => ({ scanId, ...d })),
      sends: summary.sends,
      deferredSurfaces: enumeration.deferred.map((d) => ({ kind: d.kind, reason: d.reason })),
      ...(summary.haltReason === undefined ? {} : { haltReason: summary.haltReason }),
    };
    sendLogs.get(scanId)?.flush();
    sdk.api.send(EVENT_DONE, active.result);
    retire(scanId);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    sdk.console.error(`[backslash] scan ${scanId} failed: ${message}`);
    active.result = {
      scanId,
      findings,
      diagnostics: [
        { scanId, slotName: "-", probeId: "-", kind: "inconclusive", detail: message },
      ],
      sends: active.transport.stats().sent,
      deferredSurfaces: [],
    };
    sendLogs.get(scanId)?.flush();
    sdk.api.send(EVENT_DONE, active.result);
    retire(scanId);
  }
}

/**
 * Batch transport log lines before pushing them to the frontend.
 *
 * A scan produces thousands of sends. One IPC event each would swamp the channel and the UI, so
 * lines are coalesced by count or by a short interval, whichever comes first.
 */
function createSendLog(
  sdk: BackendSDK,
  scanId: string,
): { record: (r: SendRecord) => void; flush: () => void } {
  const BATCH = 25;
  const FLUSH_MS = 250;
  let pending: SendLogEntry[] = [];
  let total = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const flush = (): void => {
    if (timer !== undefined) {
      clearTimeout(timer);
      timer = undefined;
    }
    if (pending.length === 0) return;
    const entries = pending;
    pending = [];
    sdk.api.send(EVENT_SENDS, { scanId, entries, totalSends: total });
  };

  return {
    record: (r: SendRecord) => {
      total += 1;
      pending.push({
        seq: r.seq,
        atMs: r.atMs,
        method: r.method,
        target: r.target,
        outcome: r.outcome,
        persisted: r.persisted,
        ...(r.label === undefined ? {} : { label: r.label }),
        ...(r.reason === undefined ? {} : { reason: r.reason }),
        ...(r.status === undefined ? {} : { status: r.status }),
        ...(r.bodyLength === undefined ? {} : { bodyLength: r.bodyLength }),
        ...(r.rttMs === undefined ? {} : { rttMs: r.rttMs }),
      });
      if (pending.length >= BATCH) flush();
      else if (timer === undefined) timer = setTimeout(flush, FLUSH_MS);
    },
    flush,
  };
}

async function startScan(
  sdk: BackendSDK,
  input: ScanRequestInput,
): Promise<ApiResult<{ scanId: string }>> {
  scanCounter += 1;
  const scanId = `scan-${scanCounter}`;

  const sendLog = createSendLog(sdk, scanId);
  sendLogs.set(scanId, sendLog);

  const transport = createProbeTransport(
    {
      // Every request is saved, unconditionally: see caido-transport.ts. The operator must be able
      // to inspect and replay the scan's real traffic, not just read counters.
      provider: createCaidoProvider(sdk),
      sleep: (ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)),
      now: () => Date.now(),
      onSend: sendLog.record,
    },
    {
      ...DEFAULT_THROTTLE,
      minDelayMs: input.delayMs,
      maxConcurrent: Math.max(1, input.maxConcurrent),
    },
  );

  scans.set(scanId, {
    transport,
    cancelled: false,
    progress: {
      scanId,
      phase: "enumerating",
      slotsTotal: 0,
      slotsDone: 0,
      probesTotal: 0,
      probesDone: 0,
      sends: 0,
      findings: 0,
    },
  });

  // Deliberately not awaited: a scan runs for minutes and the caller must not block on it.
  void runScan(sdk, scanId, input);
  return Promise.resolve(ok({ scanId }));
}

export type API = DefineAPI<{
  startScan: typeof startScanHandler;
  cancelScan: typeof cancelScanHandler;
  getResult: typeof getResultHandler;
  listScans: typeof listScansHandler;
}>;

function startScanHandler(sdk: BackendSDK, input: ScanRequestInput): Promise<ApiResult<{ scanId: string }>> {
  return startScan(sdk, input);
}

function cancelScanHandler(_sdk: SDK, scanId: string): ApiResult<null> {
  const active = scans.get(scanId);
  if (active === undefined) return err("no such scan");
  active.cancelled = true;
  active.transport.halt({ kind: "cancelled" });
  return ok(null);
}

function getResultHandler(_sdk: SDK, scanId: string): ApiResult<ScanResult | null> {
  const active = scans.get(scanId);
  if (active === undefined) return err("no such scan");
  return ok(active.result ?? null);
}

function listScansHandler(): ApiResult<readonly ScanProgress[]> {
  return ok([...scans.values()].map((s) => s.progress));
}

export function init(sdk: BackendSDK): void {
  sdk.api.register("startScan", startScanHandler);
  sdk.api.register("cancelScan", cancelScanHandler);
  sdk.api.register("getResult", getResultHandler);
  sdk.api.register("listScans", listScansHandler);
  sdk.console.log("[backslash] backend ready");
}
