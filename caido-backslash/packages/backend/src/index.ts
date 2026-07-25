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
import { EVENT_DONE, EVENT_FINDING, EVENT_PROGRESS } from "../../shared/src/api.ts";

import { createCaidoProvider } from "./caido-transport.ts";

/**
 * Events this backend emits. Must mirror BackslashEvents in the shared package; the literal keys are
 * spelled out because a computed key from a const is not usable in a type literal.
 */
export type Events = DefineEvents<{
  "backslash:progress": (progress: ScanProgress) => void;
  "backslash:finding": (finding: ScanFinding) => void;
  "backslash:done": (result: ScanResult) => void;
}>;

/** The fully-typed SDK handle. Without the Events parameter, `sdk.api.send` narrows to never. */
type BackendSDK = SDK<API, Events>;

/** Probe counts per aggressivity. `ctx.limit`-style slicing, so catalogue order is meaningful. */
const PROBE_LIMIT: Record<string, number> = { low: 4, medium: 12, high: ALL_STATIC_PROBES.length };
const SLOT_LIMIT: Record<string, number> = { low: 3, medium: 8, high: 24 };

interface ActiveScan {
  readonly progress: ScanProgress;
  readonly transport: ProbeTransport;
  cancelled: boolean;
  result?: ScanResult;
}

const scans = new Map<string, ActiveScan>();
let scanCounter = 0;

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

    const raw = stored.request.getRaw().toBytes();
    const template = locate(raw);
    const enumeration = enumerateSlots(template);

    const slots = enumeration.slots
      .filter((s) => input.slotFilter === undefined || s.name === input.slotFilter)
      .slice(0, SLOT_LIMIT[input.aggressivity] ?? 8);
    const probes = ALL_STATIC_PROBES.slice(0, PROBE_LIMIT[input.aggressivity] ?? 12);

    let seed = 0x9e3779b9 >>> 0;
    const random = (): number => {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      seed >>>= 0;
      return seed / 0xffffffff;
    };

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
          scans.set(scanId, { ...active, progress: next });
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
    sdk.api.send(EVENT_DONE, active.result);
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
    sdk.api.send(EVENT_DONE, active.result);
  }
}

async function startScan(
  sdk: BackendSDK,
  input: ScanRequestInput,
): Promise<ApiResult<{ scanId: string }>> {
  scanCounter += 1;
  const scanId = `scan-${scanCounter}`;

  const transport = createProbeTransport(
    {
      provider: createCaidoProvider(sdk),
      sleep: (ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)),
      now: () => Date.now(),
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
