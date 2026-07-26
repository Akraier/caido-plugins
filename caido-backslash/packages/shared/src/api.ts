/**
 * The typed contract between frontend and backend.
 *
 * Shared so a rename cannot silently desynchronise the two halves: the frontend calls
 * `sdk.backend.startScan(...)` and the backend registers `startScan`, and only a shared type makes
 * that a compile error rather than a runtime undefined.
 */

/** Progress and results are pushed, not polled: a scan can run for minutes. */
export const EVENT_PROGRESS = "backslash:progress";
export const EVENT_FINDING = "backslash:finding";
export const EVENT_DONE = "backslash:done";
/** Transport log lines, batched: a long scan emits thousands and one event each would flood IPC. */
export const EVENT_SENDS = "backslash:sends";

export type ScanAggressivity = "low" | "medium" | "high";

/**
 * How much of the catalogue each aggressivity level spends.
 *
 * Declared here, in shared, and consumed by BOTH halves. The backend previously held its own copy and
 * the frontend hint text held another, so the hint said "high all 24" after the catalogue had grown
 * to 28 probes. `probes: null` means the whole catalogue, whatever its current size.
 */
export const AGGRESSIVITY_BUDGET: Record<
  ScanAggressivity,
  { readonly probes: number | null; readonly slots: number }
> = {
  low: { probes: 4, slots: 3 },
  medium: { probes: 12, slots: 8 },
  high: { probes: null, slots: 24 },
};

/** One line of the transport log, as shown in the UI. */
export interface SendLogEntry {
  readonly seq: number;
  readonly atMs: number;
  readonly label?: string;
  readonly method: string;
  readonly target: string;
  readonly outcome: "usable" | "soft-fail" | "hard-fail" | "halted";
  readonly reason?: string;
  readonly status?: number;
  readonly bodyLength?: number;
  readonly rttMs?: number;
  readonly persisted: boolean;
}

export interface SendLogBatch {
  readonly scanId: string;
  readonly entries: readonly SendLogEntry[];
  /** Total sends so far, so the UI can show how many lines it is not retaining. */
  readonly totalSends: number;
}

export interface ScanRequestInput {
  /** Caido request id to scan. */
  readonly requestId: string;
  readonly aggressivity: ScanAggressivity;
  /** Minimum milliseconds between request starts. */
  readonly delayMs: number;
  readonly maxConcurrent: number;
  /** Restrict to one slot by name. Empty means all. */
  readonly slotFilter?: string;
  /**
   * Follow redirects and measure the final response instead of the 3xx.
   *
   * Template injection frequently renders somewhere other than where it was injected: the handler
   * bounces and the evaluated payload appears on the target page. Same-origin only, always.
   */
  readonly followRedirects?: boolean;
  /** Redirect hops to follow when `followRedirects` is set. Clamped to 1..10 by the engine. */
  readonly maxRedirectHops?: number;
  /**
   * Fetch this URL after every probe and measure IT rather than the probe's own response.
   *
   * The stored / second-order case: inject at A, render at B. A bare path resolves against the
   * scanned request's origin; an absolute URL is honoured as typed. Setting this forces probe pairs to
   * run one at a time, because two pairs sharing one sink would read each other's payloads.
   */
  readonly observationUrl?: string;
}

export interface ScanProgress {
  readonly scanId: string;
  readonly phase: "enumerating" | "screening" | "attributing" | "finished" | "halted";
  readonly slotsTotal: number;
  readonly slotsDone: number;
  readonly probesTotal: number;
  readonly probesDone: number;
  readonly sends: number;
  readonly findings: number;
  /** Present once the transport stops accepting work. */
  readonly haltReason?: string;
}

export interface WitnessView {
  readonly name: string;
  readonly featureClass: string;
  readonly breakValue: string;
  readonly escapeValue: string;
}

export interface AttributionView {
  readonly witness: string;
  readonly by: string;
  readonly explains: string;
}

export interface ScanFinding {
  readonly scanId: string;
  readonly probeId: string;
  readonly probeName: string;
  readonly confidence: "firm" | "probable" | "tentative";
  readonly surface: string;
  readonly slotName: string;
  readonly breakPayload: string;
  readonly escapePayload: string;
  readonly witnesses: readonly WitnessView[];
  /** Witnesses a control arm explained away, kept so the operator sees what was ruled out. */
  readonly attributedElsewhere: readonly AttributionView[];
  readonly sends: number;
  /** Caido request id of the saved evidence re-send, when one was obtained. */
  readonly evidenceRequestId?: string;
  /**
   * Hops walked to reach the measured response, when it was not the probe's own reply.
   *
   * Absent for a normal finding. Present for a second-order one, where it is the difference between
   * "this endpoint mishandled the payload" and "the page it redirects to did".
   */
  readonly observedVia?: readonly string[];
}

/**
 * Outcomes that are not findings but must still be visible.
 *
 * Silence was the prior implementation's worst failure mode: a measurement blinded by rate limiting
 * returned "nothing found", indistinguishable from a clean result. Every non-finding outcome is
 * surfaced with its reason.
 */
export interface ScanDiagnostic {
  readonly scanId: string;
  readonly slotName: string;
  readonly probeId: string;
  readonly kind: "boring" | "inconclusive" | "veto-payload-delta" | "veto-control" | "drift";
  readonly detail: string;
}

export interface ScanResult {
  readonly scanId: string;
  readonly findings: readonly ScanFinding[];
  readonly diagnostics: readonly ScanDiagnostic[];
  readonly sends: number;
  readonly deferredSurfaces: readonly { readonly kind: string; readonly reason: string }[];
  readonly haltReason?: string;
}

export type ApiResult<T> =
  | { readonly kind: "ok"; readonly value: T }
  | { readonly kind: "error"; readonly error: string };

/**
 * Backend-to-frontend events, as CALLBACK types.
 *
 * The SDK's BackendEvents is `{[key: string]: (...args) => void}`, so each entry is the listener
 * signature rather than a payload tuple.
 *
 * Declared with `type` rather than `interface` deliberately: an interface does not get an implicit
 * index signature, so it cannot satisfy the SDK's index-signature constraint. A type alias can.
 */
export type BackslashEvents = {
  "backslash:progress": (progress: ScanProgress) => void;
  "backslash:sends": (batch: SendLogBatch) => void;
  "backslash:finding": (finding: ScanFinding) => void;
  "backslash:done": (result: ScanResult) => void;
};

/**
 * Methods the backend registers. Shared so a rename is a compile error in both halves rather than a
 * runtime undefined. Also a `type` for the index-signature reason above.
 */
export type BackslashApi = {
  startScan: (input: ScanRequestInput) => Promise<ApiResult<{ scanId: string }>>;
  cancelScan: (scanId: string) => Promise<ApiResult<null>>;
  getResult: (scanId: string) => Promise<ApiResult<ScanResult | null>>;
  listScans: () => Promise<ApiResult<readonly ScanProgress[]>>;
};
