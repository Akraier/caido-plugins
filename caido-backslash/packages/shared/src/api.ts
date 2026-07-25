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
