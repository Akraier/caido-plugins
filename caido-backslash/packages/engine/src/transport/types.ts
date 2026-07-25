/**
 * The host boundary.
 *
 * Everything in this package is defined against these types and nothing else. There are no
 * Caido imports anywhere in the engine, which is what makes the detection logic testable
 * offline against recorded fixtures with injected randomness and time.
 *
 * The critical design constraint: `send` returns a typed result and NEVER throws for a
 * transport failure. A dropped connection or a timeout is a first-class outcome, because a
 * firewall that consistently kills the break payload while letting the escape payload through
 * would otherwise look exactly like a confident finding. The original Java implementation fed
 * null responses straight into feature computation and reported precisely that as an issue.
 * Typing the failure is what turns the technique's largest false-positive source into a
 * correctly classified non-signal.
 */

/**
 * A request to send, as bytes.
 *
 * `raw` is the complete request line, headers and body, byte-exact and already carrying any
 * Content-Length the caller intends. The engine builds these itself by splicing a payload into
 * a recorded request at a byte offset, so no layer between here and the socket may re-encode,
 * normalise, or "fix" anything. Hostile payloads such as a lone backslash, an unbalanced
 * quote, a NUL byte or a bare CR are the entire point of the technique.
 */
export interface EngineRequest {
  readonly host: string;
  readonly port: number;
  readonly tls: boolean;
  readonly raw: Uint8Array;
}

export interface EngineResponse {
  readonly status: number;
  /**
   * Header names lowercased. Values are kept as a list because duplicate headers are
   * themselves signal, and joining them would lose that.
   */
  readonly headers: ReadonlyMap<string, readonly string[]>;
  /** The complete raw response including status line and headers. */
  readonly raw: Uint8Array;
  /** Offset of the first body byte within `raw`. */
  readonly bodyStart: number;
  /**
   * Whole-roundtrip duration in integer milliseconds, including connection setup.
   *
   * This is all Caido exposes: there is no time-to-first-byte, connect or TLS breakdown.
   * Timing is therefore usable only as a coarse distribution, never as a precise oracle,
   * and comparisons must be robust to connection-setup noise on the first request to a host.
   */
  readonly roundtripMs: number;
  /**
   * Host-assigned identifier for the sent request, when the host persisted it. Undefined for
   * unsaved traffic. A finding can only cite a request the host actually stored.
   */
  readonly requestId?: string;
}

/** Why a request produced no response at all. */
export type TransportFailure =
  | "timeout"
  | "connection-reset"
  | "connection-refused"
  | "dns"
  | "tls"
  | "aborted"
  | "unknown";

export type SendOutcome =
  | { readonly kind: "ok"; readonly response: EngineResponse }
  | {
      readonly kind: "failed";
      readonly failure: TransportFailure;
      /** Host-supplied message, retained verbatim for the evidence record. */
      readonly detail?: string;
    };

export interface SendOptions {
  /** Abort in-flight work. Hosts must map this onto their own cancellation. */
  readonly signal?: AbortSignal;
  /** Per-request ceiling in milliseconds. */
  readonly timeoutMs?: number;
  /**
   * Whether the host should persist this request so a finding can cite it.
   *
   * Probe traffic is high volume and is normally sent unsaved. Only the pair that a confirmed
   * finding rests on is re-sent with `persist` set, which both keeps the project database
   * clean and guarantees the evidence attached to a finding is the exact exchange the claim
   * was computed from.
   */
  readonly persist?: boolean;
}

/**
 * The entire transport surface. One method.
 *
 * Implemented by the Caido backend adapter and by the Node fixture harness. Adding anything
 * here couples the engine to a host capability, so additions require the same scrutiny as a
 * change to the detection algorithm.
 */
export interface RequestProvider {
  send(request: EngineRequest, options?: SendOptions): Promise<SendOutcome>;
}

/** Injected so schedules are deterministic under test. */
export type SleepFn = (ms: number, signal?: AbortSignal) => Promise<void>;

/** Injected so probe ordering and canary generation are reproducible under test. */
export type RandomSource = () => number;

/** Injected so timing-derived features and backoff windows are deterministic under test. */
export type NowFn = () => number;

export type LogLevel = "debug" | "info" | "warn" | "error";
export type LoggerFn = (level: LogLevel, message: string) => void;

export interface EngineDeps {
  readonly provider: RequestProvider;
  readonly sleep: SleepFn;
  readonly random: RandomSource;
  readonly now: NowFn;
  readonly log: LoggerFn;
}

/** Read a single header value, case-insensitively, taking the first if repeated. */
export function header(
  response: EngineResponse,
  name: string,
): string | undefined {
  return response.headers.get(name.toLowerCase())?.[0];
}
