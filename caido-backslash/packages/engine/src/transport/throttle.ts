/**
 * Adaptive throttling and halt-on-blinded supervision.
 *
 * This is the capability whose absence decided against living inside the community scanner
 * plugin: that engine's only throttle is a fixed inter-request gap, with no rate-limit sensing
 * anywhere (verified by grep: zero occurrences of 429, Retry-After, or backoff).
 *
 * Two responsibilities, and the second is the important one:
 *
 * 1. Pace requests. Bounded concurrency, a minimum gap between starts, and an optional
 *    requests-per-second ceiling, with exponential backoff when the target pushes back.
 *
 * 2. Refuse to keep measuring a target that has stopped answering honestly. Once the recent
 *    window is mostly unusable responses, continuing produces a confident-looking negative
 *    result derived from firewall pages. The engine halts and says so. A negative result and a
 *    blinded measurement must never be reported as the same thing, because the operator cannot
 *    tell them apart from the outside.
 *
 * All time and sleeping is injected, so the whole policy is deterministic under test.
 */

import {
  type Admission,
  type AdmissionOptions,
  type AdmissionTally,
  admit,
  newTally,
  record,
} from "./admission.ts";
import type {
  EngineRequest,
  NowFn,
  RequestProvider,
  SendOptions,
  SleepFn,
} from "./types.ts";

export interface ThrottleConfig {
  /** Maximum requests in flight at once. */
  readonly maxConcurrent: number;
  /** Minimum milliseconds between the start of one request and the next. */
  readonly minDelayMs: number;
  /** Optional ceiling on request starts per rolling second. */
  readonly maxRequestsPerSecond?: number;

  /** First backoff step after a soft failure. */
  readonly backoffBaseMs: number;
  /** Ceiling for a single backoff step. */
  readonly backoffMaxMs: number;
  /** Multiplier applied per consecutive soft failure. */
  readonly backoffFactor: number;

  /** How many recent outcomes the halt decision considers. */
  readonly haltWindow: number;
  /** Fraction of unusable outcomes in the window that triggers a halt. */
  readonly haltUnusableRate: number;
  /** Minimum observations before a halt may be declared, so a bad start is not fatal. */
  readonly haltMinObservations: number;
  /**
   * A server-requested delay above this aborts instead of sleeping. A target asking for five
   * minutes is telling you to come back another day, not to block the event loop.
   */
  readonly abortAboveRetryAfterMs: number;
}

export const DEFAULT_THROTTLE: ThrottleConfig = {
  maxConcurrent: 4,
  minDelayMs: 0,
  backoffBaseMs: 500,
  backoffMaxMs: 30_000,
  backoffFactor: 2,
  haltWindow: 20,
  haltUnusableRate: 0.5,
  haltMinObservations: 8,
  abortAboveRetryAfterMs: 60_000,
};

export type HaltReason =
  | { readonly kind: "unusable-rate"; readonly rate: number; readonly window: number }
  | { readonly kind: "retry-after-too-long"; readonly requestedMs: number }
  | { readonly kind: "cancelled" };

export type ThrottleState = "running" | "backing-off" | "halted";

/** Returned instead of an Admission once the transport has stopped. */
export interface Halted {
  readonly kind: "halted";
  readonly reason: HaltReason;
}

export type ProbeResult = Admission | Halted;

export function isHalted(result: ProbeResult): result is Halted {
  return result.kind === "halted";
}

export interface ProbeTransportStats {
  readonly state: ThrottleState;
  readonly sent: number;
  readonly consecutiveSoftFails: number;
  readonly currentBackoffMs: number;
  readonly tally: AdmissionTally;
  readonly haltReason?: HaltReason;
}

export interface ProbeTransport {
  /**
   * Send one probe and classify it. Never throws for a transport failure; a hostile or
   * unavailable target surfaces as a soft-fail, a hard-fail, or a halt.
   */
  send(request: EngineRequest, options?: SendOptions): Promise<ProbeResult>;
  stats(): ProbeTransportStats;
  /** Stop accepting work. Idempotent. */
  halt(reason: HaltReason): void;
}

export interface ProbeTransportDeps {
  readonly provider: RequestProvider;
  readonly sleep: SleepFn;
  readonly now: NowFn;
}

export function createProbeTransport(
  deps: ProbeTransportDeps,
  config: ThrottleConfig = DEFAULT_THROTTLE,
  admissionOptions: () => AdmissionOptions = () => ({}),
): ProbeTransport {
  const { provider, sleep, now } = deps;

  let state: ThrottleState = "running";
  let haltReason: HaltReason | undefined;
  let sent = 0;
  let consecutiveSoftFails = 0;
  let lastStart = Number.NEGATIVE_INFINITY;
  const tally = newTally();

  // Read state through a function rather than the variable directly. TypeScript narrows a
  // captured `let` inside a closure and then keeps that narrowing across an await, which makes
  // later comparisons against "halted" look unreachable even though another closure can set it.
  const currentState = (): ThrottleState => state;

  /** Rolling record of whether each recent outcome was usable. Drives the halt decision. */
  const recentOutcomes: boolean[] = [];
  /** Start timestamps within the last second, for the requests-per-second ceiling. */
  let recentStarts: number[] = [];
  /** Serialises the gap/rate wait so concurrent callers cannot all pass the same check. */
  let gate: Promise<void> = Promise.resolve();
  /**
   * Earliest timestamp at which the next request may start.
   *
   * Backoff is expressed as a deadline rather than an inline sleep at the failure site. An
   * earlier version slept immediately and reset the failure counter, which meant consecutive
   * failures never escalated past the first step: every one of them waited the base delay.
   */
  let nextAllowedAt = Number.NEGATIVE_INFINITY;

  function doHalt(reason: HaltReason): void {
    if (state === "halted") return;
    state = "halted";
    haltReason = reason;
  }

  function noteOutcome(usable: boolean): void {
    recentOutcomes.push(usable);
    if (recentOutcomes.length > config.haltWindow) recentOutcomes.shift();

    if (recentOutcomes.length < config.haltMinObservations) return;
    const unusable = recentOutcomes.reduce((n, ok) => (ok ? n : n + 1), 0);
    const rate = unusable / recentOutcomes.length;
    if (rate >= config.haltUnusableRate) {
      doHalt({ kind: "unusable-rate", rate, window: recentOutcomes.length });
    }
  }

  function backoffFor(attempt: number): number {
    if (attempt <= 0) return 0;
    const raw = config.backoffBaseMs * Math.pow(config.backoffFactor, attempt - 1);
    return Math.min(config.backoffMaxMs, raw);
  }

  /**
   * Wait until this request is allowed to start. Serialised through `gate` so that N concurrent
   * callers queue behind one another rather than each independently observing a stale
   * `lastStart` and all firing at once.
   */
  async function waitForSlot(signal: AbortSignal | undefined): Promise<void> {
    const mine = gate.then(async () => {
      for (;;) {
        const at = now();

        const sinceLast = at - lastStart;
        if (config.minDelayMs > 0 && sinceLast < config.minDelayMs) {
          await sleep(config.minDelayMs - sinceLast, signal);
          continue;
        }

        const rps = config.maxRequestsPerSecond;
        if (rps !== undefined && rps > 0) {
          recentStarts = recentStarts.filter((t) => at - t < 1000);
          if (recentStarts.length >= rps) {
            const oldest = recentStarts[0]!;
            await sleep(Math.max(1, 1000 - (at - oldest)), signal);
            continue;
          }
        }

        if (at < nextAllowedAt) {
          if (currentState() !== "halted") state = "backing-off";
          await sleep(nextAllowedAt - at, signal);
          if (currentState() === "backing-off") state = "running";
          continue;
        }

        lastStart = now();
        recentStarts.push(lastStart);
        return;
      }
    });
    gate = mine.catch(() => undefined);
    await mine;
  }

  // A counting semaphore with an explicit waiter queue.
  //
  // The obvious implementation, spinning on `while (inFlight >= max) await sleep(1)`, is wrong:
  // the check and the increment are separated by an await, so every concurrent caller observes
  // inFlight === 0 and passes the gate before any of them reserves a slot. Reserving inside
  // acquire with no await between the test and the increment is what makes it correct on a
  // single-threaded runtime. It also avoids consuming the injected clock, keeping tests exact.
  let inFlight = 0;
  const waiters: (() => void)[] = [];

  async function acquireSlot(): Promise<void> {
    if (inFlight < config.maxConcurrent) {
      inFlight += 1;
      return;
    }
    await new Promise<void>((resolve) => waiters.push(resolve));
    inFlight += 1;
  }

  function releaseSlot(): void {
    inFlight -= 1;
    waiters.shift()?.();
  }

  return {
    async send(request, options): Promise<ProbeResult> {
      if (currentState() === "halted") {
        return { kind: "halted", reason: haltReason ?? { kind: "cancelled" } };
      }
      if (options?.signal?.aborted === true) {
        doHalt({ kind: "cancelled" });
        return { kind: "halted", reason: { kind: "cancelled" } };
      }

      // The concurrency slot is held across the pacing wait as well as the request itself, so
      // that a backoff genuinely quiets the target instead of letting queued callers through.
      await acquireSlot();
      let admission: Admission;
      try {
        await waitForSlot(options?.signal);

        if (currentState() === "halted") {
          return { kind: "halted", reason: haltReason ?? { kind: "cancelled" } };
        }

        const outcome = await provider.send(request, options);
        sent += 1;
        admission = admit(outcome, admissionOptions(), now());
      } finally {
        releaseSlot();
      }

      record(tally, admission);

      if (admission.kind === "usable") {
        consecutiveSoftFails = 0;
        noteOutcome(true);
        return admission;
      }

      if (admission.kind === "soft-fail") {
        const requested = admission.retryAfterMs;
        if (requested !== undefined && requested > config.abortAboveRetryAfterMs) {
          doHalt({ kind: "retry-after-too-long", requestedMs: requested });
          return { kind: "halted", reason: haltReason! };
        }
        consecutiveSoftFails += 1;
        // A server-supplied delay overrides our own schedule when it is longer, since the
        // server is authoritative about when it will answer again.
        const delay = Math.max(backoffFor(consecutiveSoftFails), requested ?? 0);
        nextAllowedAt = now() + delay;
      } else {
        // Hard failures also warrant slowing down: a target dropping connections is not a
        // target to hammer. They count toward the halt window identically.
        consecutiveSoftFails += 1;
        nextAllowedAt = now() + backoffFor(consecutiveSoftFails);
      }

      noteOutcome(false);
      if (state === "halted") {
        return { kind: "halted", reason: haltReason! };
      }
      return admission;
    },

    stats(): ProbeTransportStats {
      const base = {
        state,
        sent,
        consecutiveSoftFails,
        currentBackoffMs: backoffFor(consecutiveSoftFails),
        tally,
      };
      return haltReason === undefined ? base : { ...base, haltReason };
    },

    halt(reason: HaltReason): void {
      doHalt(reason);
    },
  };
}
