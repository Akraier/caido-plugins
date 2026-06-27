// Active cache-confirmation: turns a passive header signal into ground truth by probing the
// resource, instead of alerting on the header alone. A 3-state machine (v0 -> resend -> control)
// sends at most two requests and short-circuits the moment the verdict is decided. A deduped,
// rate-limited, self-halting queue keeps the generated traffic bounded and controllable.
import type { Request as CaidoRequest } from "caido:utils";

import { cacheState, hitsOf, randSeg } from "./cache.js";
import { send, specFor, type EngineSDK, type Probe } from "./probe.js";
import type { CacheStatus } from "./types.js";

function sleep(ms: number): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function intervalFor(ratePerMin: number): number {
  return Math.max(0, Math.floor(60000 / Math.max(1, ratePerMin)));
}

// The passive observation that seeds the machine (read off the intercepted response, free).
export type V0 = {
  state: CacheStatus; // header-derived state WITHOUT the Age fallback (cacheState)
  age: number; // Age header value, or -1
  hits: number; // x-cache-hits counter, or -1
  status: number; // response status code
};

export type DetectedOutcome = {
  kind: "detected";
  confidence: "high" | "medium" | "low";
  keyedQuery: boolean; // did a unique query buster MISS (cache keys on the query)?
  last: Probe; // the last probe sent (control buster, or resend)
  firstMiss?: Probe; // the cold sample, when one was observed
};

export type ConfirmOutcome =
  | { kind: "dead" } // DYNAMIC / BYPASS — cannot transition on an identical resend
  | { kind: "not-cached"; last?: Probe }
  | DetectedOutcome;

// ---- the state machine -----------------------------------------------------

// v0 -> [resend] -> control. The intercepted response is v0 (free); the only active sends are
// the identical resend (skipped when v0 is already warm) and the single query-buster control.
export async function confirmByProbing(
  sdk: EngineSDK,
  base: CaidoRequest,
  v0: V0,
): Promise<ConfirmOutcome> {
  // STATE v0 — dead-negatives never get probed (an identical resend cannot move them).
  if (v0.state === "DYNAMIC" || v0.state === "BYPASS") return { kind: "dead" };

  // Already served from cache (HIT / Age / hit-counter) -> skip the resend, go straight to the
  // control. Otherwise (MISS / keyword-only) we need a resend to look for the transition.
  const warm = v0.state === "HIT" || v0.age > 0 || v0.hits > 0;
  let firstMiss: Probe | undefined;

  if (!warm) {
    // STATE resend — identical request; look for MISS -> HIT / Age++ / hits++.
    const r = await send(sdk, specFor(base, { marker: true }));
    if (!r.ok) return { kind: "not-cached" };
    firstMiss = r;
    const transitioned =
      cacheState(r.headers) === "HIT" ||
      (v0.hits >= 0 && hitsOf(r.headers) > v0.hits) ||
      (v0.age >= 0 && r.age > v0.age);
    if (!transitioned) return { kind: "not-cached", last: r };
  }

  // STATE control — a unique query buster. A clean MISS proves the cache keys on the query and
  // genuinely stored the real URL (high confidence). A HIT means the query is unkeyed or the
  // host serves a catch-all entry: still detected (we saw warmth/transition), but degraded.
  const buster = await send(
    sdk,
    specFor(base, { marker: true, appendQuery: `__cpb=${randSeg()}` }),
  );
  if (!buster.ok) {
    return { kind: "detected", confidence: "medium", keyedQuery: false, last: buster, firstMiss };
  }
  const busterCached = cacheState(buster.headers) === "HIT" || buster.age > 0;
  if (!busterCached) {
    return { kind: "detected", confidence: "high", keyedQuery: true, last: buster, firstMiss };
  }
  return {
    kind: "detected",
    confidence: warm ? "low" : "medium",
    keyedQuery: false,
    last: buster,
    firstMiss,
  };
}

// ---- bounded confirmation queue --------------------------------------------

export type ConfirmQueueOpts = {
  ratePerMin: number; // resources probed per minute (each = at most 2 requests)
  sessionMax: number; // hard ceiling on resources probed for the life of the backend
};

type Item = {
  sdk: EngineSDK;
  base: CaidoRequest;
  v0: V0;
  onDetected: (o: DetectedOutcome) => Promise<void>;
};

// Dedupes by cache-key (one probe per resource per session), spaces probes by a fixed interval,
// caps the session total, and halts on a run of rate-limit/bot responses. A single drain loop
// (no concurrency) keeps the wire calm.
export class ConfirmQueue {
  private readonly probed = new Set<string>();
  private readonly queue: Item[] = [];
  private running = false;
  private sessionCount = 0;
  private consecutiveBlocks = 0;
  private halted = false;
  private minInterval: number;
  private sessionMax: number;
  private readonly log: (m: string) => void;

  constructor(opts: ConfirmQueueOpts, log: (m: string) => void) {
    this.minInterval = intervalFor(opts.ratePerMin);
    this.sessionMax = Math.max(1, opts.sessionMax);
    this.log = log;
  }

  // Apply new rate / session ceiling live (from the settings page). A raised ceiling re-opens a
  // queue that had hit the cap; the drain loop is kicked in case work was waiting.
  updateLimits(ratePerMin: number, sessionMax: number): void {
    this.minInterval = intervalFor(ratePerMin);
    this.sessionMax = Math.max(1, sessionMax);
    void this.pump();
  }

  // Clear a throttle halt so probing can resume (e.g. after the target's rate-limit subsides).
  resume(): void {
    if (!this.halted) return;
    this.halted = false;
    this.consecutiveBlocks = 0;
    void this.pump();
  }

  stats(): { probed: number; queued: number; halted: boolean; sessionMax: number } {
    return {
      probed: this.sessionCount,
      queued: this.queue.length,
      halted: this.halted,
      sessionMax: this.sessionMax,
    };
  }

  enqueue(
    sdk: EngineSDK,
    key: string,
    base: CaidoRequest,
    v0: V0,
    onDetected: (o: DetectedOutcome) => Promise<void>,
  ): void {
    if (this.halted) return;
    if (this.probed.has(key)) return; // one probe per resource per session
    this.probed.add(key);
    this.queue.push({ sdk, base, v0, onDetected });
    void this.pump();
  }

  private async pump(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      while (this.queue.length > 0 && !this.halted) {
        if (this.sessionCount >= this.sessionMax) {
          this.log(
            `confirm budget reached (${this.sessionMax}); ${this.queue.length} candidate(s) dropped`,
          );
          this.queue.length = 0;
          break;
        }
        const item = this.queue.shift();
        if (item === undefined) break;
        this.sessionCount++;

        let outcome: ConfirmOutcome;
        try {
          outcome = await confirmByProbing(item.sdk, item.base, item.v0);
        } catch (err) {
          this.log(`confirm probe failed: ${String(err)}`);
          continue;
        }

        // Throttle watchdog — halt on a run of 429/503 instead of hammering a limiter.
        const last = "last" in outcome ? outcome.last : undefined;
        const st = last?.status ?? 0;
        if (st === 429 || st === 503) {
          this.consecutiveBlocks++;
          if (this.consecutiveBlocks >= 3) {
            this.halted = true;
            this.log(
              `confirmation halted: ${this.consecutiveBlocks} consecutive ${st} responses (rate-limit/bot). Reload the plugin to resume.`,
            );
            this.queue.length = 0;
            break;
          }
        } else {
          this.consecutiveBlocks = 0;
        }

        if (outcome.kind === "detected") {
          try {
            await item.onDetected(outcome);
          } catch (err) {
            this.log(`confirm emit failed: ${String(err)}`);
          }
        }

        if (this.minInterval > 0 && this.queue.length > 0) {
          await sleep(this.minInterval);
        }
      }
    } finally {
      this.running = false;
    }
  }
}
