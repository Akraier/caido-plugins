import { describe, expect, it } from "vitest";

import {
  DEFAULT_THROTTLE,
  type ThrottleConfig,
  createProbeTransport,
  isHalted,
} from "../src/transport/throttle.ts";
import { findBodyStart } from "../src/response/scan.ts";
import type {
  EngineRequest,
  EngineResponse,
  SendOutcome,
  TransportFailure,
} from "../src/transport/types.ts";

function ascii(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

function res(status: number, headers: Record<string, string> = {}, body = "ok"): EngineResponse {
  const headerLines = Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\r\n");
  const raw = ascii(
    `HTTP/1.1 ${status} X\r\n${headerLines}${headerLines === "" ? "" : "\r\n"}\r\n${body}`,
  );
  return {
    status,
    headers: new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), [v]])),
    raw,
    bodyStart: findBodyStart(raw),
    roundtripMs: 10,
  };
}

const okOutcome = (): SendOutcome => ({ kind: "ok", response: res(200) });
const rateLimited = (retryAfter?: string): SendOutcome => ({
  kind: "ok",
  response: retryAfter === undefined ? res(429) : res(429, { "Retry-After": retryAfter }),
});
const failed = (failure: TransportFailure): SendOutcome => ({ kind: "failed", failure });

const REQUEST: EngineRequest = {
  host: "example.test",
  port: 443,
  tls: true,
  raw: ascii("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
};

/**
 * A virtual clock. `sleep` advances time instantly and yields to the microtask queue, so
 * pacing policy is asserted exactly rather than by waiting on wall-clock time.
 */
function fakeClock() {
  let t = 0;
  return {
    now: () => t,
    sleep: async (ms: number): Promise<void> => {
      t += ms;
      await Promise.resolve();
    },
    advance: (ms: number) => {
      t += ms;
    },
  };
}

/** A provider that returns scripted outcomes and records when each send happened. */
function scriptedProvider(outcomes: SendOutcome[], now: () => number) {
  const startedAt: number[] = [];
  let index = 0;
  return {
    startedAt,
    calls: () => index,
    provider: {
      send: async (): Promise<SendOutcome> => {
        startedAt.push(now());
        const outcome = outcomes[Math.min(index, outcomes.length - 1)]!;
        index += 1;
        await Promise.resolve();
        return outcome;
      },
    },
  };
}

function config(overrides: Partial<ThrottleConfig> = {}): ThrottleConfig {
  return { ...DEFAULT_THROTTLE, ...overrides };
}

describe("pacing", () => {
  it("enforces a minimum gap between request starts", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([okOutcome()], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({ minDelayMs: 100 }),
    );

    for (let i = 0; i < 3; i++) await transport.send(REQUEST);
    expect(script.startedAt).toEqual([0, 100, 200]);
  });

  it("applies no gap when minDelayMs is zero", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([okOutcome()], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({ minDelayMs: 0 }),
    );

    for (let i = 0; i < 3; i++) await transport.send(REQUEST);
    expect(script.startedAt).toEqual([0, 0, 0]);
  });

  it("enforces a requests-per-second ceiling", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([okOutcome()], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({ minDelayMs: 0, maxRequestsPerSecond: 2 }),
    );

    for (let i = 0; i < 5; i++) await transport.send(REQUEST);
    // Two per rolling second: the third waits out the window, and so on.
    expect(script.startedAt).toEqual([0, 0, 1000, 1000, 2000]);
  });

  it("bounds concurrency", async () => {
    const clock = fakeClock();
    let inFlight = 0;
    let peak = 0;
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });

    const provider = {
      send: async (): Promise<SendOutcome> => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        await gate;
        inFlight -= 1;
        return okOutcome();
      },
    };

    const transport = createProbeTransport(
      { provider, sleep: clock.sleep, now: clock.now },
      config({ maxConcurrent: 2, minDelayMs: 0 }),
    );

    const sends = [0, 1, 2, 3, 4].map(() => transport.send(REQUEST));
    // Let the transport admit as many as it will before anything completes.
    for (let i = 0; i < 50; i++) await Promise.resolve();
    expect(peak).toBeLessThanOrEqual(2);

    release!();
    await Promise.all(sends);
    expect(peak).toBeLessThanOrEqual(2);
  });
});

describe("adaptive backoff", () => {
  it("escalates exponentially across consecutive soft failures", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([rateLimited()], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({
        minDelayMs: 0,
        backoffBaseMs: 500,
        backoffFactor: 2,
        backoffMaxMs: 30_000,
        // Keep the halt out of the way so escalation is observable.
        haltMinObservations: 100,
      }),
    );

    for (let i = 0; i < 5; i++) await transport.send(REQUEST);
    // Gaps: 500, 1000, 2000, 4000 -> cumulative starts.
    expect(script.startedAt).toEqual([0, 500, 1500, 3500, 7500]);
  });

  it("caps a single backoff step", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([rateLimited()], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({
        minDelayMs: 0,
        backoffBaseMs: 1000,
        backoffFactor: 10,
        backoffMaxMs: 2000,
        haltMinObservations: 100,
      }),
    );

    for (let i = 0; i < 4; i++) await transport.send(REQUEST);
    // 1000, then capped at 2000 thereafter.
    expect(script.startedAt).toEqual([0, 1000, 3000, 5000]);
  });

  it("resets the escalation after a usable response", async () => {
    const clock = fakeClock();
    const script = scriptedProvider(
      [rateLimited(), rateLimited(), okOutcome(), rateLimited(), okOutcome()],
      clock.now,
    );
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({ minDelayMs: 0, backoffBaseMs: 100, backoffFactor: 2, haltMinObservations: 100 }),
    );

    for (let i = 0; i < 5; i++) await transport.send(REQUEST);
    // 0, +100 (1st fail), +200 (2nd fail), then ok resets, so the 4th fail costs 100 again.
    expect(script.startedAt).toEqual([0, 100, 300, 300, 400]);
    expect(transport.stats().consecutiveSoftFails).toBe(0);
  });

  it("honours a Retry-After longer than the computed backoff", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([rateLimited("5"), okOutcome()], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({ minDelayMs: 0, backoffBaseMs: 100, haltMinObservations: 100 }),
    );

    await transport.send(REQUEST);
    await transport.send(REQUEST);
    expect(script.startedAt).toEqual([0, 5000]);
  });

  it("ignores a Retry-After shorter than the computed backoff", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([rateLimited("1"), okOutcome()], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({ minDelayMs: 0, backoffBaseMs: 8000, haltMinObservations: 100 }),
    );

    await transport.send(REQUEST);
    await transport.send(REQUEST);
    expect(script.startedAt).toEqual([0, 8000]);
  });

  it("backs off on hard failures too", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([failed("connection-reset")], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({ minDelayMs: 0, backoffBaseMs: 200, backoffFactor: 2, haltMinObservations: 100 }),
    );

    for (let i = 0; i < 3; i++) await transport.send(REQUEST);
    expect(script.startedAt).toEqual([0, 200, 600]);
  });
});

describe("halting rather than reporting a blinded measurement as a negative", () => {
  it("halts once the recent window is mostly unusable", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([rateLimited()], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({ minDelayMs: 0, haltWindow: 10, haltUnusableRate: 0.5, haltMinObservations: 4 }),
    );

    const results = [];
    for (let i = 0; i < 6; i++) results.push(await transport.send(REQUEST));

    expect(results.slice(0, 3).every((r) => !isHalted(r))).toBe(true);
    expect(isHalted(results[results.length - 1]!)).toBe(true);
    const stats = transport.stats();
    expect(stats.state).toBe("halted");
    expect(stats.haltReason).toMatchObject({ kind: "unusable-rate" });
  });

  it("does not halt before the minimum observation count", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([rateLimited()], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({ minDelayMs: 0, haltMinObservations: 8, haltUnusableRate: 0.5 }),
    );

    // A bad start must not be fatal: three consecutive rate limits on a slow target are
    // recoverable and halting there would abandon scans that would have succeeded.
    for (let i = 0; i < 3; i++) {
      expect(isHalted(await transport.send(REQUEST))).toBe(false);
    }
    expect(transport.stats().state).not.toBe("halted");
  });

  it("does not halt a target that is merely slow but answering", async () => {
    const clock = fakeClock();
    // One soft failure in five is normal on a busy target and must not stop the scan.
    const script = scriptedProvider(
      [okOutcome(), okOutcome(), rateLimited(), okOutcome(), okOutcome(), okOutcome()],
      clock.now,
    );
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({ minDelayMs: 0, haltMinObservations: 4, haltUnusableRate: 0.5 }),
    );

    for (let i = 0; i < 6; i++) {
      expect(isHalted(await transport.send(REQUEST))).toBe(false);
    }
    expect(transport.stats().state).toBe("running");
  });

  it("halts immediately on an unreasonable Retry-After instead of sleeping", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([rateLimited("3600")], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({ minDelayMs: 0, abortAboveRetryAfterMs: 60_000 }),
    );

    const result = await transport.send(REQUEST);
    expect(isHalted(result)).toBe(true);
    if (isHalted(result)) {
      expect(result.reason).toMatchObject({ kind: "retry-after-too-long" });
    }
    // Crucially, the clock did not advance by an hour.
    expect(clock.now()).toBe(0);
  });

  it("stops calling the provider once halted", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([rateLimited()], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({ minDelayMs: 0, haltMinObservations: 2, haltUnusableRate: 0.5 }),
    );

    for (let i = 0; i < 3; i++) await transport.send(REQUEST);
    const callsAtHalt = script.calls();
    for (let i = 0; i < 5; i++) {
      expect(isHalted(await transport.send(REQUEST))).toBe(true);
    }
    expect(script.calls()).toBe(callsAtHalt);
  });

  it("can be halted explicitly and is idempotent", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([okOutcome()], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config(),
    );

    transport.halt({ kind: "cancelled" });
    transport.halt({ kind: "unusable-rate", rate: 1, window: 10 });
    // First halt wins, so the reported reason is not overwritten by a later call.
    expect(transport.stats().haltReason).toMatchObject({ kind: "cancelled" });
    expect(isHalted(await transport.send(REQUEST))).toBe(true);
    expect(script.calls()).toBe(0);
  });

  it("halts on an already-aborted signal without sending", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([okOutcome()], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config(),
    );

    const controller = new AbortController();
    controller.abort();
    const result = await transport.send(REQUEST, { signal: controller.signal });
    expect(isHalted(result)).toBe(true);
    expect(script.calls()).toBe(0);
  });
});

describe("statistics", () => {
  it("tallies outcomes by reason so a blinded run is explainable", async () => {
    const clock = fakeClock();
    const script = scriptedProvider(
      [okOutcome(), rateLimited(), failed("timeout"), okOutcome()],
      clock.now,
    );
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config({ minDelayMs: 0, haltMinObservations: 100 }),
    );

    for (let i = 0; i < 4; i++) await transport.send(REQUEST);
    const stats = transport.stats();
    expect(stats.sent).toBe(4);
    expect(stats.tally.usable).toBe(2);
    expect(stats.tally.softFail).toBe(1);
    expect(stats.tally.hardFail).toBe(1);
    expect(stats.tally.reasons.get("rate-limited")).toBe(1);
    expect(stats.tally.reasons.get("timeout")).toBe(1);
  });

  it("passes usable responses through unchanged", async () => {
    const clock = fakeClock();
    const script = scriptedProvider([okOutcome()], clock.now);
    const transport = createProbeTransport(
      { provider: script.provider, sleep: clock.sleep, now: clock.now },
      config(),
    );

    const result = await transport.send(REQUEST);
    expect(result.kind).toBe("usable");
    if (result.kind === "usable") expect(result.response.status).toBe(200);
  });
});
