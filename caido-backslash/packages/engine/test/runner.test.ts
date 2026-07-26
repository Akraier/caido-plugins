import { describe, expect, it } from "vitest";

import { runSuite, type SuiteSummary } from "../src/detect/runner.ts";
import { ALL_STATIC_PROBES, DELIMITER_PROBES } from "../src/probes/catalogue.ts";
import { enumerateSlots } from "../src/request/slots.ts";
import { asciiBytes, locate } from "../src/request/template.ts";
import { findBodyStart } from "../src/response/scan.ts";
import { DEFAULT_THROTTLE, createProbeTransport } from "../src/transport/throttle.ts";
import type { SendOutcome } from "../src/transport/types.ts";

const REQUEST = [
  "GET /search?q=widget&page=2 HTTP/1.1",
  "Host: shop.test",
  "Accept: text/html",
  "",
  "",
].join("\r\n");

function respond(status: number, body: string): SendOutcome {
  const raw = asciiBytes(
    `HTTP/1.1 ${status} X\r\nContent-Type: text/html\r\nContent-Length: ${body.length}\r\n\r\n${body}`,
  );
  return {
    kind: "ok",
    response: {
      status,
      headers: new Map([["content-type", ["text/html"]]]),
      raw,
      bodyStart: findBodyStart(raw),
      roundtripMs: 12,
    },
  };
}

/** A suite over a fixed target, with an injected clock and coin so runs are reproducible. */
function harness(
  target: () => SendOutcome,
  options: {
    cancelAfterSends?: number;
    haltMinObservations?: number;
    probes?: typeof DELIMITER_PROBES;
  } = {},
) {
  const template = locate(asciiBytes(REQUEST));
  const slots = enumerateSlots(template).slots.filter((s) => s.kind === "query-value");
  expect(slots.length).toBeGreaterThan(1);

  let time = 0;
  let seed = 7;
  let sends = 0;
  const sendLog: string[] = [];

  const transport = createProbeTransport(
    {
      provider: {
        send: async () => {
          sends += 1;
          await Promise.resolve();
          return target();
        },
      },
      sleep: async (ms: number) => {
        time += ms;
        await Promise.resolve();
      },
      now: () => time,
      onSend: (record) => sendLog.push(`${record.label ?? "-"} ${record.outcome}`),
    },
    {
      ...DEFAULT_THROTTLE,
      minDelayMs: 0,
      // Halting is off by default here so it cannot perturb the cancellation cases; the halt test
      // opts back in.
      haltMinObservations: options.haltMinObservations ?? 1000,
    },
  );

  return {
    slots,
    template,
    sendLog,
    sentCount: () => sends,
    run: () =>
      runSuite({
        template,
        slots,
        probes: options.probes ?? DELIMITER_PROBES,
        target: { host: "shop.test", port: 443, tls: true },
        transport,
        random: () => {
          seed ^= seed << 13;
          seed ^= seed >>> 17;
          seed ^= seed << 5;
          seed >>>= 0;
          return seed / 0xffffffff;
        },
        cancelled: () =>
          options.cancelAfterSends !== undefined && sends >= options.cancelAfterSends,
      }),
  };
}

describe("suite termination", () => {
  it("runs every slot and probe when not cancelled", async () => {
    const h = harness(() => respond(200, "<html><body>static</body></html>"));
    const summary = await h.run();
    // Nothing interesting, so every pair is boring at S0: two sends each.
    const expectedPairs = h.slots.length * DELIMITER_PROBES.length;
    expect(summary.diagnostics.filter((d) => d.kind === "boring")).toHaveLength(expectedPairs);
    expect(summary.haltReason).toBeUndefined();
  });

  it("stops the WHOLE suite when cancelled, not just the current slot", async () => {
    // The regression this guards: an unlabelled break exited only the inner probe loop, so the outer
    // slot loop re-entered and the run continued to completion. Traffic stopped because the halted
    // transport short-circuits sends, but the suite churned through every remaining probe.
    const h = harness(() => respond(200, "<html><body>static</body></html>"), {
      cancelAfterSends: 3,
    });
    const summary = await h.run();

    const fullRun = h.slots.length * DELIMITER_PROBES.length;
    const attempted = summary.diagnostics.filter((d) => d.probeId !== "-").length;
    expect(attempted).toBeLessThan(fullRun);
    expect(summary.haltReason).toBe("cancelled");
  });

  it("records exactly one diagnostic for the stop, naming what was not run", async () => {
    const h = harness(() => respond(200, "<html><body>static</body></html>"), {
      cancelAfterSends: 3,
    });
    const summary = await h.run();

    const stopNotes = summary.diagnostics.filter((d) => d.probeId === "-");
    expect(stopNotes).toHaveLength(1);
    expect(stopNotes[0]!.detail).toMatch(/stopped by the operator with \d+ probe\(s\) not run/);
  });

  it("does not keep sending after the cancel is observed", async () => {
    const h = harness(() => respond(200, "<html><body>static</body></html>"), {
      cancelAfterSends: 3,
    });
    await h.run();
    // A probe pair in flight may finish, but nothing beyond that: no full second slot's worth.
    expect(h.sentCount()).toBeLessThan(8);
  });

  it("labels every send with its probe and arm, so the log is attributable", async () => {
    const h = harness(() => respond(200, "<html><body>static</body></html>"), {
      cancelAfterSends: 4,
    });
    await h.run();
    expect(h.sendLog.length).toBeGreaterThan(0);
    for (const line of h.sendLog) {
      expect(line).toMatch(/^delim\.[a-z-]+:(break|escape) /);
    }
  });

  it("reports a transport halt distinctly from an operator stop", async () => {
    // A target that refuses everything trips the halt supervisor rather than being cancelled.
    let n = 0;
    const h = harness(
      () => {
        n += 1;
        const raw = asciiBytes("HTTP/1.1 429 X\r\nContent-Length: 4\r\n\r\nslow");
        return {
          kind: "ok",
          response: {
            status: 429,
            headers: new Map<string, string[]>(),
            raw,
            bodyStart: findBodyStart(raw),
            roundtripMs: n,
          },
        };
      },
      { haltMinObservations: 4 },
    );
    const summary = await h.run();
    expect(summary.haltReason).toBe("unusable-rate");
    const stopNotes = summary.diagnostics.filter((d) => d.probeId === "-");
    expect(stopNotes).toHaveLength(1);
    expect(stopNotes[0]!.detail).toMatch(/transport halted/);
  });
});


describe("ERB and EJS template injection", () => {
  it("ships a probe for the ERB and EJS delimiter family", () => {
    // Regression: the catalogue had no <% %> probe at all, so plain ERB injection was invisible.
    const probe = ALL_STATIC_PROBES.find((p) => p.id === "interp.erb")!;
    expect(probe).toBeDefined();
    expect(probe.wireForm).toBe("literal-raw-percent");
  });

  it("declares the ERB probes with a raw percent, or the delimiters never arrive", () => {
    // With % encoded, "<%z" leaves as "<%25z" and "z%>" as "z%25>": the syntax under test is gone.
    for (const id of ["interp.erb", "interp.erb-eval", "interp.percent"]) {
      const probe = ALL_STATIC_PROBES.find((p) => p.id === id)!;
      expect(probe.wireForm, id).toBe("literal-raw-percent");
    }
  });

  it("keeps the ERB evaluation arms the same length", () => {
    const probe = ALL_STATIC_PROBES.find((p) => p.id === "interp.erb-eval")!;
    const lengths = new Set([...probe.breaks, ...probe.escapeSets.flat()].map((p) => p.length));
    expect([...lengths]).toEqual([10]);
    expect(probe.parity).toBe("equal");
  });
});

describe("pair concurrency", () => {
  /** Records how many provider calls were in flight simultaneously. */
  function overlapHarness(width: number) {
    const template = locate(asciiBytes(REQUEST));
    const slots = enumerateSlots(template).slots.filter((s) => s.kind === "query-value");
    let inFlight = 0;
    let peak = 0;
    let time = 0;

    const transport = createProbeTransport(
      {
        provider: {
          send: async () => {
            inFlight += 1;
            peak = Math.max(peak, inFlight);
            // A macrotask, not a microtask: every worker must be able to reach its own send before
            // the first one resolves, otherwise the harness measures its own setup latency rather
            // than the suite's concurrency.
            await new Promise<void>((resolve) => setTimeout(resolve, 0));
            inFlight -= 1;
            return respond(200, "<html><body>static</body></html>");
          },
        },
        sleep: async (ms: number) => {
          time += ms;
          await Promise.resolve();
        },
        now: () => time,
      },
      { ...DEFAULT_THROTTLE, minDelayMs: 0, maxConcurrent: 8, haltMinObservations: 1000 },
    );

    return {
      peak: () => peak,
      run: () =>
        runSuite({
          template,
          slots,
          probes: DELIMITER_PROBES,
          target: { host: "shop.test", port: 443, tls: true },
          transport,
          random: () => 0.5,
          pairConcurrency: width,
        }),
    };
  }

  it("sends one request at a time when concurrency is one", async () => {
    const h = overlapHarness(1);
    await h.run();
    expect(h.peak()).toBe(1);
  });

  it("overlaps independent pairs when concurrency is raised", async () => {
    // The bug this guards: the suite loop was a plain nested await, so only ever one request was in
    // flight and the transport's concurrency cap did nothing. Throughput was pinned at
    // 1/(latency + gap), which is why only the delay knob appeared to matter.
    const h = overlapHarness(4);
    await h.run();
    expect(h.peak()).toBeGreaterThan(1);
  });

  it("produces identical results at any concurrency, given the same seed", async () => {
    // Concurrency must not change what is found. Each pair draws from its own derived stream, so the
    // interleaving cannot perturb any individual measurement.
    const results: SuiteSummary[] = [];
    for (const width of [1, 3, 5]) {
      const template = locate(asciiBytes(REQUEST));
      const slots = enumerateSlots(template).slots.filter((s) => s.kind === "query-value");
      let time = 0;
      const transport = createProbeTransport(
        {
          provider: {
            send: async () => {
              await Promise.resolve();
              return respond(200, "<html><body>static</body></html>");
            },
          },
          sleep: async (ms: number) => {
            time += ms;
            await Promise.resolve();
          },
          now: () => time,
        },
        { ...DEFAULT_THROTTLE, minDelayMs: 0, haltMinObservations: 1000 },
      );
      results.push(
        await runSuite({
          template,
          slots,
          probes: DELIMITER_PROBES,
          target: { host: "shop.test", port: 443, tls: true },
          transport,
          random: () => 0.5,
          pairConcurrency: width,
        }),
      );
    }

    const shape = (r: SuiteSummary) =>
      JSON.stringify({
        findings: r.findings.map((f) => f.probeId),
        diagnostics: r.diagnostics.map((d) => `${d.slotName}/${d.probeId}/${d.kind}`),
      });
    expect(shape(results[1]!)).toBe(shape(results[0]!));
    expect(shape(results[2]!)).toBe(shape(results[0]!));
  });
});
