/**
 * End-to-end vertical slice.
 *
 * A synthetic target is driven through the real chain: slot enumeration, per-surface encoding,
 * byte-exact assembly, transport with admission and throttling, reflection excision, featurisation,
 * and the screening ladder. Nothing is stubbed except the socket.
 *
 * Each target below is a specific adversarial scenario from the design, and the assertion is the
 * verdict the whole pipeline should reach.
 */

import { describe, expect, it } from "vitest";

import { runLadder, type ProbeArms } from "../src/detect/ladder.ts";
import { QUERY_VALUE_CODEC } from "../src/request/codecs.ts";
import { enumerateSlots } from "../src/request/slots.ts";
import { asciiBytes, assemble, locate } from "../src/request/template.ts";
import { findBodyStart } from "../src/response/scan.ts";
import { createProbeTransport, DEFAULT_THROTTLE } from "../src/transport/throttle.ts";
import type { EngineRequest, SendOutcome } from "../src/transport/types.ts";

const REQUEST = [
  "GET /search?q=widget&page=2 HTTP/1.1",
  "Host: shop.test",
  "Accept: text/html",
  "",
  "",
].join("\r\n");

const str = (u: Uint8Array): string => {
  let out = "";
  for (const b of u) out += String.fromCharCode(b);
  return out;
};

const template = locate(asciiBytes(REQUEST));
const slot = enumerateSlots(template).slots.find(
  (s) => s.kind === "query-value" && s.name === "q",
)!;

/** Build one arm: encode the payload for the surface, splice it, wrap it as an EngineRequest. */
function armBuilder(): ProbeArms["build"] {
  return (payload, canary) => {
    // The framing the design mandates: base value, anchor, payload, closing anchor.
    const framed =
      canary.right === undefined
        ? `${slot.baseValue}${canary.left}${payload}`
        : `${slot.baseValue}${canary.left}${payload}${canary.right}`;
    const encoded = QUERY_VALUE_CODEC.encode(asciiBytes(framed), "literal");
    if (!encoded.ok) throw new Error(`unexpectedly refused: ${encoded.reason}`);
    return {
      host: "shop.test",
      port: 443,
      tls: true,
      raw: assemble(template, [{ range: slot.range, bytes: encoded.bytes }]),
    };
  };
}

/** The payload as the target sees it: everything after the opening canary. */
function payloadSeen(raw: Uint8Array): string {
  const value = decodeQueryValue(raw);
  const marker = /lq[0-9a-z]{3}z/.exec(value);
  return marker === null ? "" : value.slice(marker.index + marker[0].length);
}

function decodeQueryValue(raw: Uint8Array): string {
  let text = "";
  for (const byte of raw) text += String.fromCharCode(byte);
  const match = /\?q=([^&\s]*)/.exec(text);
  const encoded = match?.[1] ?? "";
  // The engine percent-encodes separators; decode only those so the target sees the true payload.
  return encoded.replace(/%([0-9A-Fa-f]{2})/g, (_, hex: string) =>
    String.fromCharCode(Number.parseInt(hex, 16)),
  );
}

function respond(status: number, body: string, extraHeaders = ""): SendOutcome {
  const raw = asciiBytes(
    `HTTP/1.1 ${status} X\r\nContent-Type: text/html\r\n${extraHeaders}Content-Length: ${body.length}\r\n\r\n${body}`,
  );
  return {
    kind: "ok",
    response: {
      status,
      headers: new Map([["content-type", ["text/html"]]]),
      raw,
      bodyStart: findBodyStart(raw),
      roundtripMs: 30,
    },
  };
}

/** Deterministic clock and coin, so the whole run is reproducible. */
function deps(target: (raw: Uint8Array) => SendOutcome) {
  let time = 0;
  let seed = 1;
  const random = () => {
    // xorshift, deterministic
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    seed >>>= 0;
    return seed / 0xffffffff;
  };
  let canaryCounter = 0;
  const transport = createProbeTransport(
    {
      provider: {
        send: async (request: EngineRequest) => {
          await Promise.resolve();
          return target(request.raw);
        },
      },
      sleep: async (ms: number) => {
        time += ms;
        await Promise.resolve();
      },
      now: () => time,
    },
    { ...DEFAULT_THROTTLE, minDelayMs: 0, haltMinObservations: 4 },
  );
  return {
    transport,
    random,
    canary: () => {
      canaryCounter += 1;
      const tag = canaryCounter.toString(36).padStart(3, "0");
      return { left: `lq${tag}z`, right: `rw${tag}y` };
    },
  };
}

/** The canonical probe pair: an odd number of trailing backslashes against an even number. */
const BACKSLASH_ARMS: ProbeArms = {
  breakPayload: "\\",
  escapePayload: "\\\\",
  build: armBuilder(),
  // A trailing backslash is only an unterminated escape if nothing follows it.
  endAnchored: true,
};

describe("end to end: the whole chain on one probe pair", () => {
  it("finds a target that errors on an unterminated escape", async () => {
    // The vulnerable case: an odd number of backslashes reaches a interpreter and throws. The
    // payload is NOT reflected, so this is the pure signal case.
    const outcome = await runLadder(
      deps((raw) => {
        const trailing = /\\*$/.exec(payloadSeen(raw))?.[0].length ?? 0;
        return trailing % 2 === 1
          ? respond(500, "<html><body>Unclosed quotation mark: SQL syntax error</body></html>")
          : respond(200, "<html><body><div>3 results for widget</div></body></html>");
      }),
      BACKSLASH_ARMS,
    );

    expect(outcome.kind).toBe("candidate");
    if (outcome.kind !== "candidate") return;
    expect(outcome.m).toBe(6);
    expect(outcome.sends).toBe(12);
    const names = outcome.witnesses.map((w) => w.name);
    expect(names).toContain("status");
    expect(names).toContain("kw:error");
    expect(names).toContain("kw:sql syntax");
  });

  it("costs exactly two requests on a target that ignores the parameter", async () => {
    // The dominant case, and the reason the screen must be cheap.
    const outcome = await runLadder(
      deps(() => respond(200, "<html><body><div>static page</div></body></html>")),
      BACKSLASH_ARMS,
    );
    expect(outcome).toEqual({ kind: "boring", stage: "S0", sends: 2 });
  });

  it("rejects a target whose response merely churns at random", async () => {
    // Scenario (a): per-request tokens and rotating content. Something differs every round, but
    // never the same thing in the same direction, so consistency filters it out.
    let n = 0;
    const outcome = await runLadder(
      deps(() => {
        n += 1;
        const filler = "x".repeat(n % 7);
        return respond(
          200,
          `<html><body><div>csrf=${n * 7919}</div><span>${filler}</span></body></html>`,
        );
      }),
      BACKSLASH_ARMS,
    );
    expect(outcome.kind).toBe("boring");
    if (outcome.kind === "boring") expect(outcome.stage === "S1" || outcome.stage === "S2").toBe(true);
  });

  it("does not report a firewall that blocks the break arm", async () => {
    // Scenario (b): the block is perfectly reproducible, so consistency alone would call it a
    // finding. Admission is what stops it, and the outcome names the reason.
    const outcome = await runLadder(
      deps((raw) => {
        const trailing = /\\*$/.exec(payloadSeen(raw))?.[0].length ?? 0;
        return trailing % 2 === 1
          ? respond(403, "<html><body>Error code: 1020</body></html>")
          : respond(200, "<html><body>ok</body></html>");
      }),
      BACKSLASH_ARMS,
    );
    expect(outcome.kind).toBe("inconclusive");
    if (outcome.kind === "inconclusive") {
      expect(outcome.reason === "blinded" || outcome.reason === "halted").toBe(true);
      expect(outcome.detail).toMatch(/firewall|halt/i);
    }
  });

  it("does not report rate limiting as a negative result", async () => {
    // Scenario (c). The distinction that matters: a blinded measurement is not a clean bill of
    // health, and the ladder says so rather than returning boring.
    const outcome = await runLadder(
      deps(() => ({
        kind: "ok",
        response: (() => {
          const raw = asciiBytes("HTTP/1.1 429 X\r\nRetry-After: 1\r\nContent-Length: 4\r\n\r\nslow");
          return {
            status: 429,
            headers: new Map([["retry-after", ["1"]]]),
            raw,
            bodyStart: findBodyStart(raw),
            roundtripMs: 5,
          };
        })(),
      })),
      BACKSLASH_ARMS,
    );
    expect(outcome.kind).toBe("inconclusive");
  });

  it("does not report a transport failure as evidence", async () => {
    // The prior implementation's worst defect: a dropped connection fingerprinted as a real
    // response, so a firewall that killed the break arm became a confident finding.
    const outcome = await runLadder(
      deps((raw) => {
        const trailing = /\\*$/.exec(payloadSeen(raw))?.[0].length ?? 0;
        return trailing % 2 === 1
          ? { kind: "failed", failure: "connection-reset" }
          : respond(200, "<html><body>ok</body></html>");
      }),
      BACKSLASH_ARMS,
    );
    expect(outcome.kind).toBe("inconclusive");
  });

  it("vetoes a reflection-only difference on a target that just echoes the payload", async () => {
    // Scenario (f), the dominant false-positive mechanism. The target echoes the value verbatim and
    // does nothing else, so every difference is explained by one arm having one more backslash.
    const outcome = await runLadder(
      deps((raw) => {
        const value = decodeQueryValue(raw);
        return respond(200, `<html><body><p>No results for ${value}</p></body></html>`);
      }),
      BACKSLASH_ARMS,
    );
    // Either nothing survived consistency, or everything that did was explained by the payload
    // delta. Both are correct; what must NOT happen is a candidate.
    expect(["boring", "veto-payload-delta"]).toContain(outcome.kind);
  });

  it("still finds a real error on a target that ALSO echoes the payload", async () => {
    // The test that proves excision does not blind the detector: the echo is neutralised, but a
    // genuine error message outside the reflection still surfaces.
    const outcome = await runLadder(
      deps((raw) => {
        const value = decodeQueryValue(raw);
        const trailing = /\\*$/.exec(payloadSeen(raw))?.[0].length ?? 0;
        const body =
          `<html><body><p>Results for ${value}</p>` +
          (trailing % 2 === 1 ? "<div>SQL syntax error near line 1</div>" : "<div>3 items</div>") +
          "</body></html>";
        return respond(200, body);
      }),
      BACKSLASH_ARMS,
    );
    expect(outcome.kind).toBe("candidate");
    if (outcome.kind !== "candidate") return;
    expect(outcome.witnesses.map((w) => w.name)).toContain("kw:sql syntax");
  });

  it("the two arms differ only inside the slot, which the permutation null requires", () => {
    const build = armBuilder();
    const canary = { left: "lq001z" };

    // Same payload, same bytes: proves nothing else in the request varies per send.
    expect(Array.from(build("\\", canary).raw)).toEqual(Array.from(build("\\", canary).raw));

    const brk = build("\\", canary).raw;
    const esc = build("\\\\", canary).raw;

    // Identical up to the slot start.
    const at = slot.range.start;
    expect(Array.from(brk.subarray(0, at))).toEqual(Array.from(esc.subarray(0, at)));

    // Identical after each arm's own payload region: the tail of the request line onward.
    const brkTail = str(brk).slice(str(brk).indexOf(" HTTP/1.1"));
    const escTail = str(esc).slice(str(esc).indexOf(" HTTP/1.1"));
    expect(brkTail).toBe(escTail);
  });
});
