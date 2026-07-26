import { describe, expect, it } from "vitest";

import { runSuite } from "../src/detect/runner.ts";
import { DELIMITER_PROBES } from "../src/probes/catalogue.ts";
import { enumerateSlots } from "../src/request/slots.ts";
import { asciiBytes, locate } from "../src/request/template.ts";
import { findBodyStart } from "../src/response/scan.ts";
import { DEFAULT_THROTTLE, createProbeTransport } from "../src/transport/throttle.ts";
import type { SendOutcome } from "../src/transport/types.ts";

/**
 * Run one probe on one slot and return the raw bytes of every request that was sent.
 *
 * Asserting on the wire bytes is the only way to catch an encoding fault. Every layer above this
 * agreed with itself while the request leaving the socket was wrong.
 */
async function sentBytes(request: string, slotName: string): Promise<string[]> {
  const template = locate(asciiBytes(request));
  const slots = enumerateSlots(template).slots.filter((s) => s.name === slotName);
  expect(slots.length, `slot ${slotName} should exist`).toBe(1);

  const sent: string[] = [];
  const body = "<html><body>ok</body></html>";
  const raw = asciiBytes(
    `HTTP/1.1 200 X\r\nContent-Type: text/html\r\nContent-Length: ${body.length}\r\n\r\n${body}`,
  );
  const transport = createProbeTransport(
    {
      provider: {
        send: async (req): Promise<SendOutcome> => {
          sent.push(new TextDecoder().decode(req.raw));
          await Promise.resolve();
          return {
            kind: "ok",
            response: {
              status: 200,
              headers: new Map([["content-type", ["text/html"]]]),
              raw,
              bodyStart: findBodyStart(raw),
              roundtripMs: 4,
            },
          };
        },
      },
      sleep: async () => {
        await Promise.resolve();
      },
      now: () => 0,
    },
    { ...DEFAULT_THROTTLE, minDelayMs: 0, haltMinObservations: 1000 },
  );

  await runSuite({
    template,
    slots,
    probes: [DELIMITER_PROBES[0]!],
    target: { host: "shop.test", port: 443, tls: true },
    transport,
    random: () => 0.5,
  });
  return sent;
}

describe("the existing parameter value is re-sent verbatim", () => {
  // Regression, found on a live target: `baseValue` comes from slicing the RECORDED request, so it is
  // already in wire form. The builder concatenated it with the payload and ran the whole string through
  // the codec, so every percent sign in the original value was re-encoded. A product template holding
  // `%3Cp%3E...%24%7Bproduct.stock%7D` was re-sent as `%253Cp%253E...`, and the application stored the
  // literal text `%3Cp%3E`. On a template field that also destroys the `${...}` expressions being
  // tested, and on a save endpoint the damage persists after the scan.
  it("does not re-encode a percent-encoded form value", async () => {
    const original = "%3Cp%3EHi%3C%2Fp%3E%24%7Bproduct.stock%7D";
    const sent = await sentBytes(
      [
        "POST /product/template HTTP/1.1",
        "Host: shop.test",
        "Content-Type: application/x-www-form-urlencoded",
        `Content-Length: ${`template=${original}`.length}`,
        "",
        `template=${original}`,
      ].join("\r\n"),
      "template",
    );

    expect(sent.length).toBeGreaterThan(0);
    for (const wire of sent) {
      expect(wire, "the recorded value must appear byte-for-byte").toContain(original);
      expect(wire, "a re-encoded percent sign means the value was mangled").not.toContain("%253Cp");
      expect(wire).not.toContain("%2524%257B");
    }
  });

  it("keeps a query value verbatim too", async () => {
    const sent = await sentBytes(
      "GET /search?q=a%20b%25c HTTP/1.1\r\nHost: shop.test\r\n\r\n",
      "q",
    );
    for (const wire of sent) {
      expect(wire).toContain("q=a%20b%25c");
      expect(wire).not.toContain("a%2520b");
    }
  });

  it("still appends the canary-framed payload after the existing value", async () => {
    const sent = await sentBytes("GET /search?q=widget HTTP/1.1\r\nHost: shop.test\r\n\r\n", "q");
    for (const wire of sent) {
      // The payload lands after the real value, so the parameter keeps its original context.
      expect(wire).toMatch(/q=widgetbs[0-9a-z]{4}/);
    }
  });

  it("sends both arms with the same base value, so parity is unaffected", async () => {
    const sent = await sentBytes("GET /search?q=widget HTTP/1.1\r\nHost: shop.test\r\n\r\n", "q");
    expect(sent.every((wire) => wire.includes("q=widget"))).toBe(true);
  });
});
