import { describe, expect, it } from "vitest";

import {
  MAX_RETRY_AFTER_MS,
  admit,
  isUsable,
  newTally,
  parseRetryAfter,
  record,
  unusableRate,
} from "../src/transport/admission.ts";
import type { EngineResponse, SendOutcome } from "../src/transport/types.ts";
import { findBodyStart, scanBody, bigramCosine } from "../src/response/scan.ts";

function ascii(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

function response(
  status: number,
  headers: Record<string, string | string[]>,
  body: string,
): EngineResponse {
  const headerLines = Object.entries(headers)
    .flatMap(([k, v]) => (Array.isArray(v) ? v.map((x) => `${k}: ${x}`) : [`${k}: ${v}`]))
    .join("\r\n");
  const rawText = `HTTP/1.1 ${status} X\r\n${headerLines}${headerLines === "" ? "" : "\r\n"}\r\n${body}`;
  const raw = ascii(rawText);
  const map = new Map<string, string[]>();
  for (const [k, v] of Object.entries(headers)) {
    map.set(k.toLowerCase(), Array.isArray(v) ? v : [v]);
  }
  return {
    status,
    headers: map,
    raw,
    bodyStart: findBodyStart(raw),
    roundtripMs: 42,
  };
}

function ok(res: EngineResponse): SendOutcome {
  return { kind: "ok", response: res };
}

describe("transport failures are typed, never silently fingerprinted", () => {
  it("classifies every failure kind as hard-fail", () => {
    for (const failure of [
      "timeout",
      "connection-reset",
      "connection-refused",
      "dns",
      "tls",
      "aborted",
      "unknown",
    ] as const) {
      const admission = admit({ kind: "failed", failure });
      expect(admission.kind).toBe("hard-fail");
      expect(isUsable(admission)).toBe(false);
    }
  });

  it("retains the host detail for the evidence record", () => {
    const admission = admit({
      kind: "failed",
      failure: "timeout",
      detail: "Timeout after 30 seconds",
    });
    expect(admission).toMatchObject({ kind: "hard-fail", detail: "Timeout after 30 seconds" });
  });

  it("a reset break payload is never usable, however reproducible it is", () => {
    // This is the defect being prevented: a firewall that reliably kills the break payload
    // produces a stable, reproducible difference that is not an injection.
    const reset = admit({ kind: "failed", failure: "connection-reset" });
    expect(isUsable(reset)).toBe(false);
  });
});

describe("rate limiting", () => {
  it("treats 429 as soft-fail and parses delta-seconds Retry-After", () => {
    const admission = admit(ok(response(429, { "Retry-After": "120" }, "slow down")));
    expect(admission).toMatchObject({
      kind: "soft-fail",
      reason: "rate-limited",
      retryAfterMs: 120_000,
    });
  });

  it("treats 429 without Retry-After as soft-fail with no delay hint", () => {
    const admission = admit(ok(response(429, {}, "slow down")));
    expect(admission.kind).toBe("soft-fail");
    if (admission.kind === "soft-fail") {
      expect(admission.reason).toBe("rate-limited");
      expect(admission.retryAfterMs).toBeUndefined();
    }
  });

  it("prefers rate-limited over a firewall signature when a 429 carries a block page", () => {
    // Backing off on the Retry-After is the correct response; recording a firewall
    // fingerprint from it would poison the learned block page.
    const admission = admit(
      ok(response(429, { "Retry-After": "5" }, "<h1>Access denied</h1> captcha")),
    );
    expect(admission).toMatchObject({ kind: "soft-fail", reason: "rate-limited" });
  });

  it("keeps the response so the engine can learn from it", () => {
    const admission = admit(ok(response(429, {}, "x")));
    if (admission.kind !== "soft-fail") throw new Error("expected soft-fail");
    expect(admission.response.status).toBe(429);
  });
});

describe("Retry-After parsing", () => {
  it("parses delta-seconds", () => {
    expect(parseRetryAfter("30")).toBe(30_000);
    expect(parseRetryAfter("  30  ")).toBe(30_000);
    expect(parseRetryAfter("0")).toBe(0);
  });

  it("parses an HTTP-date relative to the supplied clock", () => {
    const now = Date.parse("Fri, 25 Jul 2026 12:00:00 GMT");
    expect(parseRetryAfter("Fri, 25 Jul 2026 12:00:30 GMT", now)).toBe(30_000);
  });

  it("clamps a past date to zero rather than returning a negative delay", () => {
    const now = Date.parse("Fri, 25 Jul 2026 12:00:00 GMT");
    expect(parseRetryAfter("Fri, 25 Jul 2026 11:59:00 GMT", now)).toBe(0);
  });

  it("parses the obsolete asctime form, which also begins with a day name", () => {
    // asctime carries no timezone, so it is interpreted in local time. The base is derived the
    // same way to keep the assertion independent of the machine's zone.
    const now = new Date("Sun Nov 6 08:49:07 1994").getTime();
    expect(parseRetryAfter("Sun Nov 6 08:49:37 1994", now)).toBe(30_000);
  });

  it("returns undefined for unparseable or absent values", () => {
    expect(parseRetryAfter(undefined)).toBeUndefined();
    expect(parseRetryAfter("")).toBeUndefined();
    expect(parseRetryAfter("   ")).toBeUndefined();
    expect(parseRetryAfter("soon")).toBeUndefined();
  });

  it("rejects values Date.parse would leniently accept as an ancient date", () => {
    // Date.parse("-5") yields a valid ancient timestamp in V8, which would collapse to a zero
    // delay and silently defeat the backoff. A malformed header must fall through to our own
    // schedule instead of being trusted.
    for (const bogus of ["-5", "5x", "0x10", "2026-07-25"]) {
      expect(parseRetryAfter(bogus), bogus).toBeUndefined();
    }
  });

  it("clamps an absurd delay instead of hanging the engine", () => {
    // A header of 1e20 seconds would otherwise become a 1e23 ms sleep. The caller is expected
    // to compare against its own budget and abort, which it can only do given a finite number.
    expect(parseRetryAfter("99999999999999999999")).toBe(MAX_RETRY_AFTER_MS);
    expect(parseRetryAfter("86400")).toBe(MAX_RETRY_AFTER_MS);
    expect(parseRetryAfter("3600")).toBe(MAX_RETRY_AFTER_MS);
    expect(parseRetryAfter("60")).toBe(60_000);
  });

  it("clamps a far-future HTTP-date the same way", () => {
    const now = Date.parse("Fri, 25 Jul 2026 12:00:00 GMT");
    expect(parseRetryAfter("Sat, 25 Jul 2099 12:00:00 GMT", now)).toBe(MAX_RETRY_AFTER_MS);
  });
});

describe("firewall and challenge fingerprints", () => {
  it("detects a Cloudflare interstitial as a bot challenge", () => {
    const admission = admit(
      ok(response(503, {}, "<title>Just a moment...</title>Checking your browser")),
    );
    expect(admission).toMatchObject({ kind: "soft-fail", reason: "bot-challenge" });
  });

  it("detects a Cloudflare firewall rule block", () => {
    const admission = admit(ok(response(403, {}, "<p>Error code: 1020</p>")));
    expect(admission).toMatchObject({ kind: "soft-fail", reason: "firewall-block" });
  });

  it("detects an Imperva block", () => {
    const admission = admit(
      ok(response(403, {}, "Incapsula incident ID: 1234-5678-90")),
    );
    expect(admission).toMatchObject({ kind: "soft-fail", reason: "firewall-block" });
  });

  it("detects an F5 BIG-IP ASM block", () => {
    const admission = admit(
      ok(response(200, {}, "The requested URL was rejected. Please consult with your admin.")),
    );
    // Note the 200: F5 commonly serves its rejection page with a success status, which is
    // exactly why status alone is an inadequate gate.
    expect(admission).toMatchObject({ kind: "soft-fail", reason: "firewall-block" });
  });

  it("detects a block by response header alone", () => {
    const admission = admit(ok(response(403, { "cf-mitigated": "challenge" }, "")));
    expect(admission).toMatchObject({ kind: "soft-fail", reason: "firewall-block" });
  });

  it("is case-insensitive", () => {
    const admission = admit(ok(response(403, {}, "ERROR CODE: 1020")));
    expect(admission.kind).toBe("soft-fail");
  });

  it("only scans the head, so a fingerprint buried deep does not suppress a finding", () => {
    // Suppression is a false negative. Block pages put their marker near the top, so bounding
    // the scan bounds the damage a coincidental deep match can do.
    const body = "x".repeat(64 * 1024) + "Incapsula incident ID: 1";
    expect(admit(ok(response(200, {}, body))).kind).toBe("usable");
  });
});

describe("weak fingerprints require a blocking status", () => {
  it('does not suppress a 200 page that merely mentions "access denied"', () => {
    // An application explaining an authorisation error, or documentation, or a search result.
    // Suppressing these would hide real findings on exactly the endpoints worth testing.
    const admission = admit(
      ok(response(200, {}, "<h1>Access denied</h1><p>You lack permission.</p>")),
    );
    expect(admission.kind).toBe("usable");
  });

  it('does not suppress a 200 page mentioning "captcha"', () => {
    const admission = admit(ok(response(200, {}, "Please solve the captcha to sign up")));
    expect(admission.kind).toBe("usable");
  });

  it("does suppress the same text behind a 403", () => {
    const admission = admit(ok(response(403, {}, "<h1>Access denied</h1>")));
    expect(admission).toMatchObject({ kind: "soft-fail", reason: "firewall-block" });
  });

  it("leaves a bare 403 with no fingerprint usable", () => {
    // A plain 403 is frequently the application's own authorisation decision and is a
    // legitimate, interesting difference between a break and an escape payload.
    const admission = admit(ok(response(403, {}, '{"error":"forbidden"}')));
    expect(admission.kind).toBe("usable");
  });

  it("leaves 401 usable, since it is ordinary authentication behaviour", () => {
    expect(admit(ok(response(401, {}, "unauthorized"))).kind).toBe("usable");
  });
});

describe("availability versus filtering", () => {
  it("distinguishes a plain 503 from a challenge served with 503", () => {
    const plain = admit(ok(response(503, {}, "upstream unavailable")));
    expect(plain).toMatchObject({ kind: "soft-fail", reason: "server-unavailable" });

    const challenge = admit(ok(response(503, {}, "Just a moment...")));
    expect(challenge).toMatchObject({ kind: "soft-fail", reason: "bot-challenge" });
  });

  it("treats 502 and 504 as unavailable", () => {
    for (const status of [502, 504]) {
      expect(admit(ok(response(status, {}, "gateway")))).toMatchObject({
        kind: "soft-fail",
        reason: "server-unavailable",
      });
    }
  });

  it("parses Retry-After on a 503", () => {
    expect(admit(ok(response(503, { "Retry-After": "7" }, "x")))).toMatchObject({
      retryAfterMs: 7000,
    });
  });
});

describe("learned block page", () => {
  const blockBody = "<html><body><h1>Request blocked</h1><p>ref 99</p></body></html>";
  const blockResponse = response(403, {}, blockBody);

  function bigramsOf(res: EngineResponse): Int32Array {
    return scanBody(res.raw, res.bodyStart, res.raw.length).bigrams;
  }

  const learned = {
    status: 403,
    bigrams: bigramsOf(blockResponse),
    threshold: 0.85,
  };

  function options(target: EngineResponse) {
    return {
      learnedBlock: learned,
      similarityTo: (res: EngineResponse) =>
        bigramCosine(bigramsOf(res), learned.bigrams),
      _target: target,
    };
  }

  it("suppresses a textless block page that matches a captured one", () => {
    const similar = response(403, {}, "<html><body><h1>Request blocked</h1><p>ref 41</p></body></html>");
    const admission = admit(ok(similar), options(similar));
    expect(admission).toMatchObject({
      kind: "soft-fail",
      reason: "firewall-block",
      signal: "matches learned block page",
    });
  });

  it("does not suppress a different 403 that happens to share the status", () => {
    const different = response(403, {}, '{"error":"insufficient_scope","scope":"admin"}');
    expect(admit(ok(different), options(different)).kind).toBe("usable");
  });

  it("does not suppress a matching body under a different status", () => {
    const sameBodyDifferentStatus = response(200, {}, blockBody);
    expect(admit(ok(sameBodyDifferentStatus), options(sameBodyDifferentStatus)).kind).toBe(
      "usable",
    );
  });

  it("is inert when no block page has been learned", () => {
    const anything = response(403, {}, "whatever");
    expect(admit(ok(anything)).kind).toBe("usable");
  });
});

describe("ordinary responses stay usable", () => {
  it("admits a normal 200", () => {
    expect(admit(ok(response(200, { "Content-Type": "text/html" }, "<h1>hi</h1>"))).kind).toBe(
      "usable",
    );
  });

  it("admits a 500, which is frequently the whole point", () => {
    // An interpreter error is the signal the technique hunts for. Treating 5xx as unusable
    // would suppress the most valuable evidence available.
    expect(admit(ok(response(500, {}, "SQL syntax error near line 1"))).kind).toBe("usable");
  });

  it("admits a 404 and a 302", () => {
    expect(admit(ok(response(404, {}, "nope"))).kind).toBe("usable");
    expect(admit(ok(response(302, { Location: "/x" }, ""))).kind).toBe("usable");
  });

  it("admits an empty body", () => {
    expect(admit(ok(response(204, {}, ""))).kind).toBe("usable");
  });
});

describe("admission tally", () => {
  it("counts outcomes by reason", () => {
    const tally = newTally();
    record(tally, admit(ok(response(200, {}, "a"))));
    record(tally, admit(ok(response(429, {}, "b"))));
    record(tally, admit(ok(response(429, {}, "c"))));
    record(tally, admit({ kind: "failed", failure: "timeout" }));

    expect(tally.usable).toBe(1);
    expect(tally.softFail).toBe(2);
    expect(tally.hardFail).toBe(1);
    expect(tally.reasons.get("rate-limited")).toBe(2);
    expect(tally.reasons.get("timeout")).toBe(1);
  });

  it("reports the unusable rate so a blinded measurement is distinguishable from a negative", () => {
    const tally = newTally();
    expect(unusableRate(tally)).toBe(0);
    record(tally, admit(ok(response(200, {}, "a"))));
    expect(unusableRate(tally)).toBe(0);
    record(tally, admit(ok(response(429, {}, "b"))));
    expect(unusableRate(tally)).toBe(0.5);
    record(tally, admit({ kind: "failed", failure: "connection-reset" }));
    expect(unusableRate(tally)).toBeCloseTo(2 / 3, 10);
  });
});
