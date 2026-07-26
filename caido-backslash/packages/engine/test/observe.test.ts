import { describe, expect, it } from "vitest";

import { differingFeatures, featurise } from "../src/detect/features.ts";
import { asciiBytes, locate, sliceText } from "../src/request/template.ts";
import { findBodyStart } from "../src/response/scan.ts";
import {
  buildObservationRequest,
  createRedirectObserver,
  createUrlObserver,
  type ObserveSend,
} from "../src/transport/observe.ts";
import type { ProbeResult } from "../src/transport/throttle.ts";
import type { EngineResponse } from "../src/transport/types.ts";
import {
  formatLocated,
  parseObservationUrl,
  removeDotSegments,
  resolveLocation,
  type Located,
} from "../src/transport/url.ts";

const ORIGIN = { host: "shop.test", port: 443, tls: true } as const;
const BASE: Located = { origin: ORIGIN, target: "/a/b/page?q=1" };

function response(status: number, headers: Record<string, string>, body = ""): EngineResponse {
  const lines = Object.entries(headers).map(([k, v]) => `${k}: ${v}`);
  const raw = asciiBytes(
    `HTTP/1.1 ${status} X\r\n${lines.join("\r\n")}\r\nContent-Length: ${body.length}\r\n\r\n${body}`,
  );
  const map = new Map<string, string[]>();
  for (const [k, v] of Object.entries(headers)) map.set(k.toLowerCase(), [v]);
  map.set("content-length", [String(body.length)]);
  return { status, headers: map, raw, bodyStart: findBodyStart(raw), roundtripMs: 5 };
}

function usable(res: EngineResponse): ProbeResult {
  return { kind: "usable", response: res };
}

describe("resolveLocation", () => {
  it("resolves a root-relative Location against the same origin", () => {
    const r = resolveLocation(BASE, "/render?id=9");
    expect(r.kind).toBe("ok");
    expect(r.kind === "ok" && formatLocated(r.located)).toBe("https://shop.test/render?id=9");
  });

  it("resolves a relative Location against the base directory, not the base file", () => {
    const r = resolveLocation(BASE, "next");
    expect(r.kind === "ok" && r.located.target).toBe("/a/b/next");
  });

  it("collapses dot segments in a relative Location", () => {
    const r = resolveLocation(BASE, "../up/here");
    expect(r.kind === "ok" && r.located.target).toBe("/a/up/here");
  });

  it("keeps an absolute Location's own origin and scheme", () => {
    const r = resolveLocation(BASE, "http://other.test:8080/x");
    expect(r.kind === "ok" && r.located.origin).toEqual({
      host: "other.test",
      port: 8080,
      tls: false,
    });
  });

  it("inherits the scheme for a protocol-relative Location", () => {
    const r = resolveLocation(BASE, "//cdn.test/asset");
    expect(r.kind === "ok" && r.located.origin).toEqual({ host: "cdn.test", port: 443, tls: true });
  });

  it("defaults the port from the scheme", () => {
    expect(resolveLocation(BASE, "http://a.test/").kind === "ok").toBe(true);
    const r = resolveLocation(BASE, "http://a.test/");
    expect(r.kind === "ok" && r.located.origin.port).toBe(80);
  });

  it("strips a fragment, which is never sent to the server", () => {
    const r = resolveLocation(BASE, "/page#section");
    expect(r.kind === "ok" && r.located.target).toBe("/page");
  });

  it("refuses non-http schemes rather than trying to fetch them", () => {
    for (const location of ["javascript:alert(1)", "mailto:a@b.test", "data:text/html,x"]) {
      const r = resolveLocation(BASE, location);
      expect(r.kind, location).toBe("unsupported");
    }
  });

  it("refuses an authority carrying userinfo instead of silently stripping it", () => {
    // Stripping would change who the observation authenticates as.
    const r = resolveLocation(BASE, "https://user:pass@evil.test/x");
    expect(r.kind).toBe("unsupported");
  });

  it("refuses a non-numeric port rather than guessing one", () => {
    expect(resolveLocation(BASE, "https://a.test:notaport/x").kind).toBe("unsupported");
  });

  it("handles an IPv6 authority with and without a port", () => {
    const bare = resolveLocation(BASE, "http://[::1]/x");
    expect(bare.kind === "ok" && bare.located.origin).toEqual({
      host: "[::1]",
      port: 80,
      tls: false,
    });
    const ported = resolveLocation(BASE, "http://[::1]:8080/x");
    expect(ported.kind === "ok" && ported.located.origin.port).toBe(8080);
  });

  it("does NOT decode percent-escapes in the target", () => {
    // Whether %2e%2e collapses is frequently the vulnerability. Deciding here would hide it.
    const r = resolveLocation(BASE, "/a/%2e%2e/b");
    expect(r.kind === "ok" && r.located.target).toBe("/a/%2e%2e/b");
  });
});

describe("removeDotSegments", () => {
  it("collapses . and .. without touching encoded forms", () => {
    expect(removeDotSegments("/a/b/../c")).toBe("/a/c");
    expect(removeDotSegments("/a/./b")).toBe("/a/b");
    expect(removeDotSegments("/a/%2e%2e/b")).toBe("/a/%2e%2e/b");
  });

  it("cannot escape above the root", () => {
    expect(removeDotSegments("/../../etc")).toBe("/etc");
  });

  it("preserves a trailing slash", () => {
    expect(removeDotSegments("/a/b/")).toBe("/a/b/");
  });
});

describe("buildObservationRequest", () => {
  const template = locate(
    asciiBytes(
      [
        "POST /submit HTTP/1.1",
        "Host: shop.test",
        "Cookie: session=abc123",
        "Authorization: Bearer t0ken",
        "Content-Type: application/x-www-form-urlencoded",
        "Content-Length: 5",
        "If-None-Match: \"etag\"",
        "",
        "q=hi",
      ].join("\r\n"),
    ),
  );

  const built = (target: string) =>
    new TextDecoder().decode(
      buildObservationRequest(template, { origin: ORIGIN, target }).raw,
    );

  it("issues a GET for the observation target regardless of the original method", () => {
    expect(built("/profile")).toMatch(/^GET \/profile HTTP\/1\.1\r\n/);
  });

  it("carries the session forward, or the observation measures a login page", () => {
    const raw = built("/profile");
    expect(raw).toContain("Cookie: session=abc123");
    expect(raw).toContain("Authorization: Bearer t0ken");
  });

  it("drops body framing headers, since there is no body", () => {
    const raw = built("/profile");
    expect(raw).not.toContain("Content-Length");
    expect(raw).not.toContain("Content-Type");
    expect(raw.endsWith("\r\n\r\n")).toBe(true);
  });

  it("drops conditional headers, so a 304 is never measured as a difference", () => {
    expect(built("/profile")).not.toContain("If-None-Match");
  });

  it("rewrites Host when the observation is on another origin", () => {
    const raw = new TextDecoder().decode(
      buildObservationRequest(template, {
        origin: { host: "other.test", port: 8080, tls: false },
        target: "/x",
      }).raw,
    );
    expect(raw).toContain("Host: other.test:8080");
    expect(raw).not.toContain("Host: shop.test");
  });

  it("omits the port from Host when it is the scheme default", () => {
    expect(built("/x")).toContain("Host: shop.test\r\n");
  });
});

describe("createRedirectObserver", () => {
  const template = locate(asciiBytes("GET /a/b/page?q=1 HTTP/1.1\r\nHost: shop.test\r\n\r\n"));

  function observerWith(pages: Record<string, EngineResponse>, maxHops = 3) {
    const targets: string[] = [];
    const send: ObserveSend = async (request) => {
      const line = new TextDecoder().decode(request.raw.slice(0, 200)).split("\r\n")[0]!;
      const target = line.split(" ")[1]!;
      targets.push(target);
      await Promise.resolve();
      return usable(pages[target] ?? response(404, {}, "nope"));
    };
    return {
      targets,
      observer: createRedirectObserver({ template, send, maxHops }),
    };
  }

  const ctx = { base: BASE, label: "probe:break" };

  it("measures the probe's own response when it is not a redirect", async () => {
    const { observer, targets } = observerWith({});
    const out = await observer(response(200, {}, "body"), ctx);
    expect(out.kind).toBe("none");
    // The point of `none`: enabling the option must not cost a request on endpoints that do not
    // redirect, nor drop them from the scan.
    expect(targets).toEqual([]);
  });

  it("follows a single hop and measures the target", async () => {
    const { observer, targets } = observerWith({
      "/rendered": response(200, {}, "<%= 7*7 %> boom"),
    });
    const out = await observer(response(302, { Location: "/rendered" }), ctx);
    expect(out.kind).toBe("ok");
    expect(out.kind === "ok" && new TextDecoder().decode(out.response.raw)).toContain("boom");
    expect(targets).toEqual(["/rendered"]);
  });

  it("follows a chain up to the hop cap", async () => {
    const { observer, targets } = observerWith(
      {
        "/one": response(302, { Location: "/two" }),
        "/two": response(302, { Location: "/three" }),
        "/three": response(200, {}, "end"),
      },
      3,
    );
    const out = await observer(response(302, { Location: "/one" }), ctx);
    expect(out.kind).toBe("ok");
    expect(targets).toEqual(["/one", "/two", "/three"]);
    expect(out.kind === "ok" && out.via).toHaveLength(3);
  });

  it("stops at the hop cap and still returns a comparable measurement", async () => {
    const { observer, targets } = observerWith(
      { "/one": response(302, { Location: "/two" }), "/two": response(302, { Location: "/one" }) },
      1,
    );
    const out = await observer(response(302, { Location: "/one" }), ctx);
    expect(out.kind).toBe("ok");
    expect(targets).toEqual(["/one"]);
  });

  it("breaks a redirect loop instead of burning the hop budget", async () => {
    // /loop points at itself. Without the seen-set this spends every hop on the same URL.
    const { observer, targets } = observerWith(
      { "/loop": response(302, { Location: "/loop" }) },
      5,
    );
    const out = await observer(response(302, { Location: "/loop" }), ctx);
    expect(out.kind).toBe("ok");
    expect(targets).toEqual(["/loop"]);
  });

  it("REFUSES to follow a redirect off the origin", async () => {
    // A Location is attacker-influenceable in exactly the cases this scanner hunts. Following it
    // would send the session's cookies to a host the operator never authorised.
    const { observer, targets } = observerWith({});
    const out = await observer(response(302, { Location: "https://evil.test/steal" }), ctx);
    expect(out.kind).toBe("none");
    expect(out.kind === "none" && out.why).toContain("leaves the origin");
    expect(targets).toEqual([]);
  });

  it("refuses a cross-origin hop even when it is mid-chain", async () => {
    const { observer, targets } = observerWith({
      "/one": response(302, { Location: "//evil.test/steal" }),
    });
    const out = await observer(response(302, { Location: "/one" }), ctx);
    expect(targets).toEqual(["/one"]);
    // The first hop is a real measurement, so it is kept rather than discarded.
    expect(out.kind).toBe("ok");
    expect(out.kind === "ok" && out.via).toEqual(["https://shop.test/one"]);
  });

  it("treats a redirect status with no Location as nothing to follow", async () => {
    const { observer } = observerWith({});
    const out = await observer(response(302, {}), ctx);
    expect(out.kind).toBe("none");
  });

  it("reports an unusable hop as a failure, never as a measurement", async () => {
    const send: ObserveSend = async () => {
      await Promise.resolve();
      return { kind: "hard-fail", failure: "connection-reset" };
    };
    const observer = createRedirectObserver({ template, send, maxHops: 2 });
    const out = await observer(response(302, { Location: "/x" }), ctx);
    expect(out.kind).toBe("failed");
  });

  it("propagates a halt rather than degrading it to a failure", async () => {
    const send: ObserveSend = async () => {
      await Promise.resolve();
      return { kind: "halted", reason: { kind: "cancelled" } } as ProbeResult;
    };
    const observer = createRedirectObserver({ template, send, maxHops: 2 });
    const out = await observer(response(302, { Location: "/x" }), ctx);
    expect(out.kind).toBe("halted");
  });
});

describe("createUrlObserver", () => {
  const template = locate(asciiBytes("GET /inject?q=1 HTTP/1.1\r\nHost: shop.test\r\n\r\n"));

  it("fetches the fixed URL and measures that, ignoring the probe response", async () => {
    const targets: string[] = [];
    const send: ObserveSend = async (request) => {
      const line = new TextDecoder().decode(request.raw).split("\r\n")[0]!;
      targets.push(line.split(" ")[1]!);
      await Promise.resolve();
      return usable(response(200, {}, "rendered 49 here"));
    };
    const observer = createUrlObserver({
      template,
      send,
      at: { origin: ORIGIN, target: "/profile" },
    });
    const out = await observer(response(200, {}, "thanks"), { base: BASE, label: "p:break" });
    expect(targets).toEqual(["/profile"]);
    expect(out.kind === "ok" && new TextDecoder().decode(out.response.raw)).toContain("49");
  });
});

describe("parseObservationUrl", () => {
  it("accepts a bare path against the scanned origin", () => {
    const r = parseObservationUrl("/profile", ORIGIN);
    expect(r.kind === "ok" && formatLocated(r.located)).toBe("https://shop.test/profile");
  });

  it("accepts an absolute URL on another host, which the caller must surface for scope", () => {
    const r = parseObservationUrl("http://staging.test:8080/render", ORIGIN);
    expect(r.kind === "ok" && formatLocated(r.located)).toBe("http://staging.test:8080/render");
  });

  it("rejects empty and non-http input", () => {
    expect(parseObservationUrl("   ", ORIGIN).kind).toBe("unsupported");
    expect(parseObservationUrl("javascript:alert(1)", ORIGIN).kind).toBe("unsupported");
  });

  it("treats a bare word as a path so a typo cannot become another host", () => {
    const r = parseObservationUrl("profile", ORIGIN);
    expect(r.kind === "ok" && formatLocated(r.located)).toBe("https://shop.test/profile");
  });
});

describe("template target slicing used as the redirect base", () => {
  it("reads the original request target, which is what keeps both arms resolving alike", () => {
    const template = locate(asciiBytes("GET /a/b/page?q=1 HTTP/1.1\r\nHost: shop.test\r\n\r\n"));
    expect(sliceText(template.raw, template.targetRange)).toBe("/a/b/page?q=1");
  });
});

describe("locationHash excises reflected input", () => {
  // Regression: a redirect that carries its input back (?next=, ?returnUrl=, an error message) gave
  // the two arms different Locations purely because the payloads differ, and the raw hash reported
  // that as a confident finding. The payload-delta veto cannot help -- it reasons about byte-class
  // counters, and a hash has none.
  const canary = { left: "bsab12", right: "cd34se" };

  function vector(location: string) {
    const raw = asciiBytes(`HTTP/1.1 302 Found\r\nLocation: ${location}\r\nContent-Length: 0\r\n\r\n`);
    const res: EngineResponse = {
      status: 302,
      headers: new Map([["location", [location]]]),
      raw,
      bodyStart: findBodyStart(raw),
      roundtripMs: 3,
    };
    return featurise(res, { canary, sentPayload: "x" });
  }

  it("gives the same hash when only the reflected payload differs", () => {
    const a = vector("/rendered?msg=bsab12%3C%25%3D%207%2F0%20%25%3Ecd34se");
    const b = vector("/rendered?msg=bsab12%3C%25%3D%207*1%20%25%3Ecd34se");
    expect(a.locationHash).toBe(b.locationHash);
    expect(differingFeatures(a, b).some((d) => d.name === "locationHash")).toBe(false);
  });

  it("still reports a genuinely different redirect destination", () => {
    const a = vector("/error?msg=bsab12xcd34se");
    const b = vector("/welcome?msg=bsab12xcd34se");
    expect(a.locationHash).not.toBe(b.locationHash);
    expect(differingFeatures(a, b).some((d) => d.name === "locationHash")).toBe(true);
  });

  it("excises to the end when the closing canary never made it into the Location", () => {
    const a = vector("/r?msg=bsab12<%= 7/0 %>");
    const b = vector("/r?msg=bsab12<%= 7*1 %>");
    expect(a.locationHash).toBe(b.locationHash);
  });

  it("leaves a Location with no echo in it alone", () => {
    expect(vector("/fixed").locationHash).toBe(vector("/fixed").locationHash);
    expect(vector("/fixed").locationHash).not.toBe(vector("/other").locationHash);
  });
});
