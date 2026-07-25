import { describe, expect, it } from "vitest";

import {
  DEFAULT_MAX_SITES,
  EchoTransform,
  capSpan,
  classifyTransform,
  locateEcho,
  mergeSpans,
  subtractSpans,
} from "../src/response/echo.ts";
import { scanBody } from "../src/response/scan.ts";

function ascii(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

const FRAME = { left: "aaqqzz", right: "wwppyy" };

function analyse(body: string, sentPayload: string, capBytes?: number) {
  const bytes = ascii(body);
  return {
    bytes,
    echo: locateEcho(
      bytes,
      0,
      bytes.length,
      FRAME,
      capBytes === undefined ? { sentPayload } : { sentPayload, capBytes },
    ),
  };
}

describe("span algebra", () => {
  it("merges overlapping and touching spans", () => {
    expect(mergeSpans([{ start: 0, end: 5 }, { start: 3, end: 8 }])).toEqual([
      { start: 0, end: 8 },
    ]);
    expect(mergeSpans([{ start: 0, end: 5 }, { start: 5, end: 8 }])).toEqual([
      { start: 0, end: 8 },
    ]);
    expect(mergeSpans([{ start: 6, end: 8 }, { start: 0, end: 5 }])).toEqual([
      { start: 0, end: 5 },
      { start: 6, end: 8 },
    ]);
  });

  it("keeps a fully contained span from extending its parent", () => {
    expect(mergeSpans([{ start: 0, end: 20 }, { start: 5, end: 10 }])).toEqual([
      { start: 0, end: 20 },
    ]);
  });

  it("subtracts a hole from the middle of a range", () => {
    expect(subtractSpans([{ start: 0, end: 100 }], [{ start: 40, end: 60 }])).toEqual([
      { start: 0, end: 40 },
      { start: 60, end: 100 },
    ]);
  });

  it("subtracts holes at both edges", () => {
    expect(
      subtractSpans([{ start: 0, end: 100 }], [
        { start: 0, end: 10 },
        { start: 90, end: 100 },
      ]),
    ).toEqual([{ start: 10, end: 90 }]);
  });

  it("returns nothing when a hole covers the range", () => {
    expect(subtractSpans([{ start: 10, end: 20 }], [{ start: 0, end: 100 }])).toEqual([]);
  });

  it("ignores holes outside the range", () => {
    expect(subtractSpans([{ start: 10, end: 20 }], [{ start: 50, end: 60 }])).toEqual([
      { start: 10, end: 20 },
    ]);
  });

  it("handles multiple ranges and multiple holes", () => {
    expect(
      subtractSpans(
        [
          { start: 0, end: 50 },
          { start: 100, end: 150 },
        ],
        [
          { start: 10, end: 20 },
          { start: 120, end: 130 },
        ],
      ),
    ).toEqual([
      { start: 0, end: 10 },
      { start: 20, end: 50 },
      { start: 100, end: 120 },
      { start: 130, end: 150 },
    ]);
  });

  it("never emits an empty range", () => {
    const out = subtractSpans([{ start: 0, end: 10 }], [{ start: 0, end: 10 }]);
    expect(out).toEqual([]);
  });
});

describe("span cap", () => {
  it("scales with the payload but is absolutely bounded", () => {
    expect(capSpan(1)).toBe(72);
    expect(capSpan(10)).toBe(144);
    // 8x covers HTML-entity and \uXXXX expansion, both at most 6x.
    expect(capSpan(100)).toBe(864);
    expect(capSpan(10_000)).toBe(4096);
  });
});

describe("locating the echo", () => {
  it("reports absent when the value is not reflected", () => {
    const { echo } = analyse("<html><body>nothing here</body></html>", "z'z");
    expect(echo.state).toBe("absent");
    expect(echo.spans).toEqual([]);
    expect(echo.excisedBytes).toBe(0);
  });

  it("excises a single paired site including both canaries", () => {
    const body = `<p>you searched for ${FRAME.left}z'z${FRAME.right} today</p>`;
    const { echo } = analyse(body, "z'z");
    expect(echo.state).toBe("paired");
    expect(echo.siteCount).toBe(1);
    expect(echo.spans).toHaveLength(1);
    const span = echo.spans[0]!;
    expect(body.slice(span.start, span.end)).toBe(`${FRAME.left}z'z${FRAME.right}`);
  });

  it("excises every site when the value is reflected repeatedly", () => {
    const one = `${FRAME.left}z'z${FRAME.right}`;
    const body = `<a>${one}</a><b>${one}</b><c>${one}</c>`;
    const { echo } = analyse(body, "z'z");
    expect(echo.siteCount).toBe(3);
    expect(echo.spans).toHaveLength(3);
    expect(echo.excisedBytes).toBe(3 * one.length);
  });

  it("bounds the work on a page that echoes input hundreds of times", () => {
    const one = `${FRAME.left}z${FRAME.right}`;
    const body = one.repeat(DEFAULT_MAX_SITES + 20);
    const { echo } = analyse(body, "z");
    expect(echo.siteCount).toBe(DEFAULT_MAX_SITES + 20);
    // Sites beyond the cap are counted but not excised, and the count reveals it.
    expect(echo.spans.length).toBeLessThanOrEqual(DEFAULT_MAX_SITES);
  });

  it("masks only the opening canary when the closing one is missing", () => {
    // The naive behaviour is to redact from L to end-of-document. That silently deletes real
    // evidence over a span that depends on the payload, which is itself a false-positive source.
    const tail = "x".repeat(5000);
    const body = `<p>${FRAME.left}z'z truncated${tail}</p>`;
    const { echo } = analyse(body, "z'z");
    expect(echo.state).toBe("unpaired");
    expect(echo.unpaired).toBe(true);
    expect(echo.spans).toHaveLength(1);
    expect(echo.spans[0]!.end - echo.spans[0]!.start).toBe(FRAME.left.length);
  });

  it("does not search for the closing canary beyond the cap", () => {
    // R exists but far past any plausible expansion of the payload, so it must not be trusted.
    const body = `${FRAME.left}z${"y".repeat(4000)}${FRAME.right}`;
    const { echo } = analyse(body, "z", 100);
    expect(echo.state).toBe("unpaired");
    expect(echo.spans[0]!.end - echo.spans[0]!.start).toBe(FRAME.left.length);
  });

  it("finds a closing canary that is within the cap", () => {
    const body = `${FRAME.left}z${"y".repeat(20)}${FRAME.right}`;
    const { echo } = analyse(body, "z", 100);
    expect(echo.state).toBe("paired");
  });

  it("merges overlapping sites rather than double counting", () => {
    // Overlapping frames are pathological but must not inflate excisedBytes past the body.
    const body = `${FRAME.left}${FRAME.left}z${FRAME.right}`;
    const { echo, bytes } = analyse(body, "z");
    expect(echo.excisedBytes).toBeLessThanOrEqual(bytes.length);
  });
});

describe("transform classification", () => {
  it("recognises a verbatim echo", () => {
    const bits = classifyTransform(ascii("z'z"), ascii("z'z"));
    expect(bits & EchoTransform.VERBATIM).toBeTruthy();
    expect(bits & EchoTransform.RAW_QUOTE).toBeTruthy();
    expect(bits & EchoTransform.SHORTENED).toBe(0);
    expect(bits & EchoTransform.LENGTHENED).toBe(0);
  });

  it("recognises HTML entity encoding", () => {
    const bits = classifyTransform(ascii("z'z"), ascii("z&#39;z"));
    expect(bits & EchoTransform.HTML_ENTITY).toBeTruthy();
    expect(bits & EchoTransform.LENGTHENED).toBeTruthy();
    expect(bits & EchoTransform.RAW_QUOTE).toBe(0);
  });

  it("recognises named entity encoding", () => {
    const bits = classifyTransform(ascii("<z>"), ascii("&lt;z&gt;"));
    expect(bits & EchoTransform.HTML_ENTITY).toBeTruthy();
  });

  it("recognises a doubled backslash, the server escaping our escape", () => {
    const bits = classifyTransform(ascii("\\"), ascii("\\\\"));
    expect(bits & EchoTransform.BACKSLASH_DOUBLED).toBeTruthy();
    expect(bits & EchoTransform.RAW_BACKSLASH).toBeTruthy();
    expect(bits & EchoTransform.LENGTHENED).toBeTruthy();
  });

  it("recognises unicode escaping", () => {
    const bits = classifyTransform(ascii("'"), ascii("\\u0027"));
    expect(bits & EchoTransform.UNICODE_ESCAPED).toBeTruthy();
  });

  it("recognises percent encoding", () => {
    const bits = classifyTransform(ascii("'"), ascii("%27"));
    expect(bits & EchoTransform.URL_ENCODED).toBeTruthy();
  });

  it("recognises stripping", () => {
    const bits = classifyTransform(ascii("z'z"), ascii("zz"));
    expect(bits & EchoTransform.SHORTENED).toBeTruthy();
    expect(bits & EchoTransform.VERBATIM).toBe(0);
  });

  it("does not mistake a bare percent or ampersand for encoding", () => {
    const bits = classifyTransform(ascii("100% & more"), ascii("100% & more"));
    expect(bits & EchoTransform.URL_ENCODED).toBe(0);
    expect(bits & EchoTransform.HTML_ENTITY).toBe(0);
    expect(bits & EchoTransform.VERBATIM).toBeTruthy();
  });

  it("handles an empty echo", () => {
    const bits = classifyTransform(ascii("z'z"), ascii(""));
    expect(bits & EchoTransform.SHORTENED).toBeTruthy();
  });
});

describe("excision applied to the feature scan", () => {
  /**
   * The load-bearing case. A break payload and its escape differ in punctuation by construction
   * -- straight from the ported catalogue, `,abs(0,1)` against `,abs(1)`. On a reflecting
   * parameter their own commas separate the arms in every single send. Excision is what removes
   * that, and without it no statistical machinery can help, because the difference is real.
   */
  const template = (payload: string) =>
    `<html><body><p>results for ${FRAME.left}${payload}${FRAME.right}</p>` +
    `<div class="a">stable content, with a comma</div></body></html>`;

  function featuresFor(payload: string, excise: boolean) {
    const body = template(payload);
    const bytes = ascii(body);
    const echo = locateEcho(bytes, 0, bytes.length, FRAME, { sentPayload: payload });
    return scanBody(bytes, 0, bytes.length, excise ? { excise: echo.spans } : {});
  }

  it("without excision, the payloads' own punctuation separates the arms", () => {
    const brk = featuresFor(",abs(0,1)", false);
    const esc = featuresFor(",abs(1)", false);
    // Both a comma count and a length difference, entirely attributable to the payloads.
    expect(brk.commas).not.toBe(esc.commas);
    expect(brk.bodyLength).not.toBe(esc.bodyLength);
  });

  it("with excision, the structural features are identical", () => {
    const brk = featuresFor(",abs(0,1)", true);
    const esc = featuresFor(",abs(1)", true);
    expect(brk.commas).toBe(esc.commas);
    expect(brk.quotes).toBe(esc.quotes);
    expect(brk.tags).toBe(esc.tags);
    expect(brk.equals).toBe(esc.equals);
    expect(brk.newlines).toBe(esc.newlines);
    expect(brk.tagHash).toBe(esc.tagHash);
    expect(Array.from(brk.keywords)).toEqual(Array.from(esc.keywords));
  });

  it("also neutralises the quote-doubling pair from the delimiter family", () => {
    // DiffingScan's apostrophe probe: z\'z against z''z.
    const brk = featuresFor("z\\'z", true);
    const esc = featuresFor("z''z", true);
    expect(brk.quotes).toBe(esc.quotes);
    expect(Array.from(brk.keywords)).toEqual(Array.from(esc.keywords));
  });

  it("still sees a genuine difference outside the excised span", () => {
    // The whole point: excision must remove the artefact without blinding the detector. Here the
    // server leaks an error into the page body, outside the reflection.
    const bodyBreak =
      `<html><body><p>results for ${FRAME.left}z'z${FRAME.right}</p>` +
      `<div>You have an error in your SQL syntax</div></body></html>`;
    const bodyEscape =
      `<html><body><p>results for ${FRAME.left}z''z${FRAME.right}</p>` +
      `<div class="a">stable content</div></body></html>`;

    const bb = ascii(bodyBreak);
    const be = ascii(bodyEscape);
    const eb = locateEcho(bb, 0, bb.length, FRAME, { sentPayload: "z'z" });
    const ee = locateEcho(be, 0, be.length, FRAME, { sentPayload: "z''z" });
    const brk = scanBody(bb, 0, bb.length, { excise: eb.spans });
    const esc = scanBody(be, 0, be.length, { excise: ee.spans });

    const errorIndex = 0; // "error" is the first keyword
    expect(brk.keywords[errorIndex]).toBeGreaterThan(0);
    expect(esc.keywords[errorIndex]).toBe(0);
  });

  it("does not manufacture a keyword match across an excised span", () => {
    // Text either side of the reflection must not be stitched together. Here "err" precedes the
    // echo and "or" follows it; concatenated they would spell a keyword.
    const body = `err${FRAME.left}z${FRAME.right}or`;
    const bytes = ascii(body);
    const echo = locateEcho(bytes, 0, bytes.length, FRAME, { sentPayload: "z" });
    const scan = scanBody(bytes, 0, bytes.length, { excise: echo.spans });
    expect(scan.keywords[0]).toBe(0);
  });

  it("reports how many bytes were excised", () => {
    const payload = ",abs(0,1)";
    const body = template(payload);
    const bytes = ascii(body);
    const echo = locateEcho(bytes, 0, bytes.length, FRAME, { sentPayload: payload });
    const scan = scanBody(bytes, 0, bytes.length, { excise: echo.spans });
    const expected = FRAME.left.length + payload.length + FRAME.right.length;
    expect(scan.excisedBytes).toBe(expected);
    expect(scan.scannedBytes).toBe(bytes.length - expected);
    expect(scan.bodyLength).toBe(bytes.length);
  });

  it("leaves the scan unchanged when there is nothing to excise", () => {
    const bytes = ascii("<p>no reflection</p>");
    const plain = scanBody(bytes, 0, bytes.length);
    const withEmpty = scanBody(bytes, 0, bytes.length, { excise: [] });
    expect(withEmpty).toEqual(plain);
    expect(plain.excisedBytes).toBe(0);
  });

  it("interacts correctly with head and tail capping", () => {
    // An excised span inside the head window must reduce scanned bytes, not shift the windows.
    const payload = "z'z";
    const filler = "y".repeat(4096);
    const body = `${filler}${FRAME.left}${payload}${FRAME.right}${filler}`;
    const bytes = ascii(body);
    const echo = locateEcho(bytes, 0, bytes.length, FRAME, { sentPayload: payload });
    const scan = scanBody(bytes, 0, bytes.length, { capBytes: 1024, excise: echo.spans });
    expect(scan.truncated).toBe(true);
    // The reflection sits in the elided middle, so nothing inside the windows is excised.
    expect(scan.excisedBytes).toBe(0);
    expect(scan.scannedBytes).toBe(1024);
  });
});
