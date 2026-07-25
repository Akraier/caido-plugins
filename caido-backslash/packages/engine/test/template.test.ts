import { describe, expect, it } from "vitest";

import {
  MalformedRequestError,
  asciiBytes,
  assemble,
  findHeader,
  headerValue,
  locate,
  sliceText,
} from "../src/request/template.ts";

const text = (bytes: Uint8Array): string => {
  let out = "";
  for (const b of bytes) out += String.fromCharCode(b);
  return out;
};

const GET = ["GET /a/b?q=1&r=2 HTTP/1.1", "Host: example.test", "Accept: */*", "", ""].join(
  "\r\n",
);

const POST = [
  "POST /submit HTTP/1.1",
  "Host: example.test",
  "Content-Type: application/x-www-form-urlencoded",
  "Content-Length: 7",
  "",
  "a=1&b=2",
].join("\r\n");

describe("locating structure", () => {
  it("finds the request line parts", () => {
    const t = locate(asciiBytes(GET));
    expect(sliceText(t.raw, t.methodRange)).toBe("GET");
    expect(sliceText(t.raw, t.targetRange)).toBe("/a/b?q=1&r=2");
    expect(sliceText(t.raw, t.versionRange)).toBe("HTTP/1.1");
    expect(t.eol).toBe("crlf");
  });

  it("finds headers with values trimmed of optional whitespace but otherwise intact", () => {
    const t = locate(asciiBytes(GET));
    expect(t.headers.map((h) => h.name)).toEqual(["host", "accept"]);
    expect(headerValue(t, "Host")).toBe("example.test");
    expect(headerValue(t, "HOST")).toBe("example.test");
  });

  it("locates the body", () => {
    const t = locate(asciiBytes(POST));
    expect(sliceText(t.raw, t.bodyRange)).toBe("a=1&b=2");
    expect(t.bodyRestriction).toBeUndefined();
  });

  it("reports no body for a GET", () => {
    const t = locate(asciiBytes(GET));
    expect(t.bodyRange.start).toBe(t.bodyRange.end);
    expect(t.bodyRestriction).toBe("no-body");
  });

  it("handles bare LF line endings without rewriting them", () => {
    // Verified defect V9: the library alternative turned a 67-byte LF-only request into 69 bytes.
    const lf = "POST /x HTTP/1.1\nHost: h\nContent-Length: 3\n\nabc";
    const t = locate(asciiBytes(lf));
    expect(t.eol).toBe("lf");
    expect(sliceText(t.raw, t.bodyRange)).toBe("abc");
    // Round trip with no edits must be byte-identical.
    expect(text(assemble(t, []))).toBe(lf);
  });

  it("keeps a raw space inside the request target instead of truncating at it", () => {
    // Verified defect V4: getQuery on "?q=hello world&next=1" returned "q=hello", silently
    // discarding a parameter and most of any payload placed there.
    const raw = "GET /s?q=hello world&next=1 HTTP/1.1\r\nHost: h\r\n\r\n";
    const t = locate(asciiBytes(raw));
    expect(sliceText(t.raw, t.targetRange)).toBe("/s?q=hello world&next=1");
    expect(sliceText(t.raw, t.versionRange)).toBe("HTTP/1.1");
  });

  it("does not treat a whitespace-only line as the end of the head", () => {
    // Verified defect V2: a whitespace-only fold line made body location wrong by two bytes and
    // made Content-Type lookup return null.
    const raw = "POST /x HTTP/1.1\r\nHost: h\r\n \r\nContent-Type: text/plain\r\n\r\nbody";
    const t = locate(asciiBytes(raw));
    expect(headerValue(t, "content-type")).toBe("text/plain");
    expect(sliceText(t.raw, t.bodyRange)).toBe("body");
  });

  it("preserves an embedded lone CR rather than normalising it", () => {
    // Verified defect V1: "a\r\r\nb" did not round-trip.
    const raw = "POST /x HTTP/1.1\r\nHost: h\r\nX-Odd: a\r\r\nContent-Length: 1\r\n\r\nb";
    const t = locate(asciiBytes(raw));
    expect(text(assemble(t, []))).toBe(raw);
  });

  it("keeps a folded header as one field and records the fold", () => {
    const raw = "GET / HTTP/1.1\r\nHost: h\r\nX-Long: one\r\n  two\r\n\r\n";
    const t = locate(asciiBytes(raw));
    const field = findHeader(t.headers, "x-long");
    expect(field?.folded).toBe(true);
    expect(sliceText(t.raw, field!.valueRange)).toBe("one\r\n  two");
    expect(t.headers.map((h) => h.name)).toEqual(["host", "x-long"]);
  });

  it("retains a header line with no colon rather than dropping it", () => {
    const raw = "GET / HTTP/1.1\r\nHost: h\r\nGarbage\r\n\r\n";
    const t = locate(asciiBytes(raw));
    expect(t.headers.map((h) => h.name)).toEqual(["host", "garbage"]);
    expect(sliceText(t.raw, findHeader(t.headers, "garbage")!.valueRange)).toBe("");
  });

  it("handles a head that ends without a blank line", () => {
    const raw = "GET / HTTP/1.1\r\nHost: h";
    const t = locate(asciiBytes(raw));
    expect(headerValue(t, "host")).toBe("h");
    expect(t.bodyRange.start).toBe(raw.length);
  });

  it("handles binary body bytes without corruption", () => {
    const head = asciiBytes("POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\n");
    const body = new Uint8Array([0x41, 0xff, 0xfe, 0x00]);
    const raw = new Uint8Array(head.length + body.length);
    raw.set(head);
    raw.set(body, head.length);
    const t = locate(raw);
    expect(Array.from(raw.subarray(t.bodyRange.start, t.bodyRange.end))).toEqual([
      0x41, 0xff, 0xfe, 0x00,
    ]);
    expect(Array.from(assemble(t, []))).toEqual(Array.from(raw));
  });

  it("rejects genuinely unusable input", () => {
    expect(() => locate(new Uint8Array(0))).toThrow(MalformedRequestError);
    expect(() => locate(asciiBytes("GET / HTTP/1.1"))).toThrow(MalformedRequestError);
    expect(() => locate(asciiBytes(" /x HTTP/1.1\r\n\r\n"))).toThrow(MalformedRequestError);
  });
});

describe("body restrictions are named, never silent", () => {
  it("refuses body splicing on a chunked request", () => {
    const raw =
      "POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    expect(locate(asciiBytes(raw)).bodyRestriction).toBe("chunked");
  });

  it("refuses body splicing on a content-encoded request", () => {
    const raw = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nxy";
    expect(locate(asciiBytes(raw)).bodyRestriction).toBe("content-encoded");
  });

  it("is case-insensitive about chunked", () => {
    const raw = "POST /x HTTP/1.1\r\nHost: h\r\nTRANSFER-ENCODING: Chunked\r\n\r\n0\r\n\r\n";
    expect(locate(asciiBytes(raw)).bodyRestriction).toBe("chunked");
  });
});

describe("assembly is byte-exact outside the edit", () => {
  it("round-trips with no edits", () => {
    for (const raw of [GET, POST]) {
      expect(text(assemble(locate(asciiBytes(raw)), []))).toBe(raw);
    }
  });

  it("replaces a query value and leaves everything else untouched", () => {
    const t = locate(asciiBytes(GET));
    // The value of q is at a known offset; find it rather than hardcoding.
    const target = sliceText(t.raw, t.targetRange);
    const at = t.targetRange.start + target.indexOf("1");
    const out = assemble(t, [{ range: { start: at, end: at + 1 }, bytes: asciiBytes("z'z\\") }]);
    expect(text(out)).toBe("GET /a/b?q=z'z\\&r=2 HTTP/1.1\r\nHost: example.test\r\nAccept: */*\r\n\r\n");
  });

  it("delivers hostile payload bytes verbatim", () => {
    const t = locate(asciiBytes(GET));
    const target = sliceText(t.raw, t.targetRange);
    const at = t.targetRange.start + target.indexOf("1");
    const payload = new Uint8Array([0x5c, 0x27, 0x22, 0x60, 0x00, 0x25, 0x33, 0x63, 0x0d]);
    const out = assemble(t, [{ range: { start: at, end: at + 1 }, bytes: payload }]);
    const idx = at;
    expect(Array.from(out.subarray(idx, idx + payload.length))).toEqual(Array.from(payload));
  });

  it("patches Content-Length when the body grows", () => {
    const t = locate(asciiBytes(POST));
    const bodyText = sliceText(t.raw, t.bodyRange);
    const at = t.bodyRange.start + bodyText.indexOf("1");
    const out = assemble(t, [
      { range: { start: at, end: at + 1 }, bytes: asciiBytes("longer-value") },
    ]);
    const rebuilt = locate(out);
    expect(headerValue(rebuilt, "content-length")).toBe("18");
    expect(sliceText(rebuilt.raw, rebuilt.bodyRange)).toBe("a=longer-value&b=2");
    expect(sliceText(rebuilt.raw, rebuilt.bodyRange).length).toBe(18);
  });

  it("patches Content-Length when the body shrinks", () => {
    const t = locate(asciiBytes(POST));
    const out = assemble(t, [{ range: t.bodyRange, bytes: asciiBytes("x") }]);
    const rebuilt = locate(out);
    expect(headerValue(rebuilt, "content-length")).toBe("1");
  });

  it("does not patch Content-Length for an edit outside the body", () => {
    const t = locate(asciiBytes(POST));
    const host = findHeader(t.headers, "host")!;
    const out = assemble(t, [{ range: host.valueRange, bytes: asciiBytes("other.test") }]);
    expect(headerValue(locate(out), "content-length")).toBe("7");
  });

  it("patches Content-Length correctly when an earlier edit shifted it", () => {
    // The Content-Length value moves when a preceding header is edited, so the patch target must
    // be shifted by the net delta of edits before it.
    const t = locate(asciiBytes(POST));
    const host = findHeader(t.headers, "host")!;
    const out = assemble(t, [
      { range: host.valueRange, bytes: asciiBytes("a-much-longer-hostname.test") },
      { range: t.bodyRange, bytes: asciiBytes("a=1&b=2&c=3") },
    ]);
    const rebuilt = locate(out);
    expect(headerValue(rebuilt, "host")).toBe("a-much-longer-hostname.test");
    expect(headerValue(rebuilt, "content-length")).toBe("11");
    expect(sliceText(rebuilt.raw, rebuilt.bodyRange)).toBe("a=1&b=2&c=3");
  });

  it("can be told not to patch Content-Length, which is a probe in its own right", () => {
    const t = locate(asciiBytes(POST));
    const out = assemble(t, [{ range: t.bodyRange, bytes: asciiBytes("a=1&b=22") }], {
      patchContentLength: false,
    });
    expect(headerValue(locate(out), "content-length")).toBe("7");
  });

  it("supports a zero-width insertion, used for new headers and path suffixes", () => {
    const t = locate(asciiBytes(GET));
    const at = t.bodyStart - 2; // just before the final CRLF of the head
    const out = assemble(t, [
      { range: { start: at, end: at }, bytes: asciiBytes("X-Probe: 1\r\n") },
    ]);
    const rebuilt = locate(out);
    expect(headerValue(rebuilt, "x-probe")).toBe("1");
    expect(rebuilt.headers.map((h) => h.name)).toEqual(["host", "accept", "x-probe"]);
  });

  it("applies two disjoint edits in one pass", () => {
    const t = locate(asciiBytes(POST));
    const host = findHeader(t.headers, "host")!;
    const out = assemble(t, [
      { range: t.bodyRange, bytes: asciiBytes("z=9") },
      { range: host.valueRange, bytes: asciiBytes("h2") },
    ]);
    const rebuilt = locate(out);
    expect(headerValue(rebuilt, "host")).toBe("h2");
    expect(sliceText(rebuilt.raw, rebuilt.bodyRange)).toBe("z=9");
  });

  it("rejects overlapping edits rather than producing silent garbage", () => {
    const t = locate(asciiBytes(POST));
    expect(() =>
      assemble(t, [
        { range: { start: 10, end: 20 }, bytes: asciiBytes("x") },
        { range: { start: 15, end: 25 }, bytes: asciiBytes("y") },
      ]),
    ).toThrow(/overlapping/);
  });

  it("rejects an out-of-bounds or inverted edit", () => {
    const t = locate(asciiBytes(POST));
    expect(() =>
      assemble(t, [{ range: { start: 0, end: t.raw.length + 1 }, bytes: asciiBytes("x") }]),
    ).toThrow(/out of bounds/);
    expect(() =>
      assemble(t, [{ range: { start: 10, end: 5 }, bytes: asciiBytes("x") }]),
    ).toThrow(/inverted/);
  });

  it("keeps the two arms byte-identical outside the slot, which the permutation null requires", () => {
    const t = locate(asciiBytes(GET));
    const target = sliceText(t.raw, t.targetRange);
    const at = t.targetRange.start + target.indexOf("1");
    const slot = { start: at, end: at + 1 };
    const brk = assemble(t, [{ range: slot, bytes: asciiBytes(",abs(0,1)") }]);
    const esc = assemble(t, [{ range: slot, bytes: asciiBytes(",abs(1)") }]);

    // Prefixes identical up to the slot.
    expect(Array.from(brk.subarray(0, at))).toEqual(Array.from(esc.subarray(0, at)));
    // Suffixes identical after their respective payloads.
    expect(text(brk.subarray(at + ",abs(0,1)".length))).toBe(
      text(esc.subarray(at + ",abs(1)".length)),
    );
  });
});
