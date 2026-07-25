import { describe, expect, it } from "vitest";

import { type JsonSite, scanJson } from "../src/request/json.ts";
import { asciiBytes } from "../src/request/template.ts";

function scan(document: string) {
  const bytes = asciiBytes(document);
  const result = scanJson(bytes, 0, bytes.length);
  return {
    ...result,
    text: (site: JsonSite) => document.slice(site.range.start, site.range.end),
    token: (site: JsonSite) => document.slice(site.tokenRange.start, site.tokenRange.end),
  };
}

function pointers(document: string, kind?: string): string[] {
  const r = scan(document);
  return r.sites.filter((s) => kind === undefined || s.kind === kind).map((s) => s.pointer);
}

describe("locating scalar sites", () => {
  it("finds a flat object's values and keys", () => {
    const r = scan('{"a":"x","b":7,"c":true,"d":null}');
    expect(r.error).toBeUndefined();
    const values = r.sites.filter((s) => s.kind !== "key");
    expect(values.map((s) => s.pointer)).toEqual(["/a", "/b", "/c", "/d"]);
    expect(values.map((s) => s.kind)).toEqual(["string", "number", "bool", "null"]);
    expect(values.map((s) => r.text(s))).toEqual(["x", "7", "true", "null"]);
  });

  it("gives a string's interior for injection and its token for raw-span mode", () => {
    const r = scan('{"a":"hello"}');
    const site = r.sites.find((s) => s.kind === "string")!;
    expect(r.text(site)).toBe("hello");
    expect(r.token(site)).toBe('"hello"');
  });

  it("finds keys as separate sites", () => {
    const r = scan('{"name":"v"}');
    const key = r.sites.find((s) => s.kind === "key")!;
    expect(r.text(key)).toBe("name");
    expect(r.token(key)).toBe('"name"');
  });

  it("descends into nested objects and arrays", () => {
    const doc = '{"a":{"b":[1,2,{"c":"z"}]}}';
    expect(pointers(doc, "string")).toEqual(["/a/b/2/c"]);
    expect(pointers(doc, "number")).toEqual(["/a/b/0", "/a/b/1"]);
  });

  it("handles a top-level array", () => {
    expect(pointers("[1,2,3]", "number")).toEqual(["/0", "/1", "/2"]);
  });

  it("handles a top-level scalar", () => {
    const r = scan('"just a string"');
    expect(r.error).toBeUndefined();
    expect(r.sites).toHaveLength(1);
    expect(r.sites[0]!.pointer).toBe("");
  });

  it("records nesting depth", () => {
    const r = scan('{"a":{"b":1}}');
    const number = r.sites.find((s) => s.kind === "number")!;
    expect(number.depth).toBe(2);
  });
});

describe("cases that break a parse-and-reserialise approach", () => {
  it("keeps duplicate keys as distinct sites", () => {
    // JSON.parse collapses these to one. A duplicate key is a distinct injectable site, and
    // collapsing them silently drops one.
    const doc = '{"a":1,"a":2}';
    expect(pointers(doc, "number")).toEqual(["/a", "/a#1"]);
  });

  it("does not renumber or reorder integer-like keys", () => {
    // JSON.parse followed by stringify reorders int-like keys, which would change the request in a
    // way unrelated to the payload.
    expect(pointers('{"2":"b","1":"a"}', "string")).toEqual(["/2", "/1"]);
  });

  it("preserves a number's exact spelling", () => {
    // A round trip turns 1.0 into 1 and truncates a 20-digit integer. The raw span keeps both.
    const r = scan('{"a":1.0,"b":99999999999999999999,"c":1e10,"d":-0.5E-3}');
    expect(r.sites.filter((s) => s.kind === "number").map((s) => r.text(s))).toEqual([
      "1.0",
      "99999999999999999999",
      "1e10",
      "-0.5E-3",
    ]);
  });

  it("does not interpret escapes inside a string", () => {
    // The interior is handed over as raw bytes, so \\u0041 stays \\u0041 rather than becoming A.
    const r = scan('{"a":"x\\u0041y\\"z"}');
    const site = r.sites.find((s) => s.kind === "string")!;
    expect(r.text(site)).toBe('x\\u0041y\\"z');
  });

  it("is not confused by a quote inside an escaped sequence", () => {
    const r = scan('{"a":"he said \\"hi\\"","b":2}');
    expect(r.error).toBeUndefined();
    expect(r.sites.filter((s) => s.kind === "number").map((s) => s.pointer)).toEqual(["/b"]);
  });

  it("is not confused by a brace or bracket inside a string", () => {
    const r = scan('{"a":"{[}]","b":1}');
    expect(r.error).toBeUndefined();
    expect(pointers('{"a":"{[}]","b":1}', "number")).toEqual(["/b"]);
  });

  it("escapes a slash in a key so it cannot forge a pointer boundary", () => {
    expect(pointers('{"a/b":1}', "number")).toEqual(["/a~1b"]);
    expect(pointers('{"a~b":1}', "number")).toEqual(["/a~0b"]);
  });
});

describe("whitespace and formatting", () => {
  it("ignores insignificant whitespace but keeps ranges exact", () => {
    const doc = '{\n  "a" : "x" ,\n  "b" : 2\n}';
    const r = scan(doc);
    expect(r.error).toBeUndefined();
    const string = r.sites.find((s) => s.kind === "string")!;
    expect(r.text(string)).toBe("x");
    expect(doc.slice(string.tokenRange.start, string.tokenRange.end)).toBe('"x"');
  });

  it("handles an empty object and an empty array", () => {
    expect(scan("{}").error).toBeUndefined();
    expect(scan("{}").sites).toHaveLength(0);
    expect(scan("[]").sites).toHaveLength(0);
    expect(scan('{"a":{},"b":[]}').error).toBeUndefined();
  });

  it("handles an empty string value, which is still an injectable site", () => {
    const r = scan('{"a":""}');
    const site = r.sites.find((s) => s.kind === "string")!;
    expect(site.range.start).toBe(site.range.end);
    expect(r.text(site)).toBe("");
  });

  it("handles deeply nested arrays", () => {
    expect(pointers("[[[[1]]]]", "number")).toEqual(["/0/0/0/0"]);
  });

  it("handles an array of objects", () => {
    expect(pointers('[{"a":1},{"a":2}]', "number")).toEqual(["/0/a", "/1/a"]);
  });
});

describe("malformed input is reported, not guessed at", () => {
  it("reports an unterminated string", () => {
    expect(scan('{"a":"oops').error).toMatch(/unterminated string/);
  });

  it("reports a missing colon", () => {
    expect(scan('{"a" 1}').error).toMatch(/expected a colon/);
  });

  it("reports an unexpected byte", () => {
    expect(scan('{"a":@}').error).toMatch(/unexpected byte/);
  });

  it("reports an empty document", () => {
    expect(scan("").error).toMatch(/empty document/);
    expect(scan("   ").error).toMatch(/empty document/);
  });

  it("reports truncation", () => {
    expect(scan('{"a":1').error).toMatch(/unexpected end/);
  });

  it("returns the sites found before failing, so a partial document is still useful", () => {
    const r = scan('{"a":1,"b":"unterminated');
    expect(r.error).toBeDefined();
    expect(r.sites.some((s) => s.pointer === "/a")).toBe(true);
  });

  it("bounds nesting depth rather than exhausting the stack", () => {
    const deep = "[".repeat(200) + "1" + "]".repeat(200);
    const r = scan(deep);
    expect(r.error).toMatch(/nesting depth/);
  });
});

describe("realistic request bodies", () => {
  it("handles a typical API payload", () => {
    const doc = JSON.stringify({
      user: { id: 42, name: "alice", roles: ["admin", "user"], active: true },
      filter: { q: "search term", limit: 10, cursor: null },
    });
    const r = scan(doc);
    expect(r.error).toBeUndefined();
    const numbers = r.sites.filter((s) => s.kind === "number").map((s) => s.pointer);
    // The integer contexts, which is where blind SQL injection hides.
    expect(numbers).toEqual(["/user/id", "/filter/limit"]);
    const strings = r.sites.filter((s) => s.kind === "string").map((s) => s.pointer);
    expect(strings).toEqual([
      "/user/name",
      "/user/roles/0",
      "/user/roles/1",
      "/filter/q",
    ]);
  });

  it("scans a sub-range, so it works on a body inside a larger buffer", () => {
    const prefix = "POST /x HTTP/1.1\r\nHost: h\r\n\r\n";
    const body = '{"a":1}';
    const bytes = asciiBytes(prefix + body);
    const r = scanJson(bytes, prefix.length, bytes.length);
    expect(r.error).toBeUndefined();
    expect(r.sites).toHaveLength(2);
    const number = r.sites.find((s) => s.kind === "number")!;
    expect(number.range.start).toBe(prefix.length + 5);
  });
});
