import { describe, expect, it } from "vitest";

import {
  CTL_ONLY,
  COOKIE_VALUE_CODEC,
  IDENTITY,
  JSON_ESCAPE,
  PATH_SEGMENT_CODEC,
  QUERY_VALUE_CODEC,
  encodePair,
} from "../src/request/codecs.ts";
import { enumerateSlots, looksPositional } from "../src/request/slots.ts";
import { asciiBytes, assemble, locate, sliceText } from "../src/request/template.ts";
import { ALL_STATIC_PROBES } from "../src/probes/catalogue.ts";

const bytes = asciiBytes;
const str = (u: Uint8Array): string => {
  let out = "";
  for (const b of u) out += String.fromCharCode(b);
  return out;
};

function enc(codec: typeof QUERY_VALUE_CODEC, payload: string): string {
  const result = codec.encode(bytes(payload), "literal");
  if (!result.ok) throw new Error(`refused: ${result.reason}`);
  return str(result.bytes);
}

describe("query codec encodes the minimum that survives the container", () => {
  it("leaves the metacharacters the technique depends on untouched", () => {
    // These are the payload bytes that carry meaning. Encoding any of them would defeat the probe.
    expect(enc(QUERY_VALUE_CODEC, "z'z")).toBe("z'z");
    expect(enc(QUERY_VALUE_CODEC, "\\")).toBe("\\");
    expect(enc(QUERY_VALUE_CODEC, '"')).toBe('"');
    expect(enc(QUERY_VALUE_CODEC, "`")).toBe("`");
    expect(enc(QUERY_VALUE_CODEC, "${{")).toBe("${{");
    expect(enc(QUERY_VALUE_CODEC, "/*z'*/")).toBe("/*z'*/");
    expect(enc(QUERY_VALUE_CODEC, "../")).toBe("../");
  });

  it("encodes the separators that would otherwise split the parameter", () => {
    expect(enc(QUERY_VALUE_CODEC, "a&b")).toBe("a%26b");
    expect(enc(QUERY_VALUE_CODEC, "a#b")).toBe("a%23b");
    expect(enc(QUERY_VALUE_CODEC, "a b")).toBe("a%20b");
  });

  it("encodes + so it stays distinguishable from a space", () => {
    // The catalogue tries both "+" and " " as concatenation operators. On a query surface a raw +
    // decodes to a space, so without this they arrive identically: a wasted probe pair and a lost
    // ability to say which operator worked.
    expect(enc(QUERY_VALUE_CODEC, "+")).toBe("%2B");
    expect(enc(QUERY_VALUE_CODEC, " ")).toBe("%20");
    expect(enc(QUERY_VALUE_CODEC, "+")).not.toBe(enc(QUERY_VALUE_CODEC, " "));
  });

  it("encodes a literal percent so it is not read as an escape", () => {
    expect(enc(QUERY_VALUE_CODEC, "100%")).toBe("100%25");
  });

  it("passes a pre-encoded payload through untouched", () => {
    // The parameter-pollution family's payloads are already wire-form. Encoding them again yields
    // %253c, a verified defect that silently destroys the family.
    const payload = "%3c%61%60%27%22%24%7b%7b%5c";
    const result = QUERY_VALUE_CODEC.encode(bytes(payload), "pre-encoded");
    expect(result.ok).toBe(true);
    if (result.ok) expect(str(result.bytes)).toBe(payload);
  });

  it("still refuses a raw control byte inside a pre-encoded payload", () => {
    const result = QUERY_VALUE_CODEC.encode(bytes("a\r\nb"), "pre-encoded");
    expect(result.ok).toBe(false);
  });

  it("encodes NUL, CR and LF", () => {
    expect(enc(QUERY_VALUE_CODEC, "\x00")).toBe("%00");
    expect(enc(QUERY_VALUE_CODEC, "\r\n")).toBe("%0D%0A");
  });
});

describe("path codec keeps the traversal family intact", () => {
  it("does not encode the separator or dots", () => {
    // Encoding / turns ../ into ..%2F, which is a different test and neuters the family.
    expect(enc(PATH_SEGMENT_CODEC, "../")).toBe("../");
    expect(enc(PATH_SEGMENT_CODEC, "..;/")).toBe("..;/");
    expect(enc(PATH_SEGMENT_CODEC, "x/../xyz")).toBe("x/../xyz");
    expect(enc(PATH_SEGMENT_CODEC, "./cow/../")).toBe("./cow/../");
  });

  it("encodes what would end the path early", () => {
    expect(enc(PATH_SEGMENT_CODEC, "a?b")).toBe("a%3Fb");
    expect(enc(PATH_SEGMENT_CODEC, "a b")).toBe("a%20b");
  });
});

describe("cookie codec", () => {
  it("encodes the crumb separators", () => {
    expect(enc(COOKIE_VALUE_CODEC, "a;b")).toBe("a%3Bb");
    expect(enc(COOKIE_VALUE_CODEC, "a,b")).toBe("a%2Cb");
    expect(enc(COOKIE_VALUE_CODEC, "a b")).toBe("a%20b");
  });

  it("leaves quotes and backslashes alone", () => {
    expect(enc(COOKIE_VALUE_CODEC, "z'z\\")).toBe("z'z\\");
  });
});

describe("header codec refuses rather than mangles", () => {
  it("passes through anything a header can carry", () => {
    const result = CTL_ONLY.encode(bytes("z'z\\`${{"), "literal");
    expect(result.ok).toBe(true);
  });

  it("refuses CR, LF and NUL with a named reason and an offset", () => {
    for (const payload of ["a\rb", "a\nb", "a\x00b"]) {
      const result = CTL_ONLY.encode(bytes(payload), "literal");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe("undeliverable-control-byte");
        expect(result.detail).toMatch(/offset 1/);
      }
    }
  });
});

describe("json escape reaches the interpreter behind the parser", () => {
  it("escapes only what the grammar requires", () => {
    expect(str((JSON_ESCAPE.encode(bytes("z'z"), "literal") as { bytes: Uint8Array }).bytes)).toBe(
      "z'z",
    );
    expect(str((JSON_ESCAPE.encode(bytes('a"b'), "literal") as { bytes: Uint8Array }).bytes)).toBe(
      'a\\"b',
    );
    expect(str((JSON_ESCAPE.encode(bytes("a\\b"), "literal") as { bytes: Uint8Array }).bytes)).toBe(
      "a\\\\b",
    );
  });

  it("escapes control bytes as \\u sequences", () => {
    const out = str((JSON_ESCAPE.encode(bytes("a\x01b"), "literal") as { bytes: Uint8Array }).bytes);
    expect(out).toBe("a\\u0001b");
  });
});

describe("both arms take the identical code path", () => {
  it("encodes a pair with one codec and refuses as a whole", () => {
    const ok = encodePair(QUERY_VALUE_CODEC, bytes(",abs(0,1)"), bytes(",abs(1)"));
    expect(ok.ok).toBe(true);

    // If either arm is undeliverable the pair is refused, because running one arm alone compares a
    // payload against nothing.
    const refused = encodePair(CTL_ONLY, bytes("a\nb"), bytes("ab"));
    expect(refused.ok).toBe(false);
    const refusedOther = encodePair(CTL_ONLY, bytes("ab"), bytes("a\nb"));
    expect(refusedOther.ok).toBe(false);
  });

  it("every catalogue pair is either deliverable on a query surface or refused symmetrically", () => {
    // Build-time matrix: no probe may be half-deliverable.
    for (const probe of ALL_STATIC_PROBES) {
      for (const brk of probe.breaks) {
        for (const set of probe.escapeSets) {
          for (const esc of set) {
            const result = encodePair(QUERY_VALUE_CODEC, bytes(brk), bytes(esc));
            expect(result.ok, `${probe.id}: ${brk} vs ${esc}`).toBe(true);
          }
        }
      }
    }
  });

  it("identity codec is byte-exact for every catalogue payload", () => {
    for (const probe of ALL_STATIC_PROBES) {
      for (const brk of probe.breaks) {
        const result = IDENTITY.encode(bytes(brk), "literal");
        expect(result.ok).toBe(true);
        if (result.ok) expect(str(result.bytes)).toBe(brk);
      }
    }
  });
});

const REQUEST = [
  "POST /api/v1/items/42?q=hello&sort=asc HTTP/1.1",
  "Host: example.test",
  "Cookie: sid=abc123; theme=dark",
  "User-Agent: probe/1",
  "Authorization: Bearer xyz",
  "Content-Type: application/x-www-form-urlencoded",
  "Content-Length: 11",
  "",
  "name=v&id=7",
].join("\r\n");

describe("slot enumeration", () => {
  const template = locate(bytes(REQUEST));
  const { slots, deferred } = enumerateSlots(template);

  it("finds query values", () => {
    const q = slots.filter((s) => s.kind === "query-value");
    expect(q.map((s) => s.name)).toEqual(["q", "sort"]);
    expect(q.map((s) => s.baseValue)).toEqual(["hello", "asc"]);
  });

  it("finds urlencoded body values", () => {
    const body = slots.filter((s) => s.kind === "form-value");
    expect(body.map((s) => s.name)).toEqual(["name", "id"]);
    expect(body.map((s) => s.baseValue)).toEqual(["v", "7"]);
  });

  it("finds cookie crumbs individually", () => {
    const cookies = slots.filter((s) => s.kind === "cookie-value");
    expect(cookies.map((s) => s.name)).toEqual(["sid", "theme"]);
    expect(cookies.map((s) => s.baseValue)).toEqual(["abc123", "dark"]);
  });

  it("finds path segments and a zero-width suffix", () => {
    const segs = slots.filter((s) => s.kind === "path-segment");
    expect(segs.map((s) => s.baseValue)).toEqual(["api", "v1", "items", "42"]);
    const suffix = slots.find((s) => s.kind === "path-suffix");
    expect(suffix).toBeDefined();
    expect(suffix!.range.start).toBe(suffix!.range.end);
  });

  it("offers ordinary headers but not framing-critical ones", () => {
    const headers = slots.filter((s) => s.kind === "header-value").map((s) => s.name);
    expect(headers).toContain("user-agent");
    for (const forbidden of ["host", "content-length", "cookie", "content-type"]) {
      // content-type is not denied outright, but host/CL/cookie must never appear.
      if (forbidden !== "content-type") expect(headers).not.toContain(forbidden);
    }
  });

  it("defers integrity-protected headers with a reason instead of probing them", () => {
    const headers = slots.filter((s) => s.kind === "header-value").map((s) => s.name);
    expect(headers).not.toContain("authorization");
    const reason = deferred.find((d) => d.kind === "header:authorization");
    expect(reason?.reason).toMatch(/integrity-protected/);
  });

  it("omits parameter-name slots unless asked", () => {
    expect(slots.some((s) => s.kind === "query-name")).toBe(false);
    const withNames = enumerateSlots(template, { includeNames: true });
    expect(withNames.slots.some((s) => s.kind === "query-name")).toBe(true);
  });

  it("offers a new-header insertion slot only when asked", () => {
    expect(slots.some((s) => s.kind === "new-header")).toBe(false);
    const withNew = enumerateSlots(template, { includeNewHeader: true });
    const slot = withNew.slots.find((s) => s.kind === "new-header");
    expect(slot).toBeDefined();
    const out = assemble(template, [
      { range: slot!.range, bytes: bytes("X-Tripwire: 1\r\n") },
    ]);
    expect(sliceText(locate(out).raw, locate(out).targetRange)).toBe(
      "/api/v1/items/42?q=hello&sort=asc",
    );
    expect(locate(out).headers.map((h) => h.name)).toContain("x-tripwire");
  });

  it("marks value-shape-sensitive slots as positional", () => {
    const id = slots.find((s) => s.kind === "form-value" && s.name === "id");
    expect(id?.positional).toBe(true);
    const segment = slots.find((s) => s.kind === "path-segment");
    expect(segment?.positional).toBe(true);
  });

  it("enumerates JSON body surfaces", () => {
    const jsonReq = locate(
      bytes(
        [
          "POST /x HTTP/1.1",
          "Host: h",
          "Content-Type: application/json",
          "Content-Length: 34",
          "",
          '{"q":"term","limit":10,"on":true}',
        ].join("\r\n"),
      ),
    );
    const result = enumerateSlots(jsonReq);
    expect(result.deferred.some((d) => d.kind.startsWith("body:json"))).toBe(false);

    const byKind = (k: string) => result.slots.filter((s) => s.kind === k);
    expect(byKind("json-string").map((s) => s.name)).toEqual(["/q"]);
    expect(byKind("json-string")[0]!.baseValue).toBe("term");
    // The integer context, where blind SQL injection hides.
    expect(byKind("json-number").map((s) => s.baseValue)).toEqual(["10"]);
    expect(byKind("json-number")[0]!.positional).toBe(true);
    expect(byKind("json-bool").map((s) => s.baseValue)).toEqual(["true"]);
  });

  it("offers both JSON modes over the same content", () => {
    const jsonReq = locate(
      bytes(
        ["POST /x HTTP/1.1", "Host: h", "Content-Type: application/json", "", '{"a":"v"}'].join(
          "\r\n",
        ),
      ),
    );
    const slots = enumerateSlots(jsonReq).slots;
    const escaped = slots.find((s) => s.kind === "json-string")!;
    const raw = slots.find((s) => s.kind === "json-raw-span")!;

    // Escaped mode targets the interior; raw mode spans the quotes so it can attack the parser.
    expect(escaped.baseValue).toBe("v");
    expect(raw.baseValue).toBe('"v"');
    expect(escaped.codec.name).toBe("json-escape");
    expect(raw.codec.name).toBe("identity");

    // Raw mode really does produce invalid JSON, which is the point.
    const out = assemble(jsonReq, [{ range: raw.range, bytes: bytes("z'z") }]);
    expect(str(out)).toContain('{"a":z\'z}');
  });

  it("gates JSON key slots behind includeNames", () => {
    const jsonReq = locate(
      bytes(
        ["POST /x HTTP/1.1", "Host: h", "Content-Type: application/json", "", '{"a":1}'].join(
          "\r\n",
        ),
      ),
    );
    expect(enumerateSlots(jsonReq).slots.some((s) => s.kind === "json-key")).toBe(false);
    expect(
      enumerateSlots(jsonReq, { includeNames: true }).slots.some((s) => s.kind === "json-key"),
    ).toBe(true);
  });

  it("treats an unparseable JSON body as opaque with a reason", () => {
    const broken = locate(
      bytes(
        ["POST /x HTTP/1.1", "Host: h", "Content-Type: application/json", "", "@@@not json"].join(
          "\r\n",
        ),
      ),
    );
    const result = enumerateSlots(broken);
    expect(result.deferred.some((d) => d.kind === "body:json")).toBe(true);
    // The URL and header surfaces still work.
    expect(result.slots.some((s) => s.family === "header")).toBe(true);
  });

  it("defers a chunked body but keeps the other families", () => {
    const chunked = locate(
      bytes(
        ["POST /x?a=1 HTTP/1.1", "Host: h", "Transfer-Encoding: chunked", "", "0", "", ""].join(
          "\r\n",
        ),
      ),
    );
    const result = enumerateSlots(chunked);
    expect(result.deferred.some((d) => d.reason.includes("chunked"))).toBe(true);
    expect(result.slots.some((s) => s.kind === "query-value")).toBe(true);
  });

  it("handles a parameter with no equals sign", () => {
    const t = locate(bytes("GET /x?flag&q=1 HTTP/1.1\r\nHost: h\r\n\r\n"));
    const result = enumerateSlots(t);
    const names = result.slots.filter((s) => s.kind === "query-value").map((s) => s.name);
    expect(names).toEqual(["flag", "q"]);
  });

  it("handles an empty query value", () => {
    const t = locate(bytes("GET /x?q= HTTP/1.1\r\nHost: h\r\n\r\n"));
    const slot = enumerateSlots(t).slots.find((s) => s.kind === "query-value");
    expect(slot?.baseValue).toBe("");
    expect(slot?.range.start).toBe(slot?.range.end);
  });

  it("does not confuse a fragment for query content", () => {
    const t = locate(bytes("GET /x?q=1#frag HTTP/1.1\r\nHost: h\r\n\r\n"));
    const slot = enumerateSlots(t).slots.find((s) => s.kind === "query-value");
    expect(slot?.baseValue).toBe("1");
  });

  it("produces slots whose ranges assemble back to the original when unchanged", () => {
    for (const slot of slots) {
      const out = assemble(template, [
        { range: slot.range, bytes: bytes(slot.baseValue) },
      ]);
      expect(str(out), slot.name).toBe(REQUEST);
    }
  });
});

describe("positional heuristic", () => {
  it("treats integers and identifiers as positional", () => {
    for (const value of ["42", "abc", "a.b", "user_id", "v1-2", "a:b", "$x"]) {
      expect(looksPositional(value), value).toBe(true);
    }
  });

  it("does not treat free text or empty values as positional", () => {
    for (const value of ["", "hello world", "a/b", "a=b", "a&b", "<x>"]) {
      expect(looksPositional(value), value).toBe(false);
    }
  });
});
