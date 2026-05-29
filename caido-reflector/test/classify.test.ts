import { test } from "node:test";
import assert from "node:assert/strict";

import { findReflections, classifyHit, isJsonContentType } from "../packages/backend/src/classify";
import { findPassiveHits } from "../packages/backend/src/reflect";
import { extractParams } from "../packages/backend/src/extract";

const MARK = "caidoMARK123";

const FIXTURES: Record<string, { body: string; expected: string }> = {
  body: {
    body: `<html><body><p>Hello ${MARK}</p></body></html>`,
    expected: "HTML_BODY",
  },
  attr_dq: {
    body: `<html><body><input type="text" value="${MARK}"></body></html>`,
    expected: "HTML_ATTR_DQ",
  },
  attr_sq: {
    body: `<html><body><input type='text' value='${MARK}'></body></html>`,
    expected: "HTML_ATTR_SQ",
  },
  attr_unq: {
    body: `<html><body><input type=text value=${MARK}></body></html>`,
    expected: "HTML_ATTR_UNQ",
  },
  js_dq: {
    body: `<html><body><script>var v = "${MARK}";</script></body></html>`,
    expected: "JS_STRING_DQ",
  },
  js_sq: {
    body: `<html><body><script>var v = '${MARK}';</script></body></html>`,
    expected: "JS_STRING_SQ",
  },
  js_tpl: {
    body: "<html><body><script>var v = `" + MARK + "`;</script></body></html>",
    expected: "JS_TEMPLATE",
  },
  js_code: {
    body: `<html><body><script>var v = ${MARK};</script></body></html>`,
    expected: "JS_CODE",
  },
  href: {
    body: `<html><body><a href="https://${MARK}.example">x</a></body></html>`,
    expected: "URL_ATTR_DQ",
  },
  comment: {
    body: `<html><body><!-- debug: ${MARK} --></body></html>`,
    expected: "HTML_COMMENT",
  },
  css: {
    body: `<html><head><style>.x{ color: ${MARK}; }</style></head><body></body></html>`,
    expected: "CSS_BLOCK",
  },
};

for (const [name, fx] of Object.entries(FIXTURES)) {
  test(`classifies ${name} correctly`, () => {
    const refs = findReflections(fx.body, MARK);
    assert.ok(refs.length > 0, `expected ≥1 reflection in ${name}`);
    assert.equal(refs[0]!.context, fx.expected);
  });
}

test("negative control: HTML-escaped body produces no raw reflection of `<>\"'`", () => {
  const html = "<html><body><p>Hello &lt;script&gt;alert(1)&lt;/script&gt;</p></body></html>";
  const refs = findReflections(html, "<script>alert(1)</script>");
  assert.equal(refs.length, 0);
});

test("classifyHit handles index inside nested script with escapes", () => {
  const body = "<script>var s = \"a\\\"b" + MARK + "c\";</script>";
  const idx = body.indexOf(MARK);
  assert.equal(classifyHit(body, idx), "JS_STRING_DQ");
});

test("extractParams pulls query, form, JSON, cookie, header sources", () => {
  const params = extractParams({
    query: "q=longvalue1&x=true",
    contentType: "application/json",
    body: '{"label":"jsonvalue2","nested":{"k":"jsonvalue3"}}',
    headers: {
      Cookie: ["session=cookievalue4; tracker=cookieval5"],
      Referer: ["https://refererhost.example/page"],
      "X-Forwarded-For": ["xffvalue6.example"],
      "X-Random": ["shouldNotAppear"],
    },
  });
  const names = params.map((p) => `${p.source}:${p.name}`).sort();
  assert.ok(names.includes("query:q"));
  assert.ok(names.includes("json:label"));
  assert.ok(names.includes("json:nested.k"));
  assert.ok(names.includes("cookie:session"));
  assert.ok(names.includes("cookie:tracker"));
  assert.ok(names.includes("header:Referer"));
  assert.ok(names.includes("header:X-Forwarded-For"));
  assert.ok(!names.some((n) => n.startsWith("header:X-Random")));
});

test("extractParams skips short and stoplisted values", () => {
  const params = extractParams({
    query: "a=ok&b=true&c=1&d=yes&e=longenoughvalue",
    contentType: "",
    body: "",
    headers: {},
  });
  const names = params.map((p) => p.name);
  assert.deepEqual(names, ["e"]);
});

test("findPassiveHits returns hit when value appears in body", () => {
  const params = [{ source: "query" as const, name: "q", value: MARK }];
  const hits = findPassiveHits(params, `<p>${MARK}</p>`);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.param.name, "q");
});

test("findPassiveHits dedupes identical source/name/value", () => {
  const params = [
    { source: "query" as const, name: "q", value: MARK },
    { source: "query" as const, name: "q", value: MARK },
  ];
  const hits = findPassiveHits(params, `<p>${MARK}</p>`);
  assert.equal(hits.length, 1);
});

test("isJsonContentType detects json variants", () => {
  assert.equal(isJsonContentType("application/json"), true);
  assert.equal(isJsonContentType("application/json; charset=utf-8"), true);
  assert.equal(isJsonContentType("application/vnd.api+json"), true);
  assert.equal(isJsonContentType("text/json"), true);
  assert.equal(isJsonContentType("text/html"), false);
  assert.equal(isJsonContentType("application/javascript"), false);
});
