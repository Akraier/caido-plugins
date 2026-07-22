import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildCanary,
  analyseSurvival,
  evaluateState,
  canaryReflected,
  detectContext,
  detectAllContexts,
  findAllCanaryIndexes,
  suggestedPayload,
  summarise,
  CHAR_LITERAL,
  type TestChar,
} from "../packages/backend/src/probe";

function applyHtmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function applyJsEscapeDQ(s: string): string {
  return s.replace(/"/g, '\\"');
}

function dropChars(s: string, drop: string[]): string {
  let out = s;
  for (const c of drop) out = out.split(c).join("");
  return out;
}

test("buildCanary contains every test char between flankers", () => {
  const c = buildCanary("test01");
  for (const tc of Object.keys(CHAR_LITERAL) as TestChar[]) {
    const { left, right } = c.markers[tc];
    assert.ok(c.value.includes(left + CHAR_LITERAL[tc] + right), `missing ${tc}`);
  }
  assert.ok(c.value.startsWith(c.head));
});

test("canaryReflected: head present → true", () => {
  const c = buildCanary("test02");
  assert.equal(canaryReflected(`<p>${c.value}</p>`, c), true);
});

test("canaryReflected: head absent → false", () => {
  const c = buildCanary("test03");
  assert.equal(canaryReflected(`<p>nothing here</p>`, c), false);
});

test("evaluateState all chars stripped → REFLECTED", () => {
  const c = buildCanary("test04");
  // Strip every special char so the survival raw set is empty.
  const allSpecials = Object.values(CHAR_LITERAL);
  const body = dropChars(c.value, allSpecials);
  const survival = analyseSurvival(body, c.markers);
  const result = evaluateState("HTML_BODY", survival);
  assert.equal(result.state, "REFLECTED");
});

test("evaluateState HTML_BODY + html-escape only → ATTEMPT (LT/GT encoded, rest raw)", () => {
  const c = buildCanary("test04b");
  const body = applyHtmlEscape(c.value);
  const survival = analyseSurvival(body, c.markers);
  const result = evaluateState("HTML_BODY", survival);
  assert.equal(result.state, "ATTEMPT");
});

test("evaluateState HTML_BODY + < and > raw → CONFIRMED", () => {
  const c = buildCanary("test05");
  const survival = analyseSurvival(c.value, c.markers);
  const result = evaluateState("HTML_BODY", survival);
  assert.equal(result.state, "CONFIRMED");
  assert.deepEqual(result.breakoutSet, ["LT", "GT"]);
});

test("evaluateState HTML_ATTR_DQ + DQ encoded → ATTEMPT (other chars raw, none satisfy ctx)", () => {
  const c = buildCanary("test06");
  const body = applyJsEscapeDQ(c.value);
  const survival = analyseSurvival(body, c.markers);
  const result = evaluateState("HTML_ATTR_DQ", survival);
  assert.equal(result.state, "ATTEMPT");
});

test("evaluateState HTML_ATTR_DQ + DQ raw → CONFIRMED", () => {
  const c = buildCanary("test07");
  const survival = analyseSurvival(c.value, c.markers);
  const result = evaluateState("HTML_ATTR_DQ", survival);
  assert.equal(result.state, "CONFIRMED");
});

test("evaluateState JS_STRING_DQ + DQ encoded but </script> survives → CONFIRMED", () => {
  const c = buildCanary("test08");
  const body = applyJsEscapeDQ(c.value);
  const survival = analyseSurvival(body, c.markers);
  const result = evaluateState("JS_STRING_DQ", survival);
  assert.equal(result.state, "CONFIRMED");
  assert.deepEqual(result.breakoutSet, ["LT", "SL"]);
});

test("evaluateState URL_ATTR_DQ + only `:` raw → CONFIRMED", () => {
  const c = buildCanary("test09");
  // Strip everything except `:` and the colon's flanker chars
  let body = c.value;
  for (const tc of Object.keys(CHAR_LITERAL) as TestChar[]) {
    if (tc === "CO") continue;
    body = body.split(CHAR_LITERAL[tc]).join("");
  }
  const survival = analyseSurvival(body, c.markers);
  const result = evaluateState("URL_ATTR_DQ", survival);
  assert.equal(result.state, "CONFIRMED");
});

test("evaluateState JSON_BODY → always ATTEMPT or REFLECTED, never CONFIRMED", () => {
  const c = buildCanary("test10");
  const survival = analyseSurvival(c.value, c.markers);
  const result = evaluateState("JSON_BODY", survival);
  assert.notEqual(result.state, "CONFIRMED");
});

test("evaluateState HTML_BODY + only `<` raw → ATTEMPT", () => {
  const c = buildCanary("test11");
  const body = dropChars(c.value, [">", '"', "'", "`", "/", ":", "(", ")", "{", "}", "$", ";", "&", "\\"]);
  const survival = analyseSurvival(body, c.markers);
  const result = evaluateState("HTML_BODY", survival);
  assert.equal(result.state, "ATTEMPT");
});

test("detectContext respects JSON Content-Type override", () => {
  const c = buildCanary("test12");
  const probeBody = `<p>${c.value}</p>`;
  const r = detectContext(probeBody, c, "application/json; charset=utf-8");
  assert.equal(r.context, "JSON_BODY");
});

test("detectContext uses HTML classifier when CT is text/html", () => {
  const c = buildCanary("test13");
  const probeBody = `<input value="${c.value}">`;
  const r = detectContext(probeBody, c, "text/html");
  assert.equal(r.context, "HTML_ATTR_DQ");
});

test("suggestedPayload returns payload for confirmed contexts", () => {
  assert.equal(suggestedPayload("HTML_BODY", ["LT", "GT"]), "<svg/onload=alert(1)>");
  assert.equal(suggestedPayload("HTML_ATTR_DQ", ["DQ"]), '" onmouseover="alert(1)" x="');
  assert.equal(suggestedPayload("URL_ATTR_DQ", ["CO"]), "javascript:alert(1)");
  assert.equal(suggestedPayload("JS_STRING_DQ", ["DQ"]), '";alert(1);//');
  assert.equal(suggestedPayload("JS_STRING_DQ", ["LT", "SL"]), "</script><svg/onload=alert(1)>");
  assert.equal(suggestedPayload("JS_TEMPLATE", ["BT"]), "`;alert(1);`");
  assert.equal(suggestedPayload("JS_TEMPLATE", ["DL", "CB"]), "${alert(1)}");
});

test("suggestedPayload returns null when no breakout set", () => {
  assert.equal(suggestedPayload("HTML_BODY", null), null);
  assert.equal(suggestedPayload("JSON_BODY", null), null);
});

test("summarise groups raw/encoded/stripped/unknown correctly", () => {
  const c = buildCanary("test14");
  const body = applyHtmlEscape(c.value);
  const survival = analyseSurvival(body, c.markers);
  const summary = summarise(survival);
  assert.ok(summary.encoded.includes("LT"));
  assert.ok(summary.raw.includes("BT"));
});

test("analyseSurvival detects double-URL-encoded characters", () => {
  const c = buildCanary("dblurl1");
  let body = c.value;
  const lt = CHAR_LITERAL["LT"];
  const leftLT = c.markers["LT"].left;
  const rightLT = c.markers["LT"].right;
  body = body.replace(leftLT + lt + rightLT, leftLT + "%253C" + rightLT);
  const gt = CHAR_LITERAL["GT"];
  const leftGT = c.markers["GT"].left;
  const rightGT = c.markers["GT"].right;
  body = body.replace(leftGT + gt + rightGT, leftGT + "%253E" + rightGT);
  const survival = analyseSurvival(body, c.markers);
  assert.equal(survival["LT"], "double_url_encode");
  assert.equal(survival["GT"], "double_url_encode");
  assert.equal(survival["DQ"], "raw");
});

test("findAllCanaryIndexes finds multiple reflections", () => {
  const c = buildCanary("multi1");
  const body = `<p>${c.value}</p><script>var x = "${c.value}";</script>`;
  const indexes = findAllCanaryIndexes(body, c);
  assert.equal(indexes.length, 2);
  assert.ok(indexes[0]! < indexes[1]!);
});

test("detectAllContexts returns distinct contexts for multi-reflection", () => {
  const c = buildCanary("multi2");
  const body = `<p>${c.value}</p><script>var x = "${c.value}";</script>`;
  const contexts = detectAllContexts(body, c, "text/html");
  assert.equal(contexts.length, 2);
  const ctxNames = contexts.map((r) => r.context).sort();
  assert.ok(ctxNames.includes("HTML_BODY"));
  assert.ok(ctxNames.includes("JS_STRING_DQ"));
});

test("detectAllContexts dedupes same context across reflections", () => {
  const c = buildCanary("multi3");
  const body = `<p>${c.value}</p><div>${c.value}</div>`;
  const contexts = detectAllContexts(body, c, "text/html");
  assert.equal(contexts.length, 1);
  assert.equal(contexts[0]!.context, "HTML_BODY");
});

test("detectAllContexts returns single JSON_BODY for JSON content type", () => {
  const c = buildCanary("multi4");
  const body = `{"a":"${c.value}","b":"${c.value}"}`;
  const contexts = detectAllContexts(body, c, "application/json");
  assert.equal(contexts.length, 1);
  assert.equal(contexts[0]!.context, "JSON_BODY");
});
