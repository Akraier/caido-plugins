import { test } from "node:test";
import assert from "node:assert/strict";

import { ScanCache, pageKey } from "../packages/backend/src/scan-cache";
import type { Param } from "../packages/backend/src/extract";

const q = (name: string, value = "v"): Param => ({ source: "query", name, value });
const f = (name: string, value = "v"): Param => ({ source: "form", name, value });
const j = (name: string, value = "v"): Param => ({ source: "json", name, value });
const c = (name: string, value = "v"): Param => ({ source: "cookie", name, value });
const h = (name: string, value = "v"): Param => ({ source: "header", name, value });

test("pageKey is identical when only param values differ", () => {
  const k1 = pageKey("GET", "example.com", "/profile", [q("id", "1")]);
  const k2 = pageKey("GET", "example.com", "/profile", [q("id", "2")]);
  assert.equal(k1, k2);
});

test("pageKey differs when a new param NAME appears", () => {
  const k1 = pageKey("GET", "example.com", "/api", [q("a")]);
  const k2 = pageKey("GET", "example.com", "/api", [q("a"), q("b")]);
  assert.notEqual(k1, k2);
});

test("pageKey differs across paths", () => {
  const k1 = pageKey("GET", "example.com", "/a", [q("x")]);
  const k2 = pageKey("GET", "example.com", "/b", [q("x")]);
  assert.notEqual(k1, k2);
});

test("pageKey differs across methods", () => {
  const k1 = pageKey("GET", "example.com", "/api", [q("x")]);
  const k2 = pageKey("POST", "example.com", "/api", [q("x")]);
  assert.notEqual(k1, k2);
});

test("pageKey normalises host case and method case", () => {
  const k1 = pageKey("get", "EXAMPLE.com", "/x", [q("a")]);
  const k2 = pageKey("GET", "example.com", "/x", [q("a")]);
  assert.equal(k1, k2);
});

test("pageKey ignores cookie/header params (too volatile)", () => {
  const k1 = pageKey("GET", "example.com", "/x", [q("a"), c("session"), h("Referer")]);
  const k2 = pageKey("GET", "example.com", "/x", [q("a"), c("other"), h("X-Forwarded-For")]);
  assert.equal(k1, k2);
});

test("pageKey is param-order independent", () => {
  const k1 = pageKey("GET", "example.com", "/x", [q("a"), q("b")]);
  const k2 = pageKey("GET", "example.com", "/x", [q("b"), q("a")]);
  assert.equal(k1, k2);
});

test("pageKey treats query vs form vs json as distinct sources", () => {
  const k1 = pageKey("POST", "example.com", "/x", [q("a")]);
  const k2 = pageKey("POST", "example.com", "/x", [f("a")]);
  const k3 = pageKey("POST", "example.com", "/x", [j("a")]);
  assert.notEqual(k1, k2);
  assert.notEqual(k2, k3);
});

test("ScanCache: first call false, second call true", () => {
  const c = new ScanCache();
  const key = "GET|example.com|/x|query:a";
  assert.equal(c.has(key), false);
  c.mark(key);
  assert.equal(c.has(key), true);
});

test("ScanCache: distinct keys do not collide", () => {
  const c = new ScanCache();
  c.mark("A");
  assert.equal(c.has("A"), true);
  assert.equal(c.has("B"), false);
});

test("ScanCache: clear() resets", () => {
  const c = new ScanCache();
  c.mark("A");
  c.clear();
  assert.equal(c.has("A"), false);
  assert.equal(c.size(), 0);
});
