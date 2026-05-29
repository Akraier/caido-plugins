/**
 * End-to-end smoke test against the live Flask app, using the v2 state machine.
 *
 *   python3 test-target/app.py &      # binds 127.0.0.1:5001
 *   npm run test:integration
 *
 * Steps per route:
 *   1. Passive: send MARK, look for value in body.
 *   2. Probe: send canary, run probe.evaluateState.
 *   3. Assert (state, context, raw-char subset) match expectations.
 */
import { extractParams } from "../packages/backend/src/extract";
import { findPassiveHits } from "../packages/backend/src/reflect";
import {
  buildCanary,
  analyseSurvival,
  canaryReflected,
  detectContext,
  evaluateState,
  CHAR_LITERAL,
  type State,
  type TestChar,
} from "../packages/backend/src/probe";
import type { ReflectionContext } from "../packages/backend/src/classify";

const BASE = process.env.TARGET ?? "http://127.0.0.1:5001";
const MARK = "caidoMARK123";

type Probe = {
  name: string;
  path: string;
  method?: "GET" | "POST";
  paramName: string;
  ct?: string;
  bodyTemplate?: (value: string) => string;
  queryTemplate?: (value: string) => string;
  expect: {
    state: State | "NO_REFLECTION";
    context?: ReflectionContext;
    rawInclude?: TestChar[];
    rawExclude?: TestChar[];
  };
};

const ROUTES: Probe[] = [
  // ── canonical context routes — all CONFIRMED ──
  { name: "body",      path: "/body",      paramName: "q",
    queryTemplate: (v) => `q=${encodeURIComponent(v)}`,
    expect: { state: "CONFIRMED", context: "HTML_BODY",     rawInclude: ["LT", "GT"] } },
  { name: "attr_dq",   path: "/attr_dq",   paramName: "q",
    queryTemplate: (v) => `q=${encodeURIComponent(v)}`,
    expect: { state: "CONFIRMED", context: "HTML_ATTR_DQ",  rawInclude: ["DQ"] } },
  { name: "attr_sq",   path: "/attr_sq",   paramName: "q",
    queryTemplate: (v) => `q=${encodeURIComponent(v)}`,
    expect: { state: "CONFIRMED", context: "HTML_ATTR_SQ",  rawInclude: ["SQ"] } },
  { name: "js_dq",     path: "/js_dq",     paramName: "q",
    queryTemplate: (v) => `q=${encodeURIComponent(v)}`,
    expect: { state: "CONFIRMED", context: "JS_STRING_DQ",  rawInclude: ["DQ"] } },
  { name: "js_sq",     path: "/js_sq",     paramName: "q",
    queryTemplate: (v) => `q=${encodeURIComponent(v)}`,
    expect: { state: "CONFIRMED", context: "JS_STRING_SQ",  rawInclude: ["SQ"] } },
  { name: "js_tpl",    path: "/js_tpl",    paramName: "q",
    queryTemplate: (v) => `q=${encodeURIComponent(v)}`,
    expect: { state: "CONFIRMED", context: "JS_TEMPLATE",   rawInclude: ["BT"] } },
  { name: "href",      path: "/href",      paramName: "redir",
    queryTemplate: (v) => `redir=${encodeURIComponent(v)}`,
    expect: { state: "CONFIRMED", context: "URL_ATTR_DQ",   rawInclude: ["CO"] } },

  // ── blacklist routes ──
  { name: "bl_lt_gt (drops <,>)",         path: "/bl_lt_gt",        paramName: "q",
    queryTemplate: (v) => `q=${encodeURIComponent(v)}`,
    expect: { state: "ATTEMPT", context: "HTML_BODY", rawExclude: ["LT", "GT"] } },
  { name: "bl_quotes (drops \", \\')",    path: "/bl_quotes",       paramName: "q",
    queryTemplate: (v) => `q=${encodeURIComponent(v)}`,
    expect: { state: "ATTEMPT", context: "HTML_ATTR_DQ", rawExclude: ["DQ", "SQ"] } },
  { name: "htmlentity_only (<,> → entity)", path: "/htmlentity_only", paramName: "q",
    queryTemplate: (v) => `q=${encodeURIComponent(v)}`,
    expect: { state: "CONFIRMED", context: "HTML_ATTR_DQ", rawInclude: ["DQ"], rawExclude: ["LT", "GT"] } },
  { name: "js_escape_dq (\\\" only)",     path: "/js_escape_dq",    paramName: "q",
    queryTemplate: (v) => `q=${encodeURIComponent(v)}`,
    expect: { state: "CONFIRMED", context: "JS_STRING_DQ", rawInclude: ["LT", "SL"], rawExclude: ["DQ"] } },
  { name: "href_bl_js (strips javascript:)", path: "/href_bl_js",   paramName: "redir",
    queryTemplate: (v) => `redir=${encodeURIComponent(v)}`,
    expect: { state: "CONFIRMED", context: "URL_ATTR_DQ", rawInclude: ["CO"] } },
  { name: "strip_xss (strips <>\"')",     path: "/strip_xss",       paramName: "q",
    queryTemplate: (v) => `q=${encodeURIComponent(v)}`,
    expect: { state: "ATTEMPT", context: "HTML_BODY", rawExclude: ["LT", "GT", "DQ", "SQ"] } },

  // ── full mitigation → REFLECTED (canary reflects, no chars raw) ──
  { name: "url_encode_all (encodes all)", path: "/url_encode_all",  paramName: "q",
    queryTemplate: (v) => `q=${encodeURIComponent(v)}`,
    expect: { state: "REFLECTED", context: "HTML_BODY" } },
  // MarkupSafe.escape only handles <>&"'. Other chars (\,:,/,(,),{,},$,;,`) survive
  // raw — none of them satisfy HTML_BODY breakout, so this is ATTEMPT not REFLECTED.
  { name: "safe (HTML escape)",           path: "/safe",            paramName: "q",
    queryTemplate: (v) => `q=${encodeURIComponent(v)}`,
    expect: { state: "ATTEMPT", context: "HTML_BODY", rawExclude: ["LT", "GT", "DQ", "SQ"] } },

  // ── POST sinks ──
  { name: "post form",  path: "/post", method: "POST", paramName: "name",
    ct: "application/x-www-form-urlencoded",
    bodyTemplate: (v) => `name=${encodeURIComponent(v)}`,
    expect: { state: "CONFIRMED", context: "HTML_BODY", rawInclude: ["LT", "GT"] } },
  { name: "post json",  path: "/json", method: "POST", paramName: "label",
    ct: "application/json",
    bodyTemplate: (v) => JSON.stringify({ label: v }),
    expect: { state: "CONFIRMED", context: "JS_STRING_DQ", rawInclude: ["DQ"] } },
];

function pad(s: string, n: number): string {
  return s.length >= n ? s.slice(0, n) : s + " ".repeat(n - s.length);
}

async function send(p: Probe, value: string): Promise<{ body: string; ct: string }> {
  const headers: Record<string, string> = {};
  if (p.ct) headers["content-type"] = p.ct;
  const method = p.method ?? "GET";
  if (method === "GET") {
    const qs = p.queryTemplate ? `?${p.queryTemplate(value)}` : "";
    const res = await fetch(`${BASE}${p.path}${qs}`, { method, headers });
    return { body: await res.text(), ct: res.headers.get("content-type") ?? "" };
  }
  const body = p.bodyTemplate ? p.bodyTemplate(value) : "";
  const res = await fetch(`${BASE}${p.path}`, { method, headers, body });
  return { body: await res.text(), ct: res.headers.get("content-type") ?? "" };
}

type Outcome = {
  state: State | "NO_REFLECTION";
  context: ReflectionContext | "—";
  raw: TestChar[];
  encoded: TestChar[];
  stripped: TestChar[];
};

async function runOne(p: Probe): Promise<Outcome> {
  const passive = await send(p, MARK);
  const params = extractParams({
    query: p.queryTemplate ? p.queryTemplate(MARK) : "",
    contentType: p.ct ?? "",
    body: p.bodyTemplate ? p.bodyTemplate(MARK) : "",
    headers: {},
  });
  const hits = findPassiveHits(params, passive.body);
  if (hits.length === 0) {
    return { state: "NO_REFLECTION", context: "—", raw: [], encoded: [], stripped: [] };
  }

  const canary = buildCanary("intg00");
  const probe = await send(p, canary.value);
  if (!canaryReflected(probe.body, canary)) {
    return { state: "NO_REFLECTION", context: "—", raw: [], encoded: [], stripped: [] };
  }

  const { context } = detectContext(probe.body, canary, probe.ct);
  const survival = analyseSurvival(probe.body, canary.markers);
  const result = evaluateState(context, survival);

  const raw: TestChar[] = [];
  const encoded: TestChar[] = [];
  const stripped: TestChar[] = [];
  for (const tc of Object.keys(survival) as TestChar[]) {
    if (survival[tc] === "raw") raw.push(tc);
    else if (survival[tc] === "stripped") stripped.push(tc);
    else if (survival[tc] !== "unknown") encoded.push(tc);
  }
  return { state: result.state, context, raw, encoded, stripped };
}

function describeChars(chars: TestChar[]): string {
  return chars.length === 0 ? "—" : chars.map((c) => CHAR_LITERAL[c]).join("");
}

async function run(): Promise<void> {
  console.log(`Target: ${BASE}`);
  console.log(
    pad("ROUTE", 38) +
      pad("STATE", 13) +
      pad("CONTEXT", 18) +
      pad("RAW", 16) +
      "VERDICT",
  );
  console.log("─".repeat(120));
  let pass = 0;
  let fail = 0;
  const failures: string[] = [];
  for (const r of ROUTES) {
    try {
      const o = await runOne(r);
      const exp = r.expect;
      const reasons: string[] = [];
      if (o.state !== exp.state) reasons.push(`state ${o.state} ≠ ${exp.state}`);
      if (exp.context && o.context !== exp.context && o.state !== "NO_REFLECTION")
        reasons.push(`context ${o.context} ≠ ${exp.context}`);
      if (exp.rawInclude) for (const c of exp.rawInclude) if (!o.raw.includes(c)) reasons.push(`missing raw ${c}`);
      if (exp.rawExclude) for (const c of exp.rawExclude) if (o.raw.includes(c)) reasons.push(`unexpected raw ${c}`);
      const ok = reasons.length === 0;
      console.log(
        pad(r.name, 38) +
          pad(o.state, 13) +
          pad(o.context, 18) +
          pad(describeChars(o.raw), 16) +
          (ok ? "PASS" : `FAIL — ${reasons.join("; ")}`),
      );
      if (ok) pass++;
      else {
        fail++;
        failures.push(`${r.name}: ${reasons.join("; ")}`);
      }
    } catch (e) {
      fail++;
      console.log(pad(r.name, 38) + "ERROR " + String(e));
      failures.push(`${r.name}: ${String(e)}`);
    }
  }
  console.log("─".repeat(120));
  console.log(`Pass: ${pass} / ${ROUTES.length}    Fail: ${fail}`);
  if (failures.length > 0) {
    console.log("\nFailures:");
    for (const f of failures) console.log(`  - ${f}`);
    process.exit(1);
  }
}

run();
