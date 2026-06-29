// Shared low-level probing primitives used by both the cache profiler and the delimiter
// detector. Every probe targets a random unique segment so cache population stays
// non-destructive. No business logic here — just send + measure.
import type {
  Request as CaidoRequest,
  Response as CaidoResponse,
  RequestSpec,
} from "caido:utils";
import type { SDK } from "caido:plugin";

import {
  ageOf,
  cacheStatus,
  isHit,
  lower,
  parseCacheControl,
  type CacheControl,
  type HeaderMap,
} from "./cache.js";
import type { BackendEvents, CacheStatus } from "./types.js";

export type EngineSDK = SDK<never, BackendEvents>;

// Inter-probe delay (ms). Raise to throttle against rate-limited / bot-protected targets.
export const REQUEST_DELAY_MS = 0;

function sleep(ms: number): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export type Probe = {
  status: number;
  cstatus: CacheStatus;
  age: number;
  bodyLen: number;
  rttMs: number; // server roundtrip time (Caido-measured)
  cc: CacheControl;
  headers: HeaderMap;
  ok: boolean; // a response was actually received
};

export const EMPTY_PROBE: Probe = {
  status: 0,
  cstatus: "NONE",
  age: -1,
  bodyLen: 0,
  rttMs: 0,
  cc: parseCacheControl({}),
  headers: {},
  ok: false,
};

// Timing fallback thresholds (used only when the response carries NO cache-status header).
// A HIT is served from the edge; a MISS goes edge -> origin -> edge, so it is markedly slower.
const TIMING_HIT_RATIO = 0.5; // 2nd request <= half the 1st request's roundtrip
const TIMING_MIN_GAP_MS = 15; // ...and at least this much faster, to clear jitter

// Header stamped on every request the plugin itself sends, so the passive interceptor can
// recognise and skip its own probe traffic (otherwise the confirmation probes would re-trigger
// the queue recursively).
export const PROBE_MARKER = "X-Cp-Probe";

export type ProbeOpts = {
  path?: string;
  appendQuery?: string;
  setCookie?: string;
  stripCookie?: boolean;
  marker?: boolean; // stamp PROBE_MARKER so the interceptor ignores this request
  headers?: Record<string, string>; // arbitrary request headers (e.g. unkeyed-header probes)
};

export function specFor(base: CaidoRequest, opts: ProbeOpts): RequestSpec {
  const spec = base.toSpec();
  if (opts.path !== undefined) spec.setPath(opts.path);
  if (opts.appendQuery !== undefined) {
    const u = base.getUrl();
    const qIdx = u.indexOf("?");
    const existing = qIdx >= 0 ? u.slice(qIdx + 1) : "";
    const q =
      existing.length > 0 ? `${existing}&${opts.appendQuery}` : opts.appendQuery;
    spec.setQuery(q);
  }
  if (opts.stripCookie === true) spec.removeHeader("Cookie");
  if (opts.setCookie !== undefined) spec.setHeader("Cookie", opts.setCookie);
  if (opts.headers !== undefined) {
    for (const [name, value] of Object.entries(opts.headers)) {
      spec.setHeader(name, value);
    }
  }
  if (opts.marker === true) spec.setHeader(PROBE_MARKER, "1");
  return spec;
}

function parseProbe(res: CaidoResponse): Probe {
  const h = lower(res.getHeaders());
  const body = res.getBody();
  return {
    status: res.getCode(),
    cstatus: cacheStatus(h),
    age: ageOf(h),
    bodyLen: body !== undefined ? body.toRaw().length : 0,
    rttMs: typeof res.getRoundtripTime === "function" ? res.getRoundtripTime() : 0,
    cc: parseCacheControl(h),
    headers: h,
    ok: true,
  };
}

export async function send(sdk: EngineSDK, spec: RequestSpec): Promise<Probe> {
  await sleep(REQUEST_DELAY_MS);
  const sent = await sdk.requests.send(spec);
  const res: CaidoResponse | undefined = sent.response;
  return res === undefined ? EMPTY_PROBE : parseProbe(res);
}

// Like send, but also decodes the response body to text — for reflection detection in the
// unkeyed-header (cache-poisoning) scan. Kept separate so the hot confirm path never pays the
// body-decode cost.
export async function sendWithBody(
  sdk: EngineSDK,
  spec: RequestSpec,
): Promise<{ probe: Probe; body: string }> {
  await sleep(REQUEST_DELAY_MS);
  const sent = await sdk.requests.send(spec);
  const res: CaidoResponse | undefined = sent.response;
  if (res === undefined) return { probe: EMPTY_PROBE, body: "" };
  const probe = parseProbe(res);
  const b = res.getBody();
  return { probe, body: b !== undefined ? b.toText() : "" };
}

// Send a URL twice; decide whether the edge actually stored it. Header-based first; only when
// the response carries NO cache-status header at all (a header-stripping CDN) does it fall
// back to timing — comparing the two roundtrips we already made (no extra requests).
export async function confirmCached(
  sdk: EngineSDK,
  base: CaidoRequest,
  path: string,
): Promise<{ cached: boolean; firstMiss?: Probe; last: Probe; via: "headers" | "timing" | "none" }> {
  const p1 = await send(sdk, specFor(base, { path }));
  const p2 = await send(sdk, specFor(base, { path }));

  const headerSignal =
    p1.cstatus !== "NONE" || p2.cstatus !== "NONE" || p1.age >= 0 || p2.age >= 0;
  let cached =
    isHit(p1.cstatus) ||
    isHit(p2.cstatus) ||
    (p1.age >= 0 && p2.age > p1.age) ||
    (p1.age <= 0 && p2.age > 0);
  let via: "headers" | "timing" | "none" = headerSignal ? "headers" : "none";

  // Timing fallback: only when headers gave nothing. For random-segment probes p1 is a genuine
  // MISS, so a 2nd request that is markedly faster means the edge served it from cache.
  if (!cached && !headerSignal && p1.rttMs > 0 && p2.rttMs > 0) {
    const fastEnough =
      p2.rttMs <= p1.rttMs * TIMING_HIT_RATIO &&
      p1.rttMs - p2.rttMs >= TIMING_MIN_GAP_MS;
    if (fastEnough) {
      cached = true;
      via = "timing";
    }
  }

  const firstMiss = !isHit(p1.cstatus)
    ? p1
    : !isHit(p2.cstatus)
      ? p2
      : undefined;
  return { cached, firstMiss, last: p2, via };
}

// Populate seedPath, then send a single mutated variant: a HIT means the variant
// collides with the seed's cache entry, i.e. the mutated dimension is NOT in the key.
export async function sharesEntry(
  sdk: EngineSDK,
  base: CaidoRequest,
  seedPath: string,
  variant: ProbeOpts,
): Promise<boolean> {
  await send(sdk, specFor(base, { path: seedPath }));
  await send(sdk, specFor(base, { path: seedPath }));
  const v = await send(sdk, specFor(base, { ...variant, path: seedPath }));
  return isHit(v.cstatus);
}

export function sameBody(a: number, b: number): boolean {
  const tol = Math.max(64, b * 0.1);
  return Math.abs(a - b) <= tol;
}

export function looksLikeControl404(p: Probe, ctrl: Probe): boolean {
  if (!ctrl.ok) return false;
  return p.status === ctrl.status && sameBody(p.bodyLen, ctrl.bodyLen);
}

// ---- two-anchor classifier (for delimiter detection) -----------------------

// A compact fingerprint of a response used to compare probes against two known anchors
// (the base "good" response and the "error" response).
export type Anchor = { status: number; contentType: string; bodyLen: number };

function contentType(h: HeaderMap): string {
  const v = h["content-type"];
  const raw = v !== undefined && v.length > 0 ? (v[0] ?? "") : "";
  return (raw.split(";")[0] ?? "").trim().toLowerCase();
}

export function anchorOf(p: Probe): Anchor {
  return { status: p.status, contentType: contentType(p.headers), bodyLen: p.bodyLen };
}

export function anchorDist(a: Anchor, b: Anchor): number {
  let d = 0;
  if (a.status !== b.status) d += 1000;
  if (a.contentType !== b.contentType) d += 500;
  d += Math.abs(a.bodyLen - b.bodyLen);
  return d;
}

export type NearestVerdict = "good" | "error" | "ambiguous";

// Classify a probe by which anchor it is closer to, requiring a margin proportional to how
// separated the two anchors are. Returns "ambiguous" when the probe resembles neither
// clearly (dynamic body, partial match) so the caller never forces a false verdict.
export function nearest(probe: Anchor, good: Anchor, error: Anchor): NearestVerdict {
  const dg = anchorDist(probe, good);
  const de = anchorDist(probe, error);
  const sep = anchorDist(good, error);
  const margin = Math.max(64, sep * 0.25);
  if (Math.abs(dg - de) < margin) return "ambiguous";
  return dg < de ? "good" : "error";
}

export function anchorsSeparable(good: Anchor, error: Anchor): boolean {
  return anchorDist(good, error) >= 64;
}
