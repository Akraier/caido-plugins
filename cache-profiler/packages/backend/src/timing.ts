// Dedicated timing-based cache probe. Operator-invoked when a header-stripping CDN is
// suspected from request timing. Unlike the embedded fallback in confirmCached (which is
// zero-extra-request and conservative), this opts into more requests for a confident,
// evidence-backed verdict on ONE URL: a cache-busted MISS baseline vs the steady-state RTT
// of repeated requests.
import type { Request as CaidoRequest, Response as CaidoResponse } from "caido:utils";

import { isHit, randSeg } from "./cache.js";
import { send, specFor, type EngineSDK } from "./probe.js";
import type { TimingResult } from "./types.js";

const N_MISS = 4; // cache-busted samples (forced origin)
const M_STEADY = 5; // repeated samples; the first may be a MISS and is dropped
const HIT_RATIO = 0.5; // steady <= half the MISS baseline => cached
const NOT_CACHED_RATIO = 0.8; // steady >= 80% of MISS baseline => not cached
const MIN_GAP_MS = 15;

function median(xs: number[]): number {
  if (xs.length === 0) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  if (s.length % 2 === 1) return s[mid] ?? 0;
  return ((s[mid - 1] ?? 0) + (s[mid] ?? 0)) / 2;
}

export async function runTimingProbe(
  sdk: EngineSDK,
  base: CaidoRequest,
  _baseResponse: CaidoResponse | undefined,
): Promise<TimingResult> {
  const host = base.getHost().toLowerCase();
  const path = base.getPath();

  const result: TimingResult = {
    host,
    path,
    missSamples: [],
    steadySamples: [],
    missMedian: 0,
    steadyMedian: 0,
    ratio: 0,
    verdict: "inconclusive",
    confidence: "low",
    notes: [],
  };

  // MISS baseline: each request carries a unique cache-buster, so it never matches a stored
  // entry and is served by the origin.
  for (let i = 0; i < N_MISS; i++) {
    const p = await send(
      sdk,
      specFor(base, { path, appendQuery: `__cpcb=${randSeg()}` }),
    );
    if (p.ok && p.rttMs > 0) result.missSamples.push(p.rttMs);
  }

  // Steady state: the real URL repeated. If it caches, requests after the first are HITs.
  for (let i = 0; i < M_STEADY; i++) {
    const p = await send(sdk, specFor(base, { path }));
    if (p.cstatus !== "NONE" && result.headerSignal === undefined) {
      result.headerSignal = `${p.cstatus.toLowerCase()}`;
    }
    if (i > 0 && p.ok && p.rttMs > 0) result.steadySamples.push(p.rttMs);
    // A real cache-status HIT header is the strongest possible signal.
    if (i > 0 && isHit(p.cstatus)) {
      result.headerSignal = "HIT";
    }
  }

  result.missMedian = median(result.missSamples);
  result.steadyMedian = median(result.steadySamples);
  result.ratio =
    result.missMedian > 0 ? result.steadyMedian / result.missMedian : 0;

  // Header signal wins when present.
  if (result.headerSignal === "HIT") {
    result.verdict = "cached";
    result.confidence = "header-confirmed";
    result.notes.push(
      "Host exposes a cache-status header (HIT) — timing corroborates but was not needed.",
    );
    return result;
  }

  if (result.missMedian === 0 || result.steadyMedian === 0) {
    result.notes.push(
      "No usable roundtrip timing was returned — cannot infer caching from latency here.",
    );
    return result;
  }

  const gap = result.missMedian - result.steadyMedian;
  if (result.ratio <= HIT_RATIO && gap >= MIN_GAP_MS) {
    result.verdict = "cached";
    result.confidence = "timing";
    result.notes.push(
      "Steady-state responses are markedly faster than cache-busted (origin) requests — served from the edge.",
    );
  } else if (result.ratio >= NOT_CACHED_RATIO) {
    result.verdict = "not-cached";
    result.confidence = "timing";
    result.notes.push(
      "Steady-state and origin timings are comparable — every request reaches the origin.",
    );
  } else {
    result.verdict = "inconclusive";
    result.confidence = "low";
    result.notes.push(
      "Timing is between the cached and origin bands — inconclusive. Re-run (jitter), or raise sample counts.",
    );
  }

  return result;
}

// ---- reporting -------------------------------------------------------------

function code(s: string): string {
  return "`" + s + "`";
}

export function timingSummary(r: TimingResult): string {
  const parts = [`${r.verdict}`];
  if (r.missMedian > 0) {
    parts.push(`miss ${Math.round(r.missMedian)}ms vs steady ${Math.round(r.steadyMedian)}ms`);
  }
  parts.push(r.confidence);
  return parts.join(", ");
}

export function timingTitle(r: TimingResult): string {
  return `Cache Profiler — timing probe: ${r.verdict} — ${r.host}`;
}

export function formatTimingResult(r: TimingResult): string {
  const out: string[] = [];
  const section = (title: string, items: string[]): void => {
    if (out.length > 0) out.push("");
    out.push(`**${title}**`);
    out.push("");
    for (const item of items) out.push(`- ${item}`);
  };

  section("TIMING CACHE PROBE", [
    `target: ${code(r.path)}`,
    `header cache signal: ${r.headerSignal ?? "none (stripped)"}`,
  ]);

  section("SAMPLES (ms)", [
    `MISS (cache-busted): ${r.missSamples.map((n) => Math.round(n)).join(" ") || "(none)"} -> median ${Math.round(r.missMedian)}`,
    `STEADY (repeated): ${r.steadySamples.map((n) => Math.round(n)).join(" ") || "(none)"} -> median ${Math.round(r.steadyMedian)}`,
  ]);

  section("VERDICT", [
    `ratio steady/miss: ${r.ratio > 0 ? r.ratio.toFixed(2) : "n/a"}`,
    `cached: ${r.verdict}`,
    `confidence: ${r.confidence}`,
  ]);

  if (r.notes.length > 0) section("NOTES", r.notes);

  return out.join("\n");
}
