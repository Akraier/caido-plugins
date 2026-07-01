// On-demand unkeyed-header detection (web cache poisoning, Param Miner style). For each candidate
// request header it injects a unique canary, checks whether the canary reflects, then confirms
// the header is unkeyed AND cached by re-requesting WITHOUT the header under the same cache key.
//
// SAFETY — every request carries a unique `cpb=<rand>` query cache-buster, so the only cache
// entries ever populated are keyed to throwaway URLs no real user visits. Before injecting
// anything, a preflight verifies the buster actually creates a distinct cache key; if the cache
// ignores the query string (so the buster cannot isolate probes), the scan ABORTS rather than
// risk poisoning the live entry served to other users.
import type { Request as CaidoRequest, Response as CaidoResponse } from "caido:utils";

import { cacheState, hitsOf, isHit, randSeg, type HeaderMap } from "./cache.js";
import { POISON_HEADERS } from "./poison_headers.js";
import { type EngineSDK, type Probe, sendWithBody, specFor } from "./probe.js";
import type { MatchKind, OobReflection, PoisonResult, UnkeyedHit } from "./types.js";

// Supplied by the caller when an interactsh client is enabled: mints per-core OOB payloads,
// registers each core->header for async callback attribution, and extends the correlation window.
export type OobHook = {
  mintPayload: (core: string) => string;
  register: (core: string, header: string) => void;
  keepAlive: () => void;
  domain: string; // interactsh server host, for matchKind classification
};

const BUSTER = "cpb"; // cache-buster query parameter name

// Stop the sweep after this many consecutive rate-limit / bot responses, rather than hammering
// a limiter — mirrors the recon-throttle discipline.
const THROTTLE_HALT = 5;

// Headers injected per batch request. Each carries its own canary, so one response identifies
// every reflecting header in the batch directly. Kept modest so the combined header block stays
// well under typical server limits; an oversize rejection (431/400) is handled by splitting.
const BATCH = 50;

function canaryToken(): string {
  return `cp${randSeg()}`;
}

// Where the canary came back, and a note when the sink is high-value.
function reflections(canary: string, probe: Probe, body: string): string[] {
  const out: string[] = [];
  if (body.includes(canary)) out.push("body");
  for (const [name, values] of Object.entries(probe.headers)) {
    if (values.some((v) => v.includes(canary))) out.push(`header:${name}`);
  }
  return out;
}

function impactOf(reflectedIn: string[]): string | undefined {
  if (reflectedIn.some((r) => r === "header:location")) {
    return "reflected in Location — open-redirect / redirect poisoning";
  }
  if (reflectedIn.some((r) => r.startsWith("header:access-control-allow-origin"))) {
    return "reflected in ACAO — CORS poisoning";
  }
  if (reflectedIn.some((r) => r.startsWith("header:set-cookie"))) {
    return "reflected in Set-Cookie — cookie injection";
  }
  if (reflectedIn.includes("body")) {
    return "reflected in body — check for absolute-URL / script-src / XSS sink";
  }
  return undefined;
}

// Did the resource transition into a served-from-cache state between two identical requests?
function cachedTransition(p1: Probe, p2: Probe): boolean {
  return (
    isHit(cacheState(p2.headers)) ||
    (p1.age >= 0 && p2.age > p1.age) ||
    hitsOf(p2.headers) > hitsOf(p1.headers)
  );
}

// A brand-new unique buster that comes back already HIT means the cache served an existing entry
// for a never-seen query string => the query is NOT in the cache key => a buster cannot isolate.
function queryIsUnkeyed(h: HeaderMap, age: number): boolean {
  return isHit(cacheState(h)) || age > 0;
}

type ScanCtx = { blocks: number; halted: boolean; sent: number; domainSeen?: boolean };

// Inject a whole group of headers in ONE request, each with its own canary, and return the names
// of those whose canary reflected. A group that reflects nothing is eliminated in a single
// request. On an oversize rejection (431/400) the group is split in half and each half retried —
// the binary fallback. On a run of 429/503 the scan halts.
async function probeGroup(
  sdk: EngineSDK,
  base: CaidoRequest,
  headers: string[],
  ctx: ScanCtx,
): Promise<string[]> {
  if (ctx.halted || headers.length === 0) return [];

  const buster = `${BUSTER}=${randSeg()}`;
  const inject: Record<string, string> = {};
  const byCanary = new Map<string, string>();
  for (const h of headers) {
    const c = canaryToken();
    inject[h] = c;
    byCanary.set(c, h);
  }

  const res = await sendWithBody(
    sdk,
    specFor(base, { appendQuery: buster, marker: true, headers: inject }),
  );
  ctx.sent++;

  if (res.probe.status === 429 || res.probe.status === 503) {
    if (++ctx.blocks >= THROTTLE_HALT) ctx.halted = true;
    return [];
  }
  ctx.blocks = 0;

  // Header block too large for the server — split and recurse (binary fallback).
  if ((res.probe.status === 431 || res.probe.status === 400) && headers.length > 1) {
    const mid = Math.floor(headers.length / 2);
    const left = await probeGroup(sdk, base, headers.slice(0, mid), ctx);
    const right = await probeGroup(sdk, base, headers.slice(mid), ctx);
    return [...left, ...right];
  }

  const found: string[] = [];
  for (const [canary, header] of byCanary) {
    if (reflections(canary, res.probe, res.body).length > 0) found.push(header);
  }
  return found;
}

// OOB pass: inject an interactsh payload (mintPayload(core)) for every header in a batch, register
// each core for async callback attribution, and record any SYNCHRONOUS reflection of the payload
// (an SSRF/redirect-grade lead before any callback). Same batching + split-on-oversize + throttle.
async function oobProbeGroup(
  sdk: EngineSDK,
  base: CaidoRequest,
  headers: string[],
  hook: OobHook,
  ctx: ScanCtx,
): Promise<OobReflection[]> {
  if (ctx.halted || headers.length === 0) return [];

  const buster = `${BUSTER}=${randSeg()}`;
  const inject: Record<string, string> = {};
  const entries: { core: string; header: string; value: string }[] = [];
  for (const h of headers) {
    const core = canaryToken();
    const value = hook.mintPayload(core);
    inject[h] = value;
    hook.register(core, h); // register EVERY header — a callback can fire without reflection
    entries.push({ core, header: h, value });
  }

  const res = await sendWithBody(
    sdk,
    specFor(base, { appendQuery: buster, marker: true, headers: inject }),
  );
  ctx.sent++;

  if (res.probe.status === 429 || res.probe.status === 503) {
    if (++ctx.blocks >= THROTTLE_HALT) ctx.halted = true;
    return [];
  }
  ctx.blocks = 0;

  if ((res.probe.status === 431 || res.probe.status === 400) && headers.length > 1) {
    const mid = Math.floor(headers.length / 2);
    const left = await oobProbeGroup(sdk, base, headers.slice(0, mid), hook, ctx);
    const right = await oobProbeGroup(sdk, base, headers.slice(mid), hook, ctx);
    return [...left, ...right];
  }

  const hay = (
    res.body +
    " " +
    Object.values(res.probe.headers).flat().join(" ")
  ).toLowerCase();
  const domain = hook.domain.toLowerCase();
  if (domain.length > 0 && hay.includes(domain)) ctx.domainSeen = true;

  const out: OobReflection[] = [];
  for (const { core, header, value } of entries) {
    let kind: MatchKind | undefined;
    if (hay.includes(value.toLowerCase())) kind = "intact";
    else if (hay.includes(core.toLowerCase())) kind = "core";
    // domain-only is shared across the batch -> not attributable to one header; ctx.domainSeen note
    if (kind !== undefined) out.push({ header, matchKind: kind });
  }
  return out;
}

export async function runUnkeyedHeaderScan(
  sdk: EngineSDK,
  base: CaidoRequest,
  _response: CaidoResponse | undefined,
  oob?: OobHook,
): Promise<PoisonResult> {
  const host = base.getHost().toLowerCase();
  const basePath = base.getPath();
  const result: PoisonResult = {
    host,
    basePath,
    aborted: false,
    cacheable: false,
    querySafe: false,
    tested: 0,
    hits: [],
    notes: [],
    oobEnabled: oob !== undefined,
    oobReflections: [],
    oobDomainReflected: false,
  };

  // ---- preflight: cacheability + buster safety -------------------------
  const bustA = `${BUSTER}=${randSeg()}`;
  const a1 = await sendWithBody(sdk, specFor(base, { appendQuery: bustA, marker: true }));
  const a2 = await sendWithBody(sdk, specFor(base, { appendQuery: bustA, marker: true }));
  result.cacheable = cachedTransition(a1.probe, a2.probe);

  const bustB = `${BUSTER}=${randSeg()}`;
  const b = await sendWithBody(sdk, specFor(base, { appendQuery: bustB, marker: true }));
  const unkeyedQuery = queryIsUnkeyed(b.probe.headers, b.probe.age);

  if (result.cacheable && unkeyedQuery) {
    result.aborted = true;
    result.abortReason =
      "cache ignores the query string — a query cache-buster cannot isolate probes, so " +
      "injecting could poison the live entry served to other users. Aborted for safety.";
    return result;
  }
  result.querySafe = !unkeyedQuery;
  if (!result.cacheable) {
    result.notes.push(
      "resource not observed cacheable under a buster — reflections below are leads only " +
        "(no cached-confirmation possible here; a cached sibling path may still be poisonable).",
    );
  }

  // ---- detection: batched, distinct-canary, split-on-oversize ---------
  // Send headers in batches; each header gets its own canary so a reflecting response names the
  // culprit(s) directly. Whole batches that reflect nothing are eliminated in a single request.
  const ctx: ScanCtx = { blocks: 0, halted: false, sent: 0 };
  const reflectors = new Set<string>();
  for (let i = 0; i < POISON_HEADERS.length && !ctx.halted; i += BATCH) {
    const group = POISON_HEADERS.slice(i, i + BATCH);
    for (const h of await probeGroup(sdk, base, group, ctx)) reflectors.add(h);
    result.tested = Math.min(i + BATCH, POISON_HEADERS.length);
  }
  result.notes.push(
    ctx.halted
      ? `halted on throttle — tested ${result.tested}/${POISON_HEADERS.length} headers in ${ctx.sent} batched requests.`
      : `scanned ${POISON_HEADERS.length} headers in ${ctx.sent} batched requests (${reflectors.size} reflected).`,
  );

  // ---- confirmation: isolate each reflector, test unkeyed + cached -----
  for (const header of reflectors) {
    if (ctx.halted) break;
    const buster = `${BUSTER}=${randSeg()}`;
    const canary = canaryToken();
    const inj = await sendWithBody(
      sdk,
      specFor(base, { appendQuery: buster, marker: true, headers: { [header]: canary } }),
    );
    // Re-confirm reflection in isolation (filters batch-context false positives).
    const reflectedIn = reflections(canary, inj.probe, inj.body);
    if (reflectedIn.length === 0) continue;

    // Unkeyed + cached: re-request WITHOUT the header, same buster (same cache key). If the canary
    // returns, the cache served a stored copy the header poisoned => the header is unkeyed.
    let cached = false;
    if (result.cacheable) {
      const clean = await sendWithBody(
        sdk,
        specFor(base, { appendQuery: buster, marker: true }),
      );
      cached = reflections(canary, clean.probe, clean.body).length > 0;
    }

    const hit: UnkeyedHit = { header, canary, reflectedIn, cached };
    const impact = impactOf(reflectedIn);
    if (impact !== undefined) hit.impact = impact;
    result.hits.push(hit);
  }

  // ---- OOB pass (interactsh) — blind / SSRF channel --------------------
  // Separate from the (authoritative, unpolluted) sterile passes above: the dotted OOB hostname
  // can error / reroute, so it must not contaminate the cache-poisoning verdict. Callbacks arrive
  // asynchronously and are emitted as their own findings; this pass records synchronous hits.
  if (oob !== undefined) {
    oob.keepAlive(); // window covers the sweep...
    const oobCtx: ScanCtx = { blocks: 0, halted: false, sent: 0, domainSeen: false };
    const refl: OobReflection[] = [];
    for (let i = 0; i < POISON_HEADERS.length && !oobCtx.halted; i += BATCH) {
      refl.push(
        ...(await oobProbeGroup(sdk, base, POISON_HEADERS.slice(i, i + BATCH), oob, oobCtx)),
      );
    }
    oob.keepAlive(); // ...and extends past the (possibly long) sweep to now + window
    // dedupe by header, preferring the strongest matchKind
    const rank: Record<MatchKind, number> = { intact: 3, core: 2, domain: 1 };
    const best = new Map<string, OobReflection>();
    for (const r of refl) {
      const cur = best.get(r.header);
      if (cur === undefined || rank[r.matchKind] > rank[cur.matchKind]) best.set(r.header, r);
    }
    result.oobReflections = [...best.values()];
    result.oobDomainReflected = oobCtx.domainSeen === true;
    result.notes.push(
      `OOB pass: injected interactsh payloads for ${POISON_HEADERS.length} headers in ` +
        `${oobCtx.sent} batched requests; DNS/HTTP callbacks arrive as separate findings within ` +
        `the correlation window. ${result.oobReflections.length} synchronous reflection(s).`,
    );
  }

  return result;
}

// ---- formatting ------------------------------------------------------------

export function poisonTitle(r: PoisonResult): string {
  if (r.aborted) return `Cache Poisoning — ABORTED (unsafe) — ${r.host}`;
  const confirmed = r.hits.filter((h) => h.cached);
  if (confirmed.length > 0) {
    return `UNKEYED HEADER${confirmed.length > 1 ? "S" : ""} — ${r.host}${r.basePath}`;
  }
  if (r.hits.length > 0) return `Reflected headers (unconfirmed) — ${r.host}${r.basePath}`;
  return `Cache Poisoning — no unkeyed headers — ${r.host}${r.basePath}`;
}

export function poisonSummary(r: PoisonResult): string {
  if (r.aborted) return "ABORTED (query unkeyed — unsafe to probe)";
  const confirmed = r.hits.filter((h) => h.cached).length;
  return `${r.tested} headers tested, ${confirmed} unkeyed+cached, ${r.hits.length - confirmed} reflected-only`;
}

export function formatPoisonResult(r: PoisonResult): string {
  const lines: string[] = [];

  if (r.aborted) {
    lines.push("**CACHE POISONING — ABORTED**", "", `- ${r.abortReason}`);
    return lines.join("\n");
  }

  const confirmed = r.hits.filter((h) => h.cached);
  const reflectedOnly = r.hits.filter((h) => !h.cached);

  lines.push(
    confirmed.length > 0 ? "**UNKEYED HEADERS — CACHE POISONING**" : "**CACHE POISONING SCAN**",
    "",
    `- target: \`${r.basePath}\``,
    `- cacheable under buster: ${r.cacheable ? "yes" : "no"}`,
    `- query buster safe (distinct key): ${r.querySafe ? "yes" : "no"}`,
    `- headers tested: ${r.tested}`,
  );

  if (confirmed.length > 0) {
    lines.push("", "**UNKEYED + CACHED** (poisoning — reproduce and assess impact)");
    for (const h of confirmed) {
      lines.push(
        `- \`${h.header}\` -> reflected in ${h.reflectedIn.join(", ")}${
          h.impact !== undefined ? `  (${h.impact})` : ""
        }`,
      );
    }
  }

  if (reflectedOnly.length > 0) {
    lines.push("", "**REFLECTED ONLY** (keyed or not cached — leads, not confirmed poisoning)");
    for (const h of reflectedOnly) {
      lines.push(`- \`${h.header}\` -> reflected in ${h.reflectedIn.join(", ")}`);
    }
  }

  if (r.hits.length === 0) {
    lines.push("", "- no candidate header reflected into the response.");
  }

  if (r.oobEnabled) {
    lines.push(
      "",
      "**OOB (interactsh) pass**",
      "- payloads injected for all tested headers; DNS/HTTP callbacks arrive as separate `OOB INTERACTION` findings within the correlation window.",
    );
    if (r.oobReflections.length > 0) {
      lines.push("- OOB payload reflected synchronously (SSRF / redirect-grade if `intact`):");
      for (const o of r.oobReflections) {
        lines.push(`  - \`${o.header}\` (${o.matchKind})`);
      }
    }
    if (r.oobDomainReflected) {
      lines.push(
        "- note: the OOB domain appeared in a response without a specific token (shared across the batch — not attributable to one header); inspect manually.",
      );
    }
  }

  for (const n of r.notes) lines.push("", `> ${n}`);

  lines.push(
    "",
    "_Every probe used a unique `cpb=` cache-buster — no live cache entry was touched._",
  );
  return lines.join("\n");
}
