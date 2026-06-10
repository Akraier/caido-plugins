// Path-normalization discrepancy detection for static-directory AND file-name cache rules.
//
// Direction A — origin resolves ..%2f, cache does NOT (DIRECTORY rules only):
//     payload  /<prefix>/..%2f<dynamic>
//     A is impossible for a file-name rule: the cache only stores the exact name, so a path
//     with the dynamic part appended can never match the rule.
//
// Direction B — cache resolves the encoded traversal, origin does NOT, plus a delimiter the
//     origin truncates at but the cache keeps (DIRECTORY and FILE-NAME rules):
//     payload  /<dynamic><delim>%2f%2e%2e%2f<target>
//     origin truncates at <delim> -> /<dynamic>; cache resolves -> <target> and stores it.
//
// Safety: directory Direction B resolves to a RANDOM path under the prefix, so even a cache
// that keys by the normalized path only ever stores under a throwaway key. A file-name rule
// matches the exact name and cannot be randomised, so before probing we check whether the
// cache keys by the normalized path (the probe HITs the real file); if so we flag the
// poisoning risk and refuse to run the confirming probe.
import type { Request as CaidoRequest, Response as CaidoResponse } from "caido:utils";

import { isHit, randSeg } from "./cache.js";
import { DELIMITER_PROBES } from "./delimiter.js";
import {
  anchorDist,
  anchorOf,
  anchorsSeparable,
  confirmCached,
  nearest,
  send,
  specFor,
  type Anchor,
  type EngineSDK,
} from "./probe.js";
import type { NormalizationResult } from "./types.js";

const ORIGIN_ENCODINGS: Array<{ enc: string; build: (rand: string, cmp: string) => string }> = [
  { enc: "enc-2nd-slash", build: (r, c) => `/${r}/..%2f${c}` },
  { enc: "enc-both-slashes", build: (r, c) => `/${r}%2f..%2f${c}` },
  { enc: "enc-dots", build: (r, c) => `/${r}/%2e%2e/${c}` },
  { enc: "enc-full", build: (r, c) => `/${r}%2f%2e%2e%2f${c}` },
];

function firstSegment(path: string): { prefix: string; rest: string } {
  const clean = path.split("?")[0] ?? path;
  const segs = clean.split("/").filter((s) => s.length > 0);
  const prefix = "/" + (segs[0] ?? "");
  const rest = segs.slice(1).join("/");
  return { prefix, rest };
}

function trimLeadingSlash(p: string): string {
  return p.startsWith("/") ? p.slice(1) : p;
}

async function originTruncatesAt(
  sdk: EngineSDK,
  base: CaidoRequest,
  comparerPath: string,
  delim: string,
  good: Anchor,
  error: Anchor,
): Promise<boolean> {
  const probe = anchorOf(
    await send(sdk, specFor(base, { path: `${comparerPath}${delim}${randSeg()}` })),
  );
  return nearest(probe, good, error) === "good";
}

async function cacheTruncatesAt(
  sdk: EngineSDK,
  base: CaidoRequest,
  basePath: string,
  delim: string,
): Promise<boolean> {
  await send(sdk, specFor(base, { path: basePath }));
  await send(sdk, specFor(base, { path: basePath }));
  const v = await send(
    sdk,
    specFor(base, { path: `${basePath}${delim}${randSeg()}` }),
  );
  return isHit(v.cstatus);
}

export async function runNormalizationScan(
  sdk: EngineSDK,
  base: CaidoRequest,
  comparerPath: string,
  _baseResponse: CaidoResponse | undefined,
): Promise<NormalizationResult> {
  const host = base.getHost().toLowerCase();
  const basePath = base.getPath();
  const { prefix, rest } = firstSegment(basePath);
  const prefixTrim = trimLeadingSlash(prefix);
  const fullPathTrim = trimLeadingSlash(basePath);

  const result: NormalizationResult = {
    host,
    basePath,
    prefix,
    comparerPath,
    aborted: false,
    matchType: "filename",
    dirRuleConfirmed: false,
    cacheKeysNormalized: false,
    originNormalizes: false,
    originEncodings: [],
    originTestable: false,
    cachePrependCached: false,
    cacheMidCached: false,
    cacheNormalizesEncoded: false,
    exploitableOrigin: false,
    exploitableCacheNorm: false,
    exploitable: false,
    timingInferred: false,
    notes: [],
  };

  // Gate: only meaningful on a cached resource.
  const baseCached = await confirmCached(sdk, base, basePath);
  if (baseCached.via === "timing") result.timingInferred = true;
  if (!baseCached.cached) {
    result.aborted = true;
    result.abortReason =
      "baseline is not cached — run this on the cached resource where the cache rule was detected";
    return result;
  }
  const baseFileAnchor = anchorOf(baseCached.last);

  // Classify the rule: an arbitrary extensionless path under the prefix that still caches
  // means a /<prefix> directory rule; otherwise treat it as an exact file-name rule.
  if (rest.length > 0) {
    const arb = await confirmCached(sdk, base, `${prefix}/${randSeg()}`);
    result.dirRuleConfirmed = arb.cached;
    if (arb.cached) result.matchType = "directory";
  }
  if (result.matchType === "filename") {
    result.notes.push(
      "File-name rule: Direction A (origin normalization) is not applicable — the cache only stores the exact file name, so /<name>/..%2f<dynamic> can never match. Testing cache normalization (Direction B) only.",
    );
  }

  // ---- origin side (needed by both directions) --------------------------------
  const good: Anchor = anchorOf(await send(sdk, specFor(base, { path: comparerPath })));
  const error: Anchor = anchorOf(
    await send(sdk, specFor(base, { path: comparerPath + randSeg() })),
  );
  result.originTestable = anchorsSeparable(good, error);
  if (!result.originTestable) {
    result.notes.push(
      `Origin comparer ${comparerPath} did not produce distinguishable good/error responses — origin normalization is unverified. Set CACHE_PROFILER_NORM_PATH to a stable, non-cached dynamic endpoint.`,
    );
  } else {
    const cmp = trimLeadingSlash(comparerPath);
    for (const variant of ORIGIN_ENCODINGS) {
      const probe = anchorOf(
        await send(sdk, specFor(base, { path: variant.build(randSeg(), cmp) })),
      );
      if (nearest(probe, good, error) === "good") result.originEncodings.push(variant.enc);
    }
    result.originNormalizes = result.originEncodings.length > 0;
  }

  // ---- Direction A (directory only) -------------------------------------------
  if (result.matchType === "directory") {
    result.cacheMidCached = (
      await confirmCached(sdk, base, `${prefix}/..%2f${rest}`)
    ).cached;
    result.exploitableOrigin = result.originNormalizes && result.cacheMidCached;
  }

  // ---- Direction B cache-normalization signal ---------------------------------
  // Resolve target: directory -> random path under the prefix (poison-safe); file-name ->
  // the exact path (guarded below).
  if (result.matchType === "directory") {
    const safeTarget = `${prefixTrim}/${randSeg()}`;
    result.cacheNormalizesEncoded = (
      await confirmCached(sdk, base, `/${randSeg()}%2f%2e%2e%2f${safeTarget}`)
    ).cached;
  } else {
    // File-name keying guard: one probe first. An immediate HIT matching the real file means
    // the cache keys by the NORMALIZED path — exploiting it would poison /<file>. Refuse.
    const probe1 = await send(
      sdk,
      specFor(base, { path: `/${randSeg()}%2f%2e%2e%2f${fullPathTrim}` }),
    );
    const collapsesOntoFile =
      isHit(probe1.cstatus) && anchorDist(anchorOf(probe1), baseFileAnchor) < 64;
    if (collapsesOntoFile) {
      result.cacheKeysNormalized = true;
      result.cacheNormalizesEncoded = true;
      result.notes.push(
        "Cache keys by the NORMALIZED path: the encoded traversal collapses onto the real file's cache entry. Exploiting this would overwrite the real file (cache poisoning), not safe deception — NOT auto-confirming. Validate manually with care.",
      );
    } else {
      const probe2 = await send(
        sdk,
        specFor(base, { path: `/${randSeg()}%2f%2e%2e%2f${fullPathTrim}` }),
      );
      result.cacheNormalizesEncoded = isHit(probe2.cstatus);
    }
  }

  // ---- Direction B delimiter split + confirm ----------------------------------
  const originKeepsEncoded = !result.originEncodings.includes("enc-full");
  const canRunB =
    result.originTestable &&
    result.cacheNormalizesEncoded &&
    originKeepsEncoded &&
    !result.cacheKeysNormalized; // never confirm a poisoning-keyed file-name rule

  if (canRunB) {
    let chosen: string | undefined;
    for (const delim of DELIMITER_PROBES) {
      const originTrunc = await originTruncatesAt(sdk, base, comparerPath, delim, good, error);
      if (!originTrunc) continue;
      const cacheTrunc = await cacheTruncatesAt(sdk, base, basePath, delim);
      if (!cacheTrunc) {
        chosen = delim;
        break;
      }
    }

    if (chosen !== undefined) {
      result.cacheNormDelimiter = chosen;
      const target =
        result.matchType === "directory"
          ? `${prefixTrim}/${randSeg()}`
          : fullPathTrim;
      const payload = `${comparerPath}${chosen}%2f%2e%2e%2f${target}`;
      const conf = await confirmCached(sdk, base, payload);
      const servedDynamic = nearest(anchorOf(conf.last), good, error) === "good";
      result.exploitableCacheNorm = conf.cached && servedDynamic;
    }
  }

  result.exploitable = result.exploitableOrigin || result.exploitableCacheNorm;

  if (result.exploitable && !result.dirRuleConfirmed && result.matchType === "directory") {
    result.notes.push(
      "Exploitability is provisional: the /<prefix> directory rule was not positively confirmed. Validate against a real dynamic path before reporting.",
    );
  }

  return result;
}

// ---- reporting -------------------------------------------------------------

function code(s: string): string {
  return "`" + s + "`";
}

export function normalizationSummary(r: NormalizationResult): string {
  if (r.aborted) return `bad baseline — ${r.abortReason ?? "unsuitable"}`;
  const parts: string[] = [`${r.matchType} rule`];
  if (r.exploitableOrigin) parts.push("EXPLOITABLE (origin-norm)");
  if (r.exploitableCacheNorm) parts.push("EXPLOITABLE (cache-norm)");
  if (r.cacheKeysNormalized) parts.push("poisoning risk — skipped");
  if (parts.length === 1) {
    parts.push(`origin ${r.originNormalizes ? "resolves" : "keeps"} ..%2f`);
    parts.push(`cache ${r.cacheNormalizesEncoded ? "resolves" : "keeps"} %2f%2e%2e%2f`);
  }
  return parts.join(", ");
}

export function normalizationTitle(r: NormalizationResult): string {
  if (r.aborted) {
    return `Cache Profiler — path normalization: unsuitable baseline — ${r.host}`;
  }
  if (r.exploitable) {
    return `Cache Profiler — WEB CACHE DECEPTION (path normalization) — ${r.host}`;
  }
  return `Cache Profiler — path normalization (${r.matchType}) — ${r.host}`;
}

export function formatNormalizationResult(r: NormalizationResult): string {
  const out: string[] = [];
  const section = (title: string, items: string[]): void => {
    if (out.length > 0) out.push("");
    out.push(`**${title}**`);
    out.push("");
    for (const item of items) out.push(`- ${item}`);
  };

  if (r.aborted) {
    section("PATH NORMALIZATION", [
      `baseline: ${code(r.basePath)}`,
      `**aborted** — ${r.abortReason ?? "unsuitable baseline"}`,
    ]);
    if (r.notes.length > 0) section("NOTES", r.notes);
    return out.join("\n");
  }

  section("PATH NORMALIZATION", [
    `baseline: ${code(r.basePath)}`,
    `rule type: ${r.matchType}`,
    r.matchType === "directory"
      ? `prefix: ${code(r.prefix)} (dir rule confirmed: ${r.dirRuleConfirmed ? "yes" : "no"})`
      : `file: ${code(r.basePath)}`,
    `origin comparer: ${code(r.comparerPath)}`,
  ]);

  section("ORIGIN", [
    `resolves ..%2f: ${r.originNormalizes ? "yes" : r.originTestable ? "no" : "unverified"}`,
    `via encodings: ${r.originEncodings.length > 0 ? r.originEncodings.join(", ") : "(none)"}`,
  ]);

  const cacheItems: string[] = [
    `resolves %2f%2e%2e%2f (encoded): ${r.cacheNormalizesEncoded ? "yes" : "no"}`,
  ];
  if (r.matchType === "directory") {
    cacheItems.unshift(
      `keeps /<prefix>/..%2f<rest> raw: ${r.cacheMidCached ? "yes" : "no"}`,
    );
  }
  if (r.cacheKeysNormalized) {
    cacheItems.push("keys by normalized path: yes (POISONING RISK — confirm skipped)");
  }
  section("CACHE", cacheItems);

  // Direction A — directory only.
  if (r.matchType === "directory") {
    const aItems: string[] = [`exploitable: ${r.exploitableOrigin ? "yes" : "no"}`];
    if (r.exploitableOrigin) {
      const enc = r.originEncodings[0] ?? "enc-2nd-slash";
      aItems.push(`payload: ${code(`${r.prefix}/..%2f<dynamic-path>`)} (encoding: ${enc})`);
    }
    section("VERDICT A — origin normalization", aItems);
  }

  // Direction B — both rule types.
  const target =
    r.matchType === "directory" ? trimLeadingSlash(r.prefix) : trimLeadingSlash(r.basePath);
  const bItems: string[] = [`exploitable: ${r.exploitableCacheNorm ? "yes" : "no"}`];
  if (r.exploitableCacheNorm && r.cacheNormDelimiter !== undefined) {
    bItems.push(`delimiter (origin truncates, cache keeps): ${code(r.cacheNormDelimiter)}`);
    bItems.push(
      `payload: ${code(`/<dynamic-path>${r.cacheNormDelimiter}%2f%2e%2e%2f${target}`)}`,
    );
  } else if (r.cacheKeysNormalized) {
    bItems.push("not confirmed — cache keys by normalized path (poisoning risk, skipped)");
  } else if (r.cacheNormDelimiter !== undefined) {
    bItems.push(
      `delimiter ${code(r.cacheNormDelimiter)} qualified, but the combined payload was not confirmed cached`,
    );
  }
  section("VERDICT B — cache normalization", bItems);

  if (r.timingInferred) {
    section("CONFIDENCE", [
      "**timing-inferred** cache verdicts present (host strips cache headers) — confirm with the Timing cache probe",
    ]);
  }

  if (r.notes.length > 0) section("NOTES", r.notes);

  return out.join("\n");
}
