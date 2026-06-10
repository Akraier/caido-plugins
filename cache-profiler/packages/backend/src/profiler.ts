// Active cache-behaviour profiler. Drives the probe state machine described in SPEC.md.
// Every probe targets a random unique segment so cache population is non-destructive.
import type { Request as CaidoRequest, Response as CaidoResponse } from "caido:utils";

import {
  cacheSignals,
  DELIMITERS,
  isCacheCandidate,
  isHit,
  lower,
  originWantsCaching,
  parseCacheControl,
  parsePath,
  parseVary,
  randSeg,
  STATIC_EXTENSIONS,
  type HeaderMap,
} from "./cache.js";
import {
  confirmCached,
  looksLikeControl404,
  sameBody,
  send,
  sharesEntry,
  specFor,
  type EngineSDK,
} from "./probe.js";
import type { CacheKeyDim, CacheProfile } from "./types.js";

// ---- main entry ------------------------------------------------------------

export async function runProfile(
  sdk: EngineSDK,
  base: CaidoRequest,
  baseResponse: CaidoResponse | undefined,
): Promise<CacheProfile> {
  const host = base.getHost().toLowerCase();
  const url = base.getUrl();
  const basePath = base.getPath();

  const h0: HeaderMap =
    baseResponse !== undefined ? lower(baseResponse.getHeaders()) : {};
  const baseBody = baseResponse !== undefined ? baseResponse.getBody() : undefined;
  const baseBodyLen = baseBody !== undefined ? baseBody.toRaw().length : 0;

  const profile: CacheProfile = {
    url,
    host,
    status: baseResponse !== undefined ? baseResponse.getCode() : 0,
    detected: isCacheCandidate(h0),
    signals: cacheSignals(h0),
    confirmedCached: false,
    rule: "none",
    cachedExtensions: [],
    ignoredExtensions: [],
    keyDims: ["path"],
    vary: parseVary(h0),
    varyMismatch: [],
    caseInsensitiveKey: false,
    detectionVia: "none",
    intent: "unknown",
    originCacheControl: parseCacheControl(h0).raw || undefined,
    delimiters: [],
    leakConfirmed: false,
    notes: [],
  };

  if (!profile.detected) {
    profile.notes.push(
      "No cache signal in the triggering response — nothing to profile.",
    );
    return profile;
  }

  // Phase 2 — confirm the triggering URL is actually stored.
  const conf = await confirmCached(sdk, base, basePath);
  profile.confirmedCached = conf.cached;
  profile.detectionVia = conf.via;
  if (conf.firstMiss !== undefined && conf.firstMiss.cc.raw.length > 0) {
    profile.originCacheControl = conf.firstMiss.cc.raw;
  }

  if (profile.confirmedCached) {
    await profileCachedResource(sdk, base, basePath, profile);
  } else {
    await probeDeception(sdk, base, basePath, baseBodyLen, profile);
  }

  return profile;
}

// Scenario A — the triggering URL is a cached resource. Classify rule, key, intent.
async function profileCachedResource(
  sdk: EngineSDK,
  base: CaidoRequest,
  basePath: string,
  profile: CacheProfile,
): Promise<void> {
  const parts = parsePath(basePath);
  const dir = parts.dir;

  // Phase 3 — directory rule? Random filename AND random non-static extension: if that
  // still caches, the edge caches everything under this prefix regardless of extension.
  const dirProbe = await confirmCached(
    sdk,
    base,
    `${dir}/${randSeg()}.${randSeg()}`,
  );

  if (dirProbe.cached) {
    profile.rule = "static directory";
  } else {
    // Phase 3b — extension sweep. Status-agnostic on purpose: a cached 404 for `.css`
    // still proves the edge keys on the extension, so we do NOT filter 404s here
    // (that filter is only for path-confusion body matching in Scenario B).
    for (const ext of STATIC_EXTENSIONS) {
      const probe = await confirmCached(sdk, base, `${dir}/${randSeg()}.${ext}`);
      if (probe.cached) profile.cachedExtensions.push(ext);
      else profile.ignoredExtensions.push(ext);
    }

    if (profile.cachedExtensions.length > 0) {
      profile.rule = "static extension";
    } else {
      const cc = parseCacheControl({
        "cache-control": [profile.originCacheControl ?? ""],
      });
      profile.rule = originWantsCaching(cc) ? "origin-directed" : "specific file";
      profile.notes.push(
        "The triggering URL is cached but no random same-extension probe cached — the edge may only cache 200s with origin Cache-Control, so this reads as origin-directed rather than a blanket extension rule.",
      );
    }
  }

  // Phase 4 — cache-key composition.
  const queryShares = await sharesEntry(sdk, base, basePath, {
    appendQuery: `${randSeg()}=${randSeg()}`,
  });
  if (!queryShares) profile.keyDims.push("query");

  const cookieShares = await sharesEntry(sdk, base, basePath, {
    setCookie: `${randSeg()}=${randSeg()}`,
  });
  if (!cookieShares) profile.keyDims.push("cookie");

  // Case sensitivity of the cache key: an upper-cased path that HITs the (already cached)
  // base entry means the cache normalises case — two differently-cased URLs collide.
  const upper = basePath.toUpperCase();
  if (upper !== basePath) {
    const f = await send(sdk, specFor(base, { path: upper }));
    if (isHit(f.cstatus)) profile.caseInsensitiveKey = true;
  }

  // Phase 4b — declared-Vary vs observed-key mismatch.
  for (const v of profile.vary) {
    if (
      v.toLowerCase() === "cookie" &&
      !profile.keyDims.includes("cookie" as CacheKeyDim)
    ) {
      profile.varyMismatch.push("Cookie");
    }
  }

  // Phase 5 — intent.
  const cc = parseCacheControl({ "cache-control": [profile.originCacheControl ?? ""] });
  profile.intent = originWantsCaching(cc)
    ? "ORIGIN OPTS IN"
    : "EDGE OVERRIDES ORIGIN";

  if (profile.varyMismatch.length > 0) {
    profile.notes.push(
      "Declared Vary: Cookie but cookie is not in the observed cache key — cross-user serving possible.",
    );
  }
}

// Scenario B — the triggering URL is NOT cached (dynamic / authenticated). Test whether
// delimiter-based path confusion can make it cacheable, then confirm cross-session leak.
async function probeDeception(
  sdk: EngineSDK,
  base: CaidoRequest,
  basePath: string,
  baseBodyLen: number,
  profile: CacheProfile,
): Promise<void> {
  const cc = parseCacheControl({ "cache-control": [profile.originCacheControl ?? ""] });
  const originPrivate = !originWantsCaching(cc);

  // Phase 0 — calibrate against this host's not-found behaviour so the Caido crafted-URL
  // artifact and negative caching aren't read as a confused 200 body in the matrix below.
  const ctrl404 = await send(
    sdk,
    specFor(base, { path: `/${randSeg()}.${randSeg()}` }),
  );

  let firstConfusedPath: string | undefined;
  let firstAuthedLen = 0;

  // Phase 6 — delimiter path-confusion matrix.
  for (const delim of DELIMITERS) {
    const confusedPath = `${basePath}${delim}${randSeg()}.css`;
    const probe = await confirmCached(sdk, base, confusedPath);
    const last = probe.last;
    const routedSame =
      last.status >= 200 &&
      last.status < 300 &&
      sameBody(last.bodyLen, baseBodyLen) &&
      !looksLikeControl404(last, ctrl404);
    if (probe.cached && routedSame) {
      profile.delimiters.push(delim);
      if (firstConfusedPath === undefined) {
        firstConfusedPath = confusedPath;
        firstAuthedLen = last.bodyLen;
      }
    }
  }

  if (profile.delimiters.length > 0) {
    profile.rule = "static extension";
    profile.intent = "EDGE OVERRIDES ORIGIN";
    profile.notes.push(
      "Dynamic/authenticated response became cacheable under a static-looking path — web cache deception candidate.",
    );

    // Operator-gated deception confirmation: populate with auth cookie, then fetch
    // the same confused URL with the cookie stripped. A HIT returning the authed
    // body proves the cache serves one session's content to another.
    if (firstConfusedPath !== undefined) {
      await send(sdk, specFor(base, { path: firstConfusedPath }));
      await send(sdk, specFor(base, { path: firstConfusedPath }));
      const clean = await send(
        sdk,
        specFor(base, { path: firstConfusedPath, stripCookie: true }),
      );
      profile.leakConfirmed =
        isHit(clean.cstatus) &&
        clean.status >= 200 &&
        clean.status < 300 &&
        sameBody(clean.bodyLen, firstAuthedLen) &&
        !looksLikeControl404(clean, ctrl404);
      if (!profile.leakConfirmed) {
        profile.notes.push(
          "Path confusion is cacheable but the unauthenticated fetch did not return the authenticated body — cache key may include the cookie, or the TTL expired between probes.",
        );
      }
    }
  } else {
    profile.intent = originPrivate ? "EDGE HONORS ORIGIN" : "unknown";
    profile.notes.push(
      "Resource is not cached and no tested delimiter made it cacheable — no path-confusion vector found.",
    );
  }
}
