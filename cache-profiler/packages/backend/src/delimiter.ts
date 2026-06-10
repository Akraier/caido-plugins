// Delimiter detection. Operator-triggered on a chosen baseline endpoint. Finds delimiters
// the ORIGIN truncates the path at (so `/x;junk` routes to `/x`) but the CACHE does not
// (so the full `/x;junk.css` is keyed and stored because of the static extension) — the
// path-confusion primitive behind web cache deception.
//
// A delimiter discrepancy is a property of the routing stack, not of one endpoint: find it
// once on any routable endpoint and it applies host-wide behind the same cache config.
import type { Request as CaidoRequest, Response as CaidoResponse } from "caido:utils";

import { isHit, parsePath, randSeg, STATIC_EXTENSIONS } from "./cache.js";
import {
  anchorOf,
  anchorsSeparable,
  confirmCached,
  nearest,
  send,
  specFor,
  type Anchor,
  type EngineSDK,
} from "./probe.js";
import { recallProfile } from "./store.js";
import type { DelimiterResult, HitTechnique } from "./types.js";

// Delimiter wordlist. Tunable — these are the highest-value path-truncation characters
// across common origin stacks (Java matrix params, encoded slashes, control chars, etc.).
export const DELIMITER_PROBES = [
  ";",
  "%3b",
  ",",
  "%2c",
  "/",
  "%2f",
  "%00",
  "%09",
  "%0a",
  "%0d",
  "%23",
  "%3f",
  "\\",
  "%5c",
  "!",
  ".",
  "@",
  ":",
];

// Fallback extensions when no cache profile is stored for the host. Caching is confirmed
// empirically per extension, so a wrong guess just yields no hit.
const DEFAULT_DELIM_EXTS = ["css", "js", "png", "gif", "ico", "svg", "jpg", "woff2"];

// Known static file names some caches whitelist by exact name (not extension). Probed as
// suffixes after a truncating delimiter: `/endpoint;robots.txt`, `/endpoint/robots.txt`, ...
const STATIC_FILENAMES = [
  "robots.txt",
  "sitemap.xml",
  "favicon.ico",
  "sw.js",
  "manifest.json",
  "crossdomain.xml",
  ".well-known/security.txt",
  "index.html",
];

// Append a unique token to the path (stripping any query) to build the "error" anchor —
// a sibling URL that should NOT resolve to the same endpoint.
function appendToken(path: string, token: string): string {
  const q = path.indexOf("?");
  const clean = q >= 0 ? path.slice(0, q) : path;
  return clean + token;
}

export async function runDelimiterScan(
  sdk: EngineSDK,
  base: CaidoRequest,
  _baseResponse: CaidoResponse | undefined,
): Promise<DelimiterResult> {
  const host = base.getHost().toLowerCase();
  const basePath = base.getPath();

  const result: DelimiterResult = {
    host,
    basePath,
    suitable: true,
    anchorsSeparable: false,
    aborted: false,
    delimiters: [],
    hits: [],
    cachedNon2xx: [],
    timingInferred: false,
    extSource: "default",
    notes: [],
  };

  // 1. Baseline suitability — a routable endpoint is the right baseline, not a static file.
  const parts = parsePath(basePath);
  if (
    parts.ext.length > 0 &&
    STATIC_EXTENSIONS.includes(parts.ext.toLowerCase())
  ) {
    result.suitable = false;
    result.notes.push(
      `Baseline ends in a static extension (.${parts.ext}). A routable endpoint (no extension) is a better baseline.`,
    );
  }
  if (base.getUrl().includes("?")) {
    result.notes.push(
      "Baseline carries a query string; it may participate in the cache key and muddy comparisons.",
    );
  }

  // 1b. Hard gate: the baseline must NOT already be cached. If it is, it's a static/cacheable
  //     resource — you can't distinguish origin-truncation from the cache simply serving the
  //     stored object, and there is no dynamic content to leak. Abort with a clear reason.
  const baseCached = await confirmCached(sdk, base, basePath);
  if (baseCached.cached) {
    result.suitable = false;
    result.aborted = true;
    result.abortReason =
      "baseline is already cached — it is a static/cacheable resource, not a routable dynamic endpoint";
    result.notes.push(
      "Delimiter detection needs a baseline whose dynamic response the cache does NOT already store. Pick an endpoint that returns user/dynamic content and is not itself cached (e.g. /profile, /api/...).",
    );
    return result;
  }

  // 2. Two anchors: the base response and a deliberately-broken sibling. Their difference
  //    is the yardstick for every delimiter verdict.
  const goodProbe = await send(sdk, specFor(base, { path: basePath }));
  const errProbe = await send(
    sdk,
    specFor(base, { path: appendToken(basePath, randSeg()) }),
  );
  const good: Anchor = anchorOf(goodProbe);
  const error: Anchor = anchorOf(errProbe);

  result.anchorsSeparable = anchorsSeparable(good, error);
  if (!result.anchorsSeparable) {
    result.aborted = true;
    result.abortReason =
      "base and error responses are indistinguishable (catch-all route, redirect, or SPA shell)";
    result.notes.push(
      "Delimiter verdicts can't be trusted when the base and error responses look the same — pick another baseline request.",
    );
    return result;
  }

  // 3. Suffix source: prefer the profiler's cached-extension findings for this host.
  const profile = recallProfile(host);
  let exts: string[];
  if (profile !== undefined && profile.cachedExtensions.length > 0) {
    exts = profile.cachedExtensions;
    result.extSource = "profile";
  } else {
    exts = DEFAULT_DELIM_EXTS;
    result.extSource = "default";
    result.notes.push(
      'No stored cache profile with cached extensions for this host — using a default static set and confirming each empirically. Run "Profile cache behaviour" on a static asset of this host first for an accurate allow-list.',
    );
  }

  const hasAuth =
    base.getHeader("Cookie") !== undefined ||
    base.getHeader("Authorization") !== undefined;

  // Cased / encoded variants are bounded to the first couple of extensions to cap requests.
  const variantExts = exts.slice(0, 2);

  // 4. Direct extension append `/endpoint.ext` (the original 2017 WCD: origin ignores the
  //    trailing extension and serves the endpoint; cache stores it). No delimiter needed.
  for (const ext of exts) {
    const hit = await probeSuffix(sdk, base, `${basePath}.${ext}`, good, error, hasAuth, {
      technique: "direct-ext",
      delimiter: "",
      suffix: "." + ext,
    }, result);
    if (!hit && variantExts.includes(ext)) {
      for (const v of extVariants(ext)) {
        await probeSuffix(sdk, base, `${basePath}${v}`, good, error, hasAuth, {
          technique: "suffix-variant",
          delimiter: "",
          suffix: v,
        }, result);
      }
    }
  }

  // 5. Truncation probes: `/base<delim><rand>`. Origin truncated at the delimiter if the
  //    response matches the base anchor; did not if it matches the error anchor.
  const taken: string[] = [];
  for (const delim of DELIMITER_PROBES) {
    const probe = await send(
      sdk,
      specFor(base, { path: `${basePath}${delim}${randSeg()}` }),
    );
    const verdict = nearest(anchorOf(probe), good, error);
    result.delimiters.push({
      delimiter: delim,
      verdict: verdict === "good" ? "taken" : verdict === "error" ? "not-taken" : "ambiguous",
    });
    if (verdict === "good") taken.push(delim);
  }

  // 6. Deception matrix for taken delimiters: cached-extension AND known static-filename
  //    suffixes. Each must still truncate (origin serves base) AND get cached.
  for (const delim of taken) {
    for (const ext of exts) {
      const hit = await probeSuffix(
        sdk,
        base,
        `${basePath}${delim}${randSeg()}.${ext}`,
        good,
        error,
        hasAuth,
        { technique: "delimiter+ext", delimiter: delim, suffix: "." + ext },
        result,
      );
      if (!hit && variantExts.includes(ext)) {
        for (const v of extVariants(ext)) {
          await probeSuffix(
            sdk,
            base,
            `${basePath}${delim}${randSeg()}${v}`,
            good,
            error,
            hasAuth,
            { technique: "suffix-variant", delimiter: delim, suffix: v },
            result,
          );
        }
      }
    }
    for (const fn of STATIC_FILENAMES) {
      await probeSuffix(
        sdk,
        base,
        `${basePath}${delim}${fn}`,
        good,
        error,
        hasAuth,
        { technique: "delimiter+filename", delimiter: delim, suffix: fn },
        result,
      );
    }
  }

  if (taken.length === 0 && result.hits.length === 0) {
    result.notes.push(
      "No delimiter was truncated by the origin and no direct-extension confusion cached — no path-confusion primitive on this routing stack.",
    );
  }
  if (result.hits.length > 0 && !hasAuth) {
    result.notes.push(
      "Hits are CANDIDATES: the baseline request carried no auth, so the cross-session leak was not confirmed. Re-run on an authenticated request that returns user-specific content to confirm impact.",
    );
  }

  return result;
}

// Confirm one confused-suffix probe: records a deception hit (cached AND still resolves to
// the base content) and/or a cached redirect / sensitive-error page on the confused path.
async function probeSuffix(
  sdk: EngineSDK,
  base: CaidoRequest,
  path: string,
  good: Anchor,
  error: Anchor,
  hasAuth: boolean,
  meta: { technique: HitTechnique; delimiter: string; suffix: string },
  result: DelimiterResult,
): Promise<boolean> {
  const conf = await confirmCached(sdk, base, path);
  if (conf.via === "timing") result.timingInferred = true;
  if (!conf.cached) return false;

  const status = conf.last.status;
  if (status >= 300 && status < 400) {
    result.cachedNon2xx.push({ path, status, kind: "redirect" });
  } else if (status === 401 || status === 403) {
    result.cachedNon2xx.push({ path, status, kind: "auth-error" });
  }

  if (nearest(anchorOf(conf.last), good, error) !== "good") return false;

  let leakConfirmed = false;
  if (hasAuth) leakConfirmed = await confirmLeak(sdk, base, path, good, error);
  result.hits.push({ ...meta, leakConfirmed, example: path });
  return true;
}

// Cased / encoded extension variants, tried only when the plain `.ext` misses — they target
// cache-vs-origin parser discrepancies on the extension itself.
function extVariants(ext: string): string[] {
  const lastHex = ext.charCodeAt(ext.length - 1).toString(16);
  return [
    `.${ext.toUpperCase()}`, // casing
    `.${ext.slice(0, -1)}%${lastHex}`, // last char percent-encoded (.cs%73)
    `%2e${ext}`, // encoded dot
  ];
}

// Populate the confused URL with the baseline's auth, then fetch it with the cookie
// stripped. A cache HIT that still matches the base (authenticated) anchor proves the cache
// serves one session's content to an unauthenticated requester.
async function confirmLeak(
  sdk: EngineSDK,
  base: CaidoRequest,
  path: string,
  good: Anchor,
  error: Anchor,
): Promise<boolean> {
  await send(sdk, specFor(base, { path }));
  await send(sdk, specFor(base, { path }));
  const clean = await send(sdk, specFor(base, { path, stripCookie: true }));
  return isHit(clean.cstatus) && nearest(anchorOf(clean), good, error) === "good";
}

// ---- reporting -------------------------------------------------------------

function code(s: string): string {
  return "`" + s + "`";
}

export function delimiterSummary(r: DelimiterResult): string {
  if (r.aborted) return `bad baseline — ${r.abortReason ?? "unsuitable"}`;
  const taken = r.delimiters.filter((d) => d.verdict === "taken").length;
  const leak = r.hits.some((h) => h.leakConfirmed);
  const parts = [`${taken} delimiter(s) taken`, `${r.hits.length} deception hit(s)`];
  if (r.cachedNon2xx.length > 0) parts.push(`${r.cachedNon2xx.length} cached non-200`);
  if (leak) parts.push("LEAK CONFIRMED");
  return parts.join(", ");
}

export function delimiterTitle(r: DelimiterResult): string {
  if (r.aborted) {
    return `Cache Profiler — delimiter detection: unsuitable baseline — ${r.host}`;
  }
  if (r.hits.some((h) => h.leakConfirmed)) {
    return `Cache Profiler — WEB CACHE DECEPTION — ${r.host}`;
  }
  if (r.hits.length > 0) {
    return `Cache Profiler — delimiter path confusion (candidate) — ${r.host}`;
  }
  return `Cache Profiler — delimiter map — ${r.host}`;
}

export function formatDelimiterResult(r: DelimiterResult): string {
  const out: string[] = [];
  const section = (title: string, items: string[]): void => {
    if (out.length > 0) out.push("");
    out.push(`**${title}**`);
    out.push("");
    for (const item of items) out.push(`- ${item}`);
  };

  if (r.aborted) {
    section("DELIMITER DETECTION", [
      `baseline: ${code(r.basePath)}`,
      `**aborted** — ${r.abortReason ?? "unsuitable baseline"}`,
    ]);
    if (r.notes.length > 0) section("NOTES", r.notes);
    return out.join("\n");
  }

  section("DELIMITER MAP", [`baseline: ${code(r.basePath)}`]);

  const group = (verdict: DelimiterResult["delimiters"][number]["verdict"]): string =>
    r.delimiters
      .filter((d) => d.verdict === verdict)
      .map((d) => code(d.delimiter))
      .join(" ") || "(none)";

  const delimItems = [
    `taken: ${group("taken")}`,
    `not taken: ${group("not-taken")}`,
  ];
  if (r.delimiters.some((d) => d.verdict === "ambiguous")) {
    delimItems.push(`ambiguous: ${group("ambiguous")}`);
  }
  section("DELIMITERS", delimItems);

  if (r.hits.length > 0) {
    const hitItems = r.hits.map((h) => {
      const label =
        h.delimiter === ""
          ? `${code(r.basePath + h.suffix)} (${h.technique})`
          : `${code(h.delimiter)} + ${code(h.suffix)} (${h.technique})`;
      return (
        `${label} -> origin serves base, edge caches  ` +
        (h.leakConfirmed ? "**[LEAK CONFIRMED]**" : "[CANDIDATE]")
      );
    });
    section("CACHE DECEPTION", hitItems);

    const first = r.hits[0];
    if (first !== undefined) {
      section("TESTER", [
        `extensions tested from: ${r.extSource}`,
        `example: ${code(first.example)}`,
        "apply the working technique to a sensitive endpoint on this host",
      ]);
    }
  }

  if (r.cachedNon2xx.length > 0) {
    section(
      "CACHED NON-200 (confused paths)",
      r.cachedNon2xx.map((c) => `${code(c.path)} -> ${c.status} (${c.kind})`),
    );
  }

  if (r.timingInferred) {
    section("CONFIDENCE", [
      "**timing-inferred** cache verdicts present (host strips cache headers) — confirm with the Timing cache probe before relying on hits",
    ]);
  }

  if (r.notes.length > 0) section("NOTES", r.notes);

  return out.join("\n");
}
