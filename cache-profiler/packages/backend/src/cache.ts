// Pure cache-analysis logic. No Caido SDK imports so it can be unit-tested in isolation.
import type { CacheProfile, CacheStatus } from "./types.js";

export type HeaderMap = Record<string, string[]>;

// ---- header access helpers -------------------------------------------------

// Lowercase every header name so lookups are case-insensitive.
export function lower(headers: HeaderMap): HeaderMap {
  const out: HeaderMap = {};
  for (const [name, values] of Object.entries(headers)) {
    out[name.toLowerCase()] = values;
  }
  return out;
}

function first(values: string[] | undefined): string | undefined {
  return values !== undefined && values.length > 0 ? values[0] : undefined;
}

function join(values: string[] | undefined): string {
  return values !== undefined ? values.join(", ") : "";
}

// ---- cache status normalisation -------------------------------------------

// Status-bearing headers (carry a HIT/MISS-style verdict) recognised across CDNs / stacks.
const STATUS_HEADERS = [
  "cf-cache-status", // Cloudflare (precise enum, handled specially)
  "x-cache", // Fastly / Varnish / CloudFront / Akamai
  "x-cache-hits", // Fastly / Varnish (numeric, special)
  "x-varnish", // Varnish (two IDs = HIT, special)
  "cache-status", // RFC 9211 standard structured field
  "akamai-cache-status", // Akamai
  "x-cache-status", // Nginx proxy_cache
  "x-cache-lookup", // Squid / Varnish
  "x-proxy-cache", // Nginx / various
  "x-drupal-cache", // Drupal
  "x-litespeed-cache", // LiteSpeed
  "x-rack-cache", // Rack::Cache (fresh/stale)
  "x-spip-cache", // SPIP
  "x-nginx-cache", // Nginx
  "x-fastcgi-cache", // Nginx fastcgi_cache
  "x-srcache-fetch-status", // Nginx srcache
  "x-srcache-store-status",
  "x-vercel-cache", // Vercel
  "x-nextjs-cache", // Next.js
  "x-now-cache", // Vercel (legacy)
  "x-cdn-cache", // generic CDN
  "x-cdn-cache-status",
  "x-edge-cache", // generic edge
  "x-edge-cache-status",
  "x-cacheable", // boolean-ish (YES/NO)
  "x-magento-cache-debug", // Magento (HIT/MISS)
  "x-nc", // KeyCDN ("HIT lhr 1")
  "x-tt-cache", // ByteDance / TikTok edge
  "x-bdcdn-cache-status",
  "x-ws-cache-status", // various WAF/CDN
];

// cacheStatus() handles these specially; the generic keyword loop skips them.
const STATUS_SPECIAL = new Set(["cf-cache-status", "x-cache-hits", "x-varnish"]);

// Presence markers — prove a caching/CDN layer is in path (no HIT/MISS verdict).
const INFRA_HEADERS = [
  "age",
  "x-served-by",
  "x-timer",
  "x-cache-key",
  "surrogate-key",
  "cdn-cache-control",
  "surrogate-control",
  "x-iinfo", // Imperva / Incapsula
  "x-cdn",
  "fastly-debug-digest",
  "cf-ray", // Cloudflare presence
  "x-amz-cf-pop", // CloudFront
  "x-amz-cf-id",
  "x-azure-ref", // Azure Front Door
  "x-msedge-ref", // Microsoft edge
  "x-akamai-transformed", // Akamai
  "akamai-grn",
  "x-akamai-request-id",
  "x-fastly-request-id", // Fastly
  "x-edge-location",
  "x-pull",
  "via", // proxy chain (often names the cache, e.g. "1.1 varnish")
];

// Cache-state keywords scanned for, both inside known status headers and (as a safety net)
// across every other header.
const CACHE_KEYWORDS = new Set([
  "HIT",
  "MISS",
  "EXPIRED",
  "STALE",
  "DYNAMIC",
  "BYPASS",
  "REVALIDATED",
  "UPDATING",
]);

// Return the first cache-state keyword that appears as a whole token in the value (so
// "TCP_HIT" and "Hit from cloudfront" match, but "whitelist" does not). Undefined if none.
export function matchCacheKeyword(value: string): string | undefined {
  if (value.length === 0) return undefined;
  for (const tok of value.toUpperCase().split(/[^A-Z0-9]+/)) {
    if (CACHE_KEYWORDS.has(tok)) return tok;
  }
  return undefined;
}

function keywordToStatus(kw: string): CacheStatus {
  if (kw === "HIT") return "HIT";
  if (kw === "DYNAMIC") return "DYNAMIC";
  if (kw === "BYPASS") return "BYPASS";
  return "MISS"; // MISS / EXPIRED / STALE / REVALIDATED / UPDATING
}

// Map a response's headers to a single vendor-independent verdict.
export function cacheStatus(h: HeaderMap): CacheStatus {
  // Cloudflare uses a precise enum.
  const cf = first(h["cf-cache-status"]);
  if (cf !== undefined) {
    const kw = matchCacheKeyword(cf);
    if (kw !== undefined) return keywordToStatus(kw);
  }

  // Numeric hit counter (Fastly / Varnish).
  const hits = first(h["x-cache-hits"]);
  if (hits !== undefined && /\d/.test(hits)) {
    const n = Number((hits.trim().split(/[\s,]/)[0] ?? "0"));
    if (!Number.isNaN(n)) return n > 0 ? "HIT" : "MISS";
  }

  // Varnish: two whitespace-separated request IDs => served from cache.
  const xv = first(h["x-varnish"]);
  if (xv !== undefined) {
    const ids = xv.trim().split(/\s+/).filter((s) => s.length > 0);
    if (ids.length >= 2) return "HIT";
    if (ids.length === 1) return "MISS";
  }

  // Generic hit/miss-bearing status headers, matched by whole-token keyword.
  for (const name of STATUS_HEADERS) {
    if (STATUS_SPECIAL.has(name)) continue;
    const kw = matchCacheKeyword(join(h[name]));
    if (kw !== undefined) return keywordToStatus(kw);
  }

  // Fallback: an Age header on its own indicates a shared cache in path.
  const age = first(h["age"]);
  if (age !== undefined) {
    return Number(age) > 0 ? "HIT" : "MISS";
  }

  return "NONE";
}

export function isHit(status: CacheStatus): boolean {
  return status === "HIT";
}

export function ageOf(h: HeaderMap): number {
  const age = first(h["age"]);
  return age !== undefined ? Number(age) : -1;
}

// ---- passive detection -----------------------------------------------------

// Collect the header tokens that prove a caching layer is present.
export function cacheSignals(h: HeaderMap): string[] {
  const signals: string[] = [];

  for (const name of [...STATUS_HEADERS, ...INFRA_HEADERS]) {
    const v = first(h[name]);
    if (v !== undefined) signals.push(`${name}: ${v}`);
  }

  const cc = parseCacheControl(h);
  if (cc.public || (cc.maxAge !== undefined && cc.maxAge > 0)) {
    signals.push(`cache-control: ${join(h["cache-control"])}`);
  }

  return signals;
}

// A response is a passive cache candidate when it carries a real cache signal.
export function isCacheCandidate(h: HeaderMap): boolean {
  if (cacheStatus(h) !== "NONE") return true;
  return cacheSignals(h).length > 0;
}

// Header names we already understand — excluded from the unknown-header keyword sweep.
const KNOWN_HEADER_NAMES = new Set([
  ...STATUS_HEADERS,
  ...INFRA_HEADERS,
  "cache-control",
  "vary",
  "expires",
  "etag",
  "last-modified",
  "pragma",
  "date",
  "content-type",
  "content-length",
]);

export type KeywordHit = { header: string; keyword: string; value: string };

// Safety net: scan every header NOT in the known set for a cache-state keyword. A match means
// a caching layer we don't have a named rule for — reported as "potentially detected".
export function unknownCacheKeywordHits(h: HeaderMap): KeywordHit[] {
  const out: KeywordHit[] = [];
  for (const [name, values] of Object.entries(h)) {
    if (KNOWN_HEADER_NAMES.has(name.toLowerCase())) continue;
    const value = values.join(", ");
    const kw = matchCacheKeyword(value);
    if (kw !== undefined) out.push({ header: name, keyword: kw, value });
  }
  return out;
}

// Classify a cached response as "dynamic" (text/html, json, xml, or a non-static path — the
// WCD-relevant content) vs "static" (css/js/images/fonts — expected and boring). Drives the
// content-type-aware passive dedupe: static collapses per host, dynamic stays per path.
export function isDynamicResponse(h: HeaderMap, path: string): boolean {
  const ct = (join(h["content-type"]).split(";")[0] ?? "").trim().toLowerCase();
  if (ct.length > 0) {
    if (ct.includes("html") || ct.includes("json") || ct.includes("xml")) return true;
    if (
      ct.startsWith("image/") ||
      ct.startsWith("font/") ||
      ct.startsWith("audio/") ||
      ct.startsWith("video/") ||
      ct === "text/css" ||
      ct.includes("javascript") ||
      ct.includes("ecmascript")
    ) {
      return false;
    }
  }
  // Unknown / missing content-type: fall back to the path extension.
  const ext = parsePath(path).ext.toLowerCase();
  if (ext.length > 0 && STATIC_EXTENSIONS.includes(ext)) return false;
  return true;
}

// Triage note for a cached response's status code. A cached non-200 is its own finding class.
export function statusNote(status: number): string | undefined {
  if (status >= 300 && status < 400) {
    return "cached **redirect** — open-redirect / location-poisoning lead";
  }
  if (status === 401 || status === 403) {
    return "cached **sensitive error** — auth page / DoS lead";
  }
  if (status === 404 || status === 410) {
    return "negative caching (usually low value)";
  }
  if (status >= 500) {
    return "cached **server error** — potential cache-poisoning DoS";
  }
  return undefined;
}

// ---- Cache-Control parsing -------------------------------------------------

export type CacheControl = {
  public: boolean;
  private: boolean;
  noStore: boolean;
  noCache: boolean;
  maxAge?: number;
  raw: string;
};

export function parseCacheControl(h: HeaderMap): CacheControl {
  const raw = join(h["cache-control"]).toLowerCase();
  const maxAgeMatch = /max-age\s*=\s*(\d+)/.exec(raw);
  return {
    public: /\bpublic\b/.test(raw),
    private: /\bprivate\b/.test(raw),
    noStore: /\bno-store\b/.test(raw),
    noCache: /\bno-cache\b/.test(raw),
    maxAge: maxAgeMatch !== undefined && maxAgeMatch !== null
      ? Number(maxAgeMatch[1])
      : undefined,
    raw: join(h["cache-control"]),
  };
}

// Does the origin intend this response to be cacheable by a shared cache?
export function originWantsCaching(cc: CacheControl): boolean {
  if (cc.noStore || cc.private) return false;
  if (cc.public) return true;
  if (cc.maxAge !== undefined && cc.maxAge > 0) return true;
  return false;
}

// ---- Vary ------------------------------------------------------------------

export function parseVary(h: HeaderMap): string[] {
  return join(h["vary"])
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// ---- path parsing ----------------------------------------------------------

export type PathParts = {
  dir: string; // directory prefix without trailing slash ("" for root)
  filename: string; // last path segment
  ext: string; // extension without dot ("" if none)
};

export function parsePath(path: string): PathParts {
  const clean = path.split("?")[0] ?? path;
  const lastSlash = clean.lastIndexOf("/");
  const dir = lastSlash > 0 ? clean.slice(0, lastSlash) : "";
  const filename = clean.slice(lastSlash + 1);
  const dot = filename.lastIndexOf(".");
  const ext = dot > 0 ? filename.slice(dot + 1) : "";
  return { dir, filename, ext };
}

// ---- extension / delimiter probe sets --------------------------------------

// Representative static extensions tested during the cache-rule sweep.
export const STATIC_EXTENSIONS = [
  "css",
  "js",
  "png",
  "jpg",
  "gif",
  "ico",
  "svg",
  "woff2",
  "json",
  "txt",
  "xml",
  "pdf",
  "html",
  "webp",
  "map",
];

// Delimiters used to test origin/cache path-parsing discrepancy (path confusion).
export const DELIMITERS = [
  ";",
  "%3b",
  "/",
  "%2f",
  "%00",
  "%23",
  "%3f",
  "\\",
  "%2e%2e/",
];

// ---- random segment --------------------------------------------------------

// Unique segment so every probe lands on a URL no real user visits
// (keeps cache population non-destructive) and forces a fresh cache key.
export function randSeg(): string {
  return (
    "cp" +
    Date.now().toString(36) +
    Math.random().toString(36).slice(2, 8)
  );
}

// ---- report formatting -----------------------------------------------------

// One-line summary for toasts / logs.
export function summaryLine(p: CacheProfile): string {
  if (!p.detected) return "no cache signal";
  const parts: string[] = [];
  parts.push(p.confirmedCached ? "cached" : "advertised-only");
  if (p.rule !== "none") parts.push(`rule=${p.rule}`);
  if (p.intent !== "unknown") parts.push(p.intent);
  if (p.delimiters.length > 0) parts.push(`delims=${p.delimiters.length}`);
  if (p.leakConfirmed) parts.push("LEAK CONFIRMED");
  return parts.join(", ");
}

function code(s: string): string {
  return "`" + s + "`";
}

// Full structured block written into the Finding description.
// The Findings panel renders Markdown, so titles are bold and every atomic item is a
// bullet on its own line. Each section renders on its own data.
export function formatProfile(p: CacheProfile): string {
  const out: string[] = [];
  const section = (title: string, items: string[]): void => {
    if (out.length > 0) out.push("");
    out.push(`**${title}**`);
    out.push("");
    for (const item of items) out.push(`- ${item}`);
  };

  // CACHE DETECTED — status, then one cache-signal header per bullet.
  const detectedItems: string[] = [];
  if (p.status > 0) {
    const note = statusNote(p.status);
    detectedItems.push(`status: ${code(String(p.status))}${note !== undefined ? ` — ${note}` : ""}`);
  }
  detectedItems.push(...(p.signals.length > 0 ? p.signals.map(code) : ["(none)"]));
  if (p.detectionVia === "timing") {
    detectedItems.push("detection: **timing-inferred** (no cache headers — lower confidence)");
  }
  section("CACHE DETECTED", detectedItems);

  // CACHE RULES — the rule, plus the extension allow/deny map when we swept it.
  const ruleItems: string[] = [];
  if (p.rule !== "none") {
    ruleItems.push(code(`[${p.rule}]`));
  } else if (!p.confirmedCached) {
    ruleItems.push(code("[none]"));
    ruleItems.push(
      "headers advertise caching but the resource was not stored on re-request",
    );
  }
  if (p.cachedExtensions.length > 0 || p.ignoredExtensions.length > 0) {
    ruleItems.push(
      `cached: ${p.cachedExtensions.length > 0 ? code(p.cachedExtensions.map((e) => "." + e).join(" ")) : "(none)"}`,
    );
    ruleItems.push(
      `ignored: ${p.ignoredExtensions.length > 0 ? code(p.ignoredExtensions.map((e) => "." + e).join(" ")) : "(none)"}`,
    );
  }
  if (ruleItems.length > 0) section("CACHE RULES", ruleItems);

  // CACHE KEY — confirmed key dimensions then declared Vary / mismatch.
  if (p.confirmedCached) {
    const keyItems: string[] = p.keyDims.map(code);
    keyItems.push(`VARY: ${p.vary.length > 0 ? code(p.vary.join(", ")) : "(none)"}`);
    if (p.varyMismatch.length > 0) {
      keyItems.push(
        `**MISMATCH**: ${p.varyMismatch.join(", ")} declared, not in observed key`,
      );
    }
    if (p.caseInsensitiveKey) {
      keyItems.push("case-insensitive key: yes (differently-cased URLs collide)");
    }
    section("CACHE KEY", keyItems);
  }

  // CACHE INTENT — origin / edge / verdict.
  if (p.intent !== "unknown") {
    const edge = p.confirmedCached
      ? "cached"
      : p.delimiters.length > 0
        ? "cached-via-confusion"
        : "bypassed";
    section("CACHE INTENT", [
      `origin: ${code(p.originCacheControl ?? "unknown")}`,
      `edge: ${code(edge)}`,
      `verdict: ${code(p.intent)}`,
    ]);
  }

  // DELIMITERS — each path-confusion delimiter on its own bullet.
  if (p.delimiters.length > 0) {
    section("DELIMITERS", [
      ...p.delimiters.map(code),
      "(origin same-body + cacheable)",
    ]);
  }

  // DECEPTION — confirmed cross-session leak.
  if (p.leakConfirmed) {
    section("DECEPTION", [
      "**CONFIRMED**",
      "unauthenticated fetch returned the authenticated body from cache",
    ]);
  }

  if (p.notes.length > 0) {
    section("NOTES", p.notes);
  }

  return out.join("\n");
}
