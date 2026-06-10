export type Result<T> =
  | { kind: "Ok"; value: T }
  | { kind: "Error"; error: string };

// Normalised cache verdict for a single response, vendor-independent.
export type CacheStatus = "HIT" | "MISS" | "DYNAMIC" | "BYPASS" | "NONE";

// Which dimensions the edge actually keys on (empirically confirmed by busting).
export type CacheKeyDim = "path" | "query" | "cookie";

export type CacheRule =
  | "static extension"
  | "static directory"
  | "specific file"
  | "origin-directed"
  | "none";

export type CacheIntent =
  | "EDGE OVERRIDES ORIGIN"
  | "ORIGIN OPTS IN"
  | "EDGE HONORS ORIGIN"
  | "unknown";

// Full structured profile emitted as a Finding.
export type CacheProfile = {
  url: string;
  host: string;
  status: number; // status code of the triggering response
  // Phase 1
  detected: boolean;
  signals: string[];
  // Phase 2
  confirmedCached: boolean;
  // Phase 3
  rule: CacheRule;
  cachedExtensions: string[];
  ignoredExtensions: string[];
  // Phase 4
  keyDims: CacheKeyDim[];
  vary: string[];
  varyMismatch: string[];
  caseInsensitiveKey: boolean; // an upper-cased path HIT the same entry (cache ignores case)
  // how the cached/not-cached verdict was reached
  detectionVia: "headers" | "timing" | "none";
  // Phase 5
  intent: CacheIntent;
  originCacheControl?: string;
  // Phase 6
  delimiters: string[];
  // Deception confirmation (operator-gated, only when run on a sensitive URL)
  leakConfirmed: boolean;
  notes: string[];
};

// Compact per-host summary shared between commands (populated by the profiler, read by the
// delimiter detector). Kept in memory for the life of the backend process.
export type HostProfile = {
  host: string;
  rule: CacheRule;
  cachedExtensions: string[];
  vary: string[];
};

export type DelimiterVerdict = "taken" | "not-taken" | "ambiguous";

export type HitTechnique =
  | "direct-ext"
  | "delimiter+ext"
  | "delimiter+filename"
  | "suffix-variant";

export type DelimiterHit = {
  technique: HitTechnique;
  delimiter: string; // "" for direct-ext
  suffix: string; // ".css" or "robots.txt"
  leakConfirmed: boolean;
  example: string; // a concrete path that worked
};

export type CachedNon2xx = {
  path: string;
  status: number;
  kind: "redirect" | "auth-error";
};

export type DelimiterResult = {
  host: string;
  basePath: string;
  suitable: boolean; // baseline looked like a routable endpoint (not a static file)
  anchorsSeparable: boolean; // base vs error responses were distinguishable
  aborted: boolean; // baseline rejected — results would be misleading
  abortReason?: string;
  delimiters: Array<{ delimiter: string; verdict: DelimiterVerdict }>;
  hits: DelimiterHit[];
  cachedNon2xx: CachedNon2xx[]; // cached redirects / sensitive error pages on confused paths
  timingInferred: boolean; // at least one cache verdict came from timing, not headers
  extSource: "profile" | "default";
  notes: string[];
};

// Path-normalization discrepancy test against a static-directory cache rule.
export type NormalizationResult = {
  host: string;
  basePath: string;
  prefix: string;
  comparerPath: string;
  aborted: boolean;
  abortReason?: string;
  matchType: "directory" | "filename";
  dirRuleConfirmed: boolean;
  cacheKeysNormalized: boolean; // filename rule: traversal collapses onto the real file's key
  // origin side
  originNormalizes: boolean;
  originEncodings: string[]; // encodings the origin resolved
  originTestable: boolean; // comparer anchors were separable
  // cache side
  cachePrependCached: boolean;
  cacheMidCached: boolean; // cache keeps /<prefix>/..%2f<rest> raw (Direction A needs this)
  cacheNormalizesEncoded: boolean; // cache resolves fully-encoded %2f%2e%2e%2f (Direction B needs this)
  // Direction A — origin normalizes, cache doesn't: /<prefix>/..%2f<dynamic>
  exploitableOrigin: boolean;
  // Direction B — cache normalizes, origin doesn't, via a delimiter origin truncates but
  // cache keeps: /<dynamic><delim>%2f%2e%2e%2f<prefix>
  cacheNormDelimiter?: string;
  exploitableCacheNorm: boolean;
  // either direction
  exploitable: boolean;
  timingInferred: boolean; // at least one cache verdict came from timing, not headers
  notes: string[];
};

// Dedicated timing-based cache probe (operator-invoked smell test).
export type TimingResult = {
  host: string;
  path: string;
  headerSignal?: string; // cache-status header if the host actually exposes one
  missSamples: number[]; // roundtrips of cache-busted requests (forced origin)
  steadySamples: number[]; // roundtrips of repeated requests (steady state)
  missMedian: number;
  steadyMedian: number;
  ratio: number; // steadyMedian / missMedian
  verdict: "cached" | "not-cached" | "inconclusive";
  confidence: "header-confirmed" | "timing" | "low";
  notes: string[];
};

export type ProfileStart = { url: string };
export type ProfileDone = { url: string; summary: string };
export type ProfileError = { message: string };

export type BackendEvents = {
  "cache-profiler:start": (data: ProfileStart) => void;
  "cache-profiler:done": (data: ProfileDone) => void;
  "cache-profiler:error": (data: ProfileError) => void;
};
