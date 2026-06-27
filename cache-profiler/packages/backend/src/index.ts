import type { DefineAPI, SDK } from "caido:plugin";
import type {
  Request as CaidoRequest,
  Response as CaidoResponse,
} from "caido:utils";

import {
  ageOf,
  cacheSignals,
  cacheState,
  formatProfile,
  hitsOf,
  isDynamicResponse,
  lower,
  passiveTrigger,
  statusNote,
  summaryLine,
  type TriggerKind,
  unknownCacheKeywordHits,
} from "./cache.js";
import {
  type DedupeMode,
  effectiveConfirm,
  hostInScope,
  isGranular,
  mergeConfig,
  type RuntimeConfig,
  seedConfigFromEnv,
} from "./config.js";
import { ConfirmQueue, type DetectedOutcome, type V0 } from "./confirm.js";
import { PROBE_MARKER } from "./probe.js";
import {
  delimiterSummary,
  delimiterTitle,
  formatDelimiterResult,
  runDelimiterScan,
} from "./delimiter.js";
import {
  formatNormalizationResult,
  normalizationSummary,
  normalizationTitle,
  runNormalizationScan,
} from "./normalize.js";
import { runProfile } from "./profiler.js";
import { rememberProfile } from "./store.js";
import {
  formatTimingResult,
  runTimingProbe,
  timingSummary,
  timingTitle,
} from "./timing.js";
import type {
  BackendEvents,
  CacheProfile,
  DelimiterResult,
  NormalizationResult,
  Result,
  TimingResult,
} from "./types.js";

type BackendSDK = SDK<never, BackendEvents>;

// Bump on every build so a reload is verifiable. Surfaced on init and footed on every finding.
export const PLUGIN_VERSION = "0.4.1";

function withVersion(description: string): string {
  return `${description}\n\n---\n_cache-profiler v${PLUGIN_VERSION}_`;
}

// Live runtime configuration. Seeded from env at init, mutated by the settings page via
// setConfig. The interceptor reads it per-response so changes apply with no reload.
let cfg: RuntimeConfig;
let queue: ConfirmQueue;

// Comparer path for origin path-normalization (default site root). Override to a stable,
// non-cached dynamic endpoint when "/" is a poor comparer.
function normComparer(sdk: BackendSDK): string {
  const v = (sdk.env.getVar("CACHE_PROFILER_NORM_PATH") ?? "").trim();
  if (v.length === 0) return "/";
  return v.startsWith("/") ? v : "/" + v;
}

// ---- settings API (read/written by the frontend settings page) -------------

const getConfig = (_sdk: BackendSDK): Promise<RuntimeConfig> => Promise.resolve(cfg);

const setConfig = (
  sdk: BackendSDK,
  patch: Partial<RuntimeConfig>,
): Promise<RuntimeConfig> => {
  cfg = mergeConfig(cfg, patch);
  queue.updateLimits(cfg.rate, cfg.max);
  sdk.console.log(
    `[cache-profiler] config updated -> confirm=${cfg.confirm} (effective ${
      effectiveConfirm(cfg) ? "on" : "off"
    }), scope=[${cfg.scope.join(", ")}], rate=${cfg.rate}/min, max=${cfg.max}, dedupe=${cfg.dedupe}`,
  );
  return Promise.resolve(cfg);
};

export type ConfirmStatus = {
  mode: "active-confirm" | "candidate-only";
  scope: string[];
  probed: number;
  queued: number;
  halted: boolean;
  sessionMax: number;
};

const getStatus = (_sdk: BackendSDK): Promise<ConfirmStatus> => {
  const s = queue.stats();
  return Promise.resolve({
    mode: effectiveConfirm(cfg) ? "active-confirm" : "candidate-only",
    scope: cfg.scope,
    probed: s.probed,
    queued: s.queued,
    halted: s.halted,
    sessionMax: s.sessionMax,
  });
};

const resumeConfirm = (_sdk: BackendSDK): Promise<boolean> => {
  queue.resume();
  return Promise.resolve(true);
};

const inflight = new Set<string>();

type RunOpts = { requestId?: string };

type Resolved =
  | { ok: true; request: CaidoRequest; response: CaidoResponse | undefined; url: string }
  | { ok: false; error: string };

async function resolve(sdk: BackendSDK, opts: RunOpts): Promise<Resolved> {
  if (opts.requestId === undefined) {
    return { ok: false, error: "Missing requestId. Trigger from a captured request." };
  }
  const existing = await sdk.requests.get(opts.requestId);
  if (existing === undefined) {
    return { ok: false, error: `Request ${opts.requestId} not found.` };
  }
  // Active probing is exploitation-adjacent — keep it inside Caido scope.
  const inScope = await sdk.requests.inScope(existing.request);
  if (inScope !== true) {
    return {
      ok: false,
      error: "Request is out of Caido scope. Add the host to scope first.",
    };
  }
  return {
    ok: true,
    request: existing.request,
    response: existing.response,
    url: existing.request.getUrl(),
  };
}

// Shared command wrapper: resolve + scope-gate + single-flight + start/done/error events.
async function runCommand(
  sdk: BackendSDK,
  opts: RunOpts,
  kind: string,
  run: (request: CaidoRequest, response: CaidoResponse | undefined) => Promise<string>,
): Promise<Result<{ summary: string }>> {
  const r = await resolve(sdk, opts);
  if (!r.ok) return { kind: "Error", error: r.error };
  if (inflight.has(r.url)) {
    return { kind: "Error", error: `A ${kind} is already running for ${r.url}.` };
  }
  inflight.add(r.url);

  sdk.api.send("cache-profiler:start", { url: r.url });
  try {
    const summary = await run(r.request, r.response);
    sdk.api.send("cache-profiler:done", { url: r.url, summary });
    return { kind: "Ok", value: { summary } };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    sdk.console.error(`[cache-profiler] ${kind} failed: ${message}`);
    sdk.api.send("cache-profiler:error", { message });
    return { kind: "Error", error: message };
  } finally {
    inflight.delete(r.url);
  }
}

const runProfileOn = (
  sdk: BackendSDK,
  opts: RunOpts,
): Promise<Result<{ summary: string }>> =>
  runCommand(sdk, opts, "profile", async (request, response) => {
    const profile = await runProfile(sdk, request, response);
    rememberProfile(profile);
    await emitProfileFinding(sdk, request, profile);
    return summaryLine(profile);
  });

const runDelimiterOn = (
  sdk: BackendSDK,
  opts: RunOpts,
): Promise<Result<{ summary: string }>> =>
  runCommand(sdk, opts, "delimiter scan", async (request, response) => {
    const result = await runDelimiterScan(sdk, request, response);
    await emitDelimiterFinding(sdk, request, result);
    return delimiterSummary(result);
  });

const runNormalizationOn = (
  sdk: BackendSDK,
  opts: RunOpts,
): Promise<Result<{ summary: string }>> =>
  runCommand(sdk, opts, "path normalization", async (request, response) => {
    const result = await runNormalizationScan(
      sdk,
      request,
      normComparer(sdk),
      response,
    );
    await emitNormalizationFinding(sdk, request, result);
    return normalizationSummary(result);
  });

const runTimingOn = (
  sdk: BackendSDK,
  opts: RunOpts,
): Promise<Result<{ summary: string }>> =>
  runCommand(sdk, opts, "timing probe", async (request, response) => {
    const result = await runTimingProbe(sdk, request, response);
    await emitTimingFinding(sdk, request, result);
    return timingSummary(result);
  });

async function emitProfileFinding(
  sdk: BackendSDK,
  request: CaidoRequest,
  profile: CacheProfile,
): Promise<void> {
  const title = profile.leakConfirmed
    ? `Cache Profile — WEB CACHE DECEPTION — ${profile.host}`
    : `Cache Profile — ${profile.host}`;
  let description = formatProfile(profile);
  // Cross-link: a static-extension rule is the precondition for delimiter path confusion.
  if (profile.rule === "static extension") {
    description +=
      "\n\n_Run **Delimiter detection** on a routable endpoint of this host to map path-confusion delimiters against these cached extensions._";
  }
  try {
    await sdk.findings.create({
      reporter: "Cache Profiler",
      request,
      title,
      description: withVersion(description),
      dedupeKey: `cache-profile:${profile.url}`,
    });
  } catch (err) {
    sdk.console.warn(`[cache-profiler] failed to create finding: ${String(err)}`);
  }
}

async function emitDelimiterFinding(
  sdk: BackendSDK,
  request: CaidoRequest,
  result: DelimiterResult,
): Promise<void> {
  try {
    await sdk.findings.create({
      reporter: "Cache Profiler",
      request,
      title: delimiterTitle(result),
      description: withVersion(formatDelimiterResult(result)),
      dedupeKey: `cache-delimiter:${result.host}:${result.basePath}`,
    });
  } catch (err) {
    sdk.console.warn(
      `[cache-profiler] failed to create delimiter finding: ${String(err)}`,
    );
  }
}

async function emitNormalizationFinding(
  sdk: BackendSDK,
  request: CaidoRequest,
  result: NormalizationResult,
): Promise<void> {
  try {
    await sdk.findings.create({
      reporter: "Cache Profiler",
      request,
      title: normalizationTitle(result),
      description: withVersion(formatNormalizationResult(result)),
      dedupeKey: `cache-normalize:${result.host}:${result.basePath}`,
    });
  } catch (err) {
    sdk.console.warn(
      `[cache-profiler] failed to create normalization finding: ${String(err)}`,
    );
  }
}

async function emitTimingFinding(
  sdk: BackendSDK,
  request: CaidoRequest,
  result: TimingResult,
): Promise<void> {
  try {
    await sdk.findings.create({
      reporter: "Cache Profiler",
      request,
      title: timingTitle(result),
      description: withVersion(formatTimingResult(result)),
      dedupeKey: `cache-timing:${result.host}:${result.path}`,
    });
  } catch (err) {
    sdk.console.warn(
      `[cache-profiler] failed to create timing finding: ${String(err)}`,
    );
  }
}

export type API = DefineAPI<{
  runProfileOn: typeof runProfileOn;
  runDelimiterOn: typeof runDelimiterOn;
  runNormalizationOn: typeof runNormalizationOn;
  runTimingOn: typeof runTimingOn;
  getConfig: typeof getConfig;
  setConfig: typeof setConfig;
  getStatus: typeof getStatus;
  resumeConfirm: typeof resumeConfirm;
}>;

export type { BackendEvents } from "./types.js";
export type { RuntimeConfig, ConfirmMode, DedupeMode } from "./config.js";

export const init = (sdk: SDK<API, BackendEvents>): void => {
  sdk.console.log(`[cache-profiler] backend v${PLUGIN_VERSION} loaded`);

  sdk.api.register("runProfileOn", runProfileOn);
  sdk.api.register("runDelimiterOn", runDelimiterOn);
  sdk.api.register("runNormalizationOn", runNormalizationOn);
  sdk.api.register("runTimingOn", runTimingOn);
  sdk.api.register("getConfig", getConfig);
  sdk.api.register("setConfig", setConfig);
  sdk.api.register("getStatus", getStatus);
  sdk.api.register("resumeConfirm", resumeConfirm);

  cfg = seedConfigFromEnv(sdk);
  queue = new ConfirmQueue(
    { ratePerMin: cfg.rate, sessionMax: cfg.max },
    (m) => sdk.console.log(`[cache-profiler] ${m}`),
  );
  const candidateSeen = new Set<string>();

  sdk.console.log(
    `[cache-profiler] passive ${effectiveConfirm(cfg) ? "active-confirm" : "candidate-only"} mode` +
      (cfg.scope.length > 0 ? ` (scope: ${cfg.scope.join(", ")})` : " (no scope set)"),
  );

  // Phase 1 — passive: a header signal is a TRIGGER, not a verdict. Only state-bearing signals
  // (real HIT/MISS, counters, or a live keyword) qualify; infra presence (cf-ray/via/age/
  // cache-control) and dead-negatives (DYNAMIC/BYPASS) are ignored — that is what was flooding
  // the panel. When confirmation is enabled the trigger feeds the probe queue and a finding is
  // raised ONLY if the active state machine confirms it. When disabled, one low-confidence
  // candidate per host is emitted with zero active traffic. Config is read live (cfg) so the
  // settings page applies without a reload.
  sdk.events.onInterceptResponse(async (innerSdk, request, response) => {
    // Skip our own confirmation traffic — otherwise the probes re-trigger the queue recursively.
    if (request.getHeader(PROBE_MARKER) !== undefined) return;

    const host = request.getHost().toLowerCase();
    if (!hostInScope(host, cfg.scope)) return;

    const h = lower(response.getHeaders());
    const trigger = passiveTrigger(h);
    if (trigger === "none") return;

    const path = request.getPath();
    const dynamic = isDynamicResponse(h, path);
    const key = isGranular(cfg.dedupe, dynamic) ? `${host}:${path}` : host;

    if (!effectiveConfirm(cfg)) {
      // Active confirmation disabled -> one low-confidence candidate per host, no probing.
      if (candidateSeen.has(host)) return;
      candidateSeen.add(host);
      await emitCandidate(innerSdk, request, host, h, trigger);
      return;
    }

    const signals = cacheSignals(h);
    const v0: V0 = {
      state: cacheState(h),
      age: ageOf(h),
      hits: hitsOf(h),
      status: response.getCode(),
    };
    queue.enqueue(innerSdk, key, request, v0, (outcome) =>
      emitConfirmed(innerSdk, request, host, path, v0, outcome, signals, dynamic, cfg.dedupe),
    );
  });
};

// Raised only after the active machine confirms the resource is served from cache.
async function emitConfirmed(
  sdk: BackendSDK,
  request: CaidoRequest,
  host: string,
  path: string,
  v0: V0,
  outcome: DetectedOutcome,
  signals: string[],
  dynamic: boolean,
  mode: DedupeMode,
): Promise<void> {
  const granular = isGranular(mode, dynamic);
  const scopeKey = granular ? `${host}:${path}` : host;
  const titlePath = granular ? ` ${path}` : "";
  const note = statusNote(v0.status);
  const conf = outcome.confidence.toUpperCase();

  const lines = [
    `**CACHE CONFIRMED — ${conf} confidence**`,
    "",
    "- verdict: edge served this resource from cache (confirmed by active probe)",
    `- status: \`${v0.status}\`${note !== undefined ? ` — ${note}` : ""}`,
    `- cache keys on query: ${
      outcome.keyedQuery
        ? "yes — unique buster MISSed (clean key)"
        : "no — query unkeyed or catch-all (verify in the exploitation phase)"
    }`,
    ...signals.map((s) => `- \`${s}\``),
    "",
    "Right-click -> **Profile cache behaviour** to classify the cache rule, key, intent and path-confusion surface.",
  ];

  try {
    await sdk.findings.create({
      reporter: "Cache Profiler",
      request,
      title: `CACHE CONFIRMED${note !== undefined ? ` [${v0.status}]` : ""} — ${host}${titlePath}`,
      description: lines.join("\n") + `\n\n---\n_cache-profiler v${PLUGIN_VERSION}_`,
      dedupeKey: `cache-confirmed:${scopeKey}`,
    });
  } catch (err) {
    sdk.console.warn(`[cache-profiler] confirmed finding failed: ${String(err)}`);
  }
}

// Emitted once per host when active confirmation is disabled — a lead, not a verdict, no traffic.
async function emitCandidate(
  sdk: BackendSDK,
  request: CaidoRequest,
  host: string,
  h: ReturnType<typeof lower>,
  trigger: TriggerKind,
): Promise<void> {
  const sig = cacheSignals(h);
  const kw = unknownCacheKeywordHits(h);
  const lines = [
    "**CACHE CANDIDATE**",
    "",
    `- a caching layer is present on \`${host}\` (passive header signal)`,
    `- trigger: ${
      trigger === "keyword"
        ? "cache-state keyword in an unrecognised header"
        : "status-bearing cache header (HIT/MISS)"
    }`,
    ...sig.map((s) => `- \`${s}\``),
    ...kw.map((u) => `- \`${u.keyword}\` in \`${u.header}\``),
    "",
    "Active confirmation is disabled. Set a scope (`CACHE_PROFILER_SCOPE`) or `CACHE_PROFILER_CONFIRM=on` to confirm cached resources by probing, or right-click -> **Profile cache behaviour** to test this request.",
  ];

  try {
    await sdk.findings.create({
      reporter: "Cache Profiler",
      request,
      title: `CACHE CANDIDATE — ${host}`,
      description: lines.join("\n") + `\n\n---\n_cache-profiler v${PLUGIN_VERSION}_`,
      dedupeKey: `cache-candidate:${host}`,
    });
  } catch (err) {
    sdk.console.warn(`[cache-profiler] candidate finding failed: ${String(err)}`);
  }
}
