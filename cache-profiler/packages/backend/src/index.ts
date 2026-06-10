import type { DefineAPI, SDK } from "caido:plugin";
import type {
  Request as CaidoRequest,
  Response as CaidoResponse,
} from "caido:utils";

import {
  cacheSignals,
  formatProfile,
  isCacheCandidate,
  isDynamicResponse,
  lower,
  statusNote,
  summaryLine,
  unknownCacheKeywordHits,
} from "./cache.js";
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
export const PLUGIN_VERSION = "0.2.0";

function withVersion(description: string): string {
  return `${description}\n\n---\n_cache-profiler v${PLUGIN_VERSION}_`;
}

// Optional scope filter for passive detection: comma-separated registrable domains.
// Empty => process all responses. The active commands are always scope-gated.
function scopeList(sdk: BackendSDK): string[] {
  return (sdk.env.getVar("CACHE_PROFILER_SCOPE") ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

function hostInScope(host: string, scope: string[]): boolean {
  if (scope.length === 0) return true;
  return scope.some((d) => host === d || host.endsWith("." + d));
}

// Passive dedupe granularity:
//   host  — one finding per host+status (aggressive; for massively-cached targets)
//   smart — static collapses per host+status, dynamic content is kept per path (default)
//   path  — one finding per host+status+path (granular; for sparse caches, miss nothing)
type DedupeMode = "host" | "smart" | "path";

function dedupeMode(sdk: BackendSDK): DedupeMode {
  const v = (sdk.env.getVar("CACHE_PROFILER_DEDUPE") ?? "").trim().toLowerCase();
  return v === "host" || v === "path" ? v : "smart";
}

// True when this finding should be kept per-path rather than collapsed to host level.
function isGranular(mode: DedupeMode, dynamic: boolean): boolean {
  if (mode === "path") return true;
  if (mode === "host") return false;
  return dynamic; // smart
}

// Comparer path for origin path-normalization (default site root). Override to a stable,
// non-cached dynamic endpoint when "/" is a poor comparer.
function normComparer(sdk: BackendSDK): string {
  const v = (sdk.env.getVar("CACHE_PROFILER_NORM_PATH") ?? "").trim();
  if (v.length === 0) return "/";
  return v.startsWith("/") ? v : "/" + v;
}

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
}>;

export type { BackendEvents } from "./types.js";

export const init = (sdk: SDK<API, BackendEvents>): void => {
  sdk.console.log(`[cache-profiler] backend v${PLUGIN_VERSION} loaded`);

  sdk.api.register("runProfileOn", runProfileOn);
  sdk.api.register("runDelimiterOn", runDelimiterOn);
  sdk.api.register("runNormalizationOn", runNormalizationOn);
  sdk.api.register("runTimingOn", runTimingOn);

  const scope = scopeList(sdk);
  const mode = dedupeMode(sdk);

  // Phase 1 — passive: flag any response that advertises a caching layer. Read-only, sends
  // nothing. Dedupe granularity is content-type-aware (toggle via CACHE_PROFILER_DEDUPE).
  sdk.events.onInterceptResponse(async (innerSdk, request, response) => {
    const h = lower(response.getHeaders());
    const host = request.getHost().toLowerCase();
    if (!hostInScope(host, scope)) return;

    const known = isCacheCandidate(h);
    const unknownHits = unknownCacheKeywordHits(h);
    if (!known && unknownHits.length === 0) return;

    const status = response.getCode();
    const path = request.getPath();
    const note = statusNote(status);
    const statusBullet = `- status: \`${status}\`${note !== undefined ? ` — ${note}` : ""}`;
    const granular = isGranular(mode, isDynamicResponse(h, path));
    const scopeKey = granular ? `${host}:${status}:${path}` : `${host}:${status}`;
    const titlePath = granular ? ` ${path}` : "";

    try {
      if (known) {
        const signals = cacheSignals(h);
        const extra = unknownHits.map(
          (u) => `- also: \`${u.keyword}\` in unrecognised header \`${u.header}\``,
        );
        await innerSdk.findings.create({
          reporter: "Cache Profiler",
          request,
          title: `CACHE DETECTED${note !== undefined ? ` [${status}]` : ""} — ${host}${titlePath}`,
          description: [
            "**CACHE DETECTED**",
            "",
            statusBullet,
            ...signals.map((s) => `- \`${s}\``),
            ...extra,
            "",
            "Right-click -> **Profile cache behaviour** to classify the cache rule, key, intent and path-confusion surface.",
          ].join("\n") + `\n\n---\n_cache-profiler v${PLUGIN_VERSION}_`,
          dedupeKey: `cache-detected:${scopeKey}`,
        });
      } else {
        // A cache-state keyword appeared in a header we don't recognise — surface as a lead.
        await innerSdk.findings.create({
          reporter: "Cache Profiler",
          request,
          title: `CACHE POTENTIALLY DETECTED — ${host}${titlePath}`,
          description: [
            "**CACHE POTENTIALLY DETECTED**",
            "",
            statusBullet,
            ...unknownHits.map(
              (u) => `- \`${u.keyword}\` in \`${u.header}\`  (\`${u.header}: ${u.value}\`)`,
            ),
            "",
            "A cache-state keyword appeared in a header the plugin does not recognise. Confirm with **Timing cache probe** or **Profile cache behaviour**, and consider adding the header to the known list.",
          ].join("\n") + `\n\n---\n_cache-profiler v${PLUGIN_VERSION}_`,
          dedupeKey: `cache-potential:${scopeKey}:${unknownHits.map((u) => u.header).sort().join(",")}`,
        });
      }
    } catch (err) {
      innerSdk.console.warn(
        `[cache-profiler] passive finding failed: ${String(err)}`,
      );
    }
  });
};
