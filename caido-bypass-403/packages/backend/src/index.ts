import type { DefineAPI, SDK } from "caido:plugin";

import {
  DEFAULT_HEADERS,
  DEFAULT_IPS,
  DEFAULT_PATH_MUTATIONS,
  MARKER_HEADER,
} from "./defaults.js";
import { runBypass } from "./engine.js";
import type { BackendEvents, BypassSettings, Result } from "./types.js";

const DEFAULT_SETTINGS: BypassSettings = {
  headers: DEFAULT_HEADERS,
  ips: DEFAULT_IPS,
  pathMutationIds: DEFAULT_PATH_MUTATIONS.map((m) => m.id),
  autoMode: false,
  scopeGated: true,
  concurrency: 8,
};

let currentSettings: BypassSettings = { ...DEFAULT_SETTINGS };
const inflightJobs = new Set<string>();

type RunOpts = {
  requestId?: string;
  raw?: string;
};

const runBypassOn = async (
  sdk: SDK<never, BackendEvents>,
  opts: RunOpts,
): Promise<Result<{ jobId: string }>> => {
  if (opts.requestId === undefined) {
    return { kind: "Error", error: "Missing requestId. Trigger bypass from a captured request." };
  }

  const existing = await sdk.requests.get(opts.requestId);
  if (existing === undefined) {
    return { kind: "Error", error: `Request ${opts.requestId} not found.` };
  }

  const targetUrl = existing.request.getUrl();
  if (inflightJobs.has(targetUrl)) {
    return { kind: "Error", error: `A bypass job is already running for ${targetUrl}.` };
  }
  inflightJobs.add(targetUrl);

  try {
    const done = await runBypass(
      sdk,
      existing.request,
      existing.response,
      currentSettings,
      DEFAULT_PATH_MUTATIONS,
    );
    return { kind: "Ok", value: { jobId: done.jobId } };
  } finally {
    inflightJobs.delete(targetUrl);
  }
};

const getSettings = (_sdk: SDK<never, BackendEvents>): BypassSettings => {
  return currentSettings;
};

const setSettings = (
  _sdk: SDK<never, BackendEvents>,
  next: BypassSettings,
): Result<BypassSettings> => {
  currentSettings = {
    headers: next.headers.filter((h) => h.trim().length > 0),
    ips: next.ips.filter((ip) => ip.trim().length > 0),
    pathMutationIds: next.pathMutationIds,
    autoMode: next.autoMode === true,
    scopeGated: next.scopeGated !== false,
    concurrency: Math.max(1, Math.min(32, Math.floor(next.concurrency))),
  };
  return { kind: "Ok", value: currentSettings };
};

const getDefaults = (
  _sdk: SDK<never, BackendEvents>,
): {
  headers: string[];
  ips: string[];
  pathMutations: Array<{ id: string; label: string }>;
} => {
  return {
    headers: DEFAULT_HEADERS,
    ips: DEFAULT_IPS,
    pathMutations: DEFAULT_PATH_MUTATIONS.map((m) => ({ id: m.id, label: m.label })),
  };
};

export type API = DefineAPI<{
  runBypassOn: typeof runBypassOn;
  getSettings: typeof getSettings;
  setSettings: typeof setSettings;
  getDefaults: typeof getDefaults;
}>;

export type { BackendEvents } from "./types.js";

export const init = (sdk: SDK<API, BackendEvents>): void => {
  sdk.api.register("runBypassOn", runBypassOn);
  sdk.api.register("getSettings", getSettings);
  sdk.api.register("setSettings", setSettings);
  sdk.api.register("getDefaults", getDefaults);

  sdk.events.onInterceptResponse(async (innerSdk, request, response) => {
    if (currentSettings.autoMode !== true) return;

    const code = response.getCode();
    if (code !== 401 && code !== 403) return;

    if (request.getHeader(MARKER_HEADER) !== undefined) return;

    if (currentSettings.scopeGated === true) {
      const inScope = await innerSdk.requests.inScope(request);
      if (inScope !== true) return;
    }

    const url = request.getUrl();
    if (inflightJobs.has(url)) return;
    inflightJobs.add(url);

    runBypass(innerSdk, request, response, currentSettings, DEFAULT_PATH_MUTATIONS)
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        innerSdk.console.error(`[bypass-403] auto-run failed: ${message}`);
      })
      .finally(() => {
        inflightJobs.delete(url);
      });
  });
};
