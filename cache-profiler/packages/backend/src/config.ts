// Runtime configuration for the passive cache detector. Held as a single mutable object so the
// settings page can change it live (the interceptor reads it per-response). Seeded from env vars
// at load for headless / first-run use; the UI persists overrides in frontend storage.
import type { SDK } from "caido:plugin";

import type { BackendEvents } from "./types.js";

type AnySDK = SDK<never, BackendEvents>;

export type ConfirmMode = "auto" | "on" | "off";
export type DedupeMode = "host" | "smart" | "path";

export type RuntimeConfig = {
  scope: string[]; // registrable domains; empty => all hosts processed passively
  confirm: ConfirmMode; // auto = on when scope is set
  rate: number; // resources probed per minute
  max: number; // hard session ceiling on probed resources
  dedupe: DedupeMode; // passive finding granularity
  // OOB (interactsh) — for the unkeyed-header poisoning scan's blind/SSRF channel
  oobClient: boolean; // run the native interactsh client + auto-poll
  oobServer: string; // interactsh server URL (user-provided; no default)
  oobToken: string; // optional auth token for self-hosted servers
  oobPollMs: number; // poll interval (ms)
  oobWindowMin: number; // minutes to keep correlating after a scan ends
};

function parseScope(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

function parseConfirm(raw: string | undefined): ConfirmMode {
  const v = (raw ?? "").trim().toLowerCase();
  if (["on", "1", "true", "yes"].includes(v)) return "on";
  if (["off", "0", "false", "no"].includes(v)) return "off";
  return "auto";
}

function parseDedupe(raw: string | undefined): DedupeMode {
  const v = (raw ?? "").trim().toLowerCase();
  return v === "host" || v === "path" ? v : "smart";
}

function parsePositive(raw: string | undefined, fallback: number): number {
  const n = Number((raw ?? "").trim());
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function parseBool(raw: string | undefined): boolean {
  return ["on", "1", "true", "yes"].includes((raw ?? "").trim().toLowerCase());
}

export function seedConfigFromEnv(sdk: AnySDK): RuntimeConfig {
  return {
    scope: parseScope(sdk.env.getVar("CACHE_PROFILER_SCOPE")),
    confirm: parseConfirm(sdk.env.getVar("CACHE_PROFILER_CONFIRM")),
    rate: parsePositive(sdk.env.getVar("CACHE_PROFILER_RATE"), 30),
    max: parsePositive(sdk.env.getVar("CACHE_PROFILER_MAX"), 200),
    dedupe: parseDedupe(sdk.env.getVar("CACHE_PROFILER_DEDUPE")),
    oobClient: parseBool(sdk.env.getVar("CACHE_PROFILER_OOB_CLIENT")),
    oobServer: (sdk.env.getVar("CACHE_PROFILER_OOB_SERVER") ?? "").trim(),
    oobToken: (sdk.env.getVar("CACHE_PROFILER_OOB_TOKEN") ?? "").trim(),
    oobPollMs: parsePositive(sdk.env.getVar("CACHE_PROFILER_OOB_POLL_MS"), 5000),
    oobWindowMin: parsePositive(sdk.env.getVar("CACHE_PROFILER_OOB_WINDOW_MIN"), 10),
  };
}

// Merge a partial update (from the settings page) onto the current config, sanitising each field.
export function mergeConfig(
  current: RuntimeConfig,
  patch: Partial<RuntimeConfig>,
): RuntimeConfig {
  return {
    scope: Array.isArray(patch.scope)
      ? patch.scope.map((s) => s.trim().toLowerCase()).filter(Boolean)
      : current.scope,
    confirm: patch.confirm ?? current.confirm,
    rate: typeof patch.rate === "number" && patch.rate > 0 ? patch.rate : current.rate,
    max: typeof patch.max === "number" && patch.max > 0 ? patch.max : current.max,
    dedupe: patch.dedupe ?? current.dedupe,
    oobClient: typeof patch.oobClient === "boolean" ? patch.oobClient : current.oobClient,
    oobServer: typeof patch.oobServer === "string" ? patch.oobServer.trim() : current.oobServer,
    oobToken: typeof patch.oobToken === "string" ? patch.oobToken.trim() : current.oobToken,
    oobPollMs:
      typeof patch.oobPollMs === "number" && patch.oobPollMs > 0
        ? patch.oobPollMs
        : current.oobPollMs,
    oobWindowMin:
      typeof patch.oobWindowMin === "number" && patch.oobWindowMin > 0
        ? patch.oobWindowMin
        : current.oobWindowMin,
  };
}

// Whether the active confirmation machine runs: explicit on/off, or auto (on iff a scope is set).
export function effectiveConfirm(cfg: RuntimeConfig): boolean {
  if (cfg.confirm === "on") return true;
  if (cfg.confirm === "off") return false;
  return cfg.scope.length > 0;
}

export function hostInScope(host: string, scope: string[]): boolean {
  if (scope.length === 0) return true;
  return scope.some((d) => host === d || host.endsWith("." + d));
}

// True when this finding should be kept per-path rather than collapsed to host level.
export function isGranular(mode: DedupeMode, dynamic: boolean): boolean {
  if (mode === "path") return true;
  if (mode === "host") return false;
  return dynamic; // smart
}
