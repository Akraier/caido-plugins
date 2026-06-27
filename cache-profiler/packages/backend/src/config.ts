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

export function seedConfigFromEnv(sdk: AnySDK): RuntimeConfig {
  return {
    scope: parseScope(sdk.env.getVar("CACHE_PROFILER_SCOPE")),
    confirm: parseConfirm(sdk.env.getVar("CACHE_PROFILER_CONFIRM")),
    rate: parsePositive(sdk.env.getVar("CACHE_PROFILER_RATE"), 30),
    max: parsePositive(sdk.env.getVar("CACHE_PROFILER_MAX"), 200),
    dedupe: parseDedupe(sdk.env.getVar("CACHE_PROFILER_DEDUPE")),
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
