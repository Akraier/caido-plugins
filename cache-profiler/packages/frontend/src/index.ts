import { mountSettingsPage } from "./settings";
import type { FrontendSDK } from "./types";

// Keep in sync with PLUGIN_VERSION in the backend / caido.config.ts.
const PLUGIN_VERSION = "0.5.0";

const Commands = {
  run: "cache-profiler.run",
  delimiter: "cache-profiler.delimiter",
  normalization: "cache-profiler.normalization",
  timing: "cache-profiler.timing",
  poison: "cache-profiler.poison",
} as const;

const requestIdFrom = (context: unknown): string | undefined => {
  const c = context as
    | { type: "RequestRowContext"; requests: Array<{ id: string }> }
    | { type: "RequestContext"; request: { id: string } }
    | undefined;
  if (c === undefined) return undefined;
  if (c.type === "RequestRowContext") return c.requests[0]?.id;
  if (c.type === "RequestContext") return c.request.id;
  return undefined;
};

const runProfile = async (
  sdk: FrontendSDK,
  requestId: string | undefined,
): Promise<void> => {
  if (requestId === undefined) {
    sdk.window.showToast("Select a request first", { variant: "warning" });
    return;
  }
  sdk.window.showToast("Cache profiling started…", { variant: "info" });
  const res = await sdk.backend.runProfileOn({ requestId });
  if (res.kind === "Error") {
    sdk.window.showToast(res.error, { variant: "error" });
  }
};

const runDelimiter = async (
  sdk: FrontendSDK,
  requestId: string | undefined,
): Promise<void> => {
  if (requestId === undefined) {
    sdk.window.showToast("Select a request first", { variant: "warning" });
    return;
  }
  sdk.window.showToast("Delimiter detection started…", { variant: "info" });
  const res = await sdk.backend.runDelimiterOn({ requestId });
  if (res.kind === "Error") {
    sdk.window.showToast(res.error, { variant: "error" });
  }
};

const runNormalization = async (
  sdk: FrontendSDK,
  requestId: string | undefined,
): Promise<void> => {
  if (requestId === undefined) {
    sdk.window.showToast("Select a request first", { variant: "warning" });
    return;
  }
  sdk.window.showToast("Path normalization started…", { variant: "info" });
  const res = await sdk.backend.runNormalizationOn({ requestId });
  if (res.kind === "Error") {
    sdk.window.showToast(res.error, { variant: "error" });
  }
};

const runTiming = async (
  sdk: FrontendSDK,
  requestId: string | undefined,
): Promise<void> => {
  if (requestId === undefined) {
    sdk.window.showToast("Select a request first", { variant: "warning" });
    return;
  }
  sdk.window.showToast("Timing cache probe started…", { variant: "info" });
  const res = await sdk.backend.runTimingOn({ requestId });
  if (res.kind === "Error") {
    sdk.window.showToast(res.error, { variant: "error" });
  }
};

const runPoison = async (
  sdk: FrontendSDK,
  requestId: string | undefined,
): Promise<void> => {
  if (requestId === undefined) {
    sdk.window.showToast("Select a request first", { variant: "warning" });
    return;
  }
  sdk.window.showToast("Unkeyed-header scan started (probes are buster-isolated)…", {
    variant: "info",
  });
  const res = await sdk.backend.runPoisonOn({ requestId });
  if (res.kind === "Error") {
    sdk.window.showToast(res.error, { variant: "error" });
  }
};

export const init = (sdk: FrontendSDK): void => {
  sdk.window.showToast(`Cache Profiler v${PLUGIN_VERSION} loaded`, {
    variant: "info",
  });

  // Settings page (sidebar) — live-editable scope / confirm / rate / max / dedupe + status.
  mountSettingsPage(sdk);

  sdk.commands.register(Commands.run, {
    name: "Profile cache behaviour",
    group: "Cache Profiler",
    run: async (context) => {
      await runProfile(sdk, requestIdFrom(context));
    },
  });

  sdk.commands.register(Commands.delimiter, {
    name: "Delimiter detection",
    group: "Cache Profiler",
    run: async (context) => {
      await runDelimiter(sdk, requestIdFrom(context));
    },
  });

  sdk.commands.register(Commands.normalization, {
    name: "Path normalization",
    group: "Cache Profiler",
    run: async (context) => {
      await runNormalization(sdk, requestIdFrom(context));
    },
  });

  sdk.commands.register(Commands.timing, {
    name: "Timing cache probe",
    group: "Cache Profiler",
    run: async (context) => {
      await runTiming(sdk, requestIdFrom(context));
    },
  });

  sdk.commands.register(Commands.poison, {
    name: "Cache poisoning: unkeyed headers",
    group: "Cache Profiler",
    run: async (context) => {
      await runPoison(sdk, requestIdFrom(context));
    },
  });

  sdk.commandPalette.register(Commands.run);
  sdk.commandPalette.register(Commands.delimiter);
  sdk.commandPalette.register(Commands.normalization);
  sdk.commandPalette.register(Commands.timing);
  sdk.commandPalette.register(Commands.poison);

  for (const type of ["Request", "RequestRow"] as const) {
    sdk.menu.registerItem({
      type,
      commandId: Commands.run,
      leadingIcon: "fas fa-database",
    });
    sdk.menu.registerItem({
      type,
      commandId: Commands.delimiter,
      leadingIcon: "fas fa-scissors",
    });
    sdk.menu.registerItem({
      type,
      commandId: Commands.normalization,
      leadingIcon: "fas fa-folder-tree",
    });
    sdk.menu.registerItem({
      type,
      commandId: Commands.timing,
      leadingIcon: "fas fa-stopwatch",
    });
    sdk.menu.registerItem({
      type,
      commandId: Commands.poison,
      leadingIcon: "fas fa-flask",
    });
  }

  sdk.backend.onEvent("cache-profiler:start", (data) => {
    sdk.window.showToast(`Cache profiling: ${data.url}`, { variant: "info" });
  });

  sdk.backend.onEvent("cache-profiler:done", (data) => {
    const variant = data.summary.includes("LEAK") ? "success" : "info";
    sdk.window.showToast(`Cache profile done — ${data.summary}`, { variant });
  });

  sdk.backend.onEvent("cache-profiler:error", (data) => {
    sdk.window.showToast(`Cache profiler error: ${data.message}`, {
      variant: "error",
    });
  });
};
