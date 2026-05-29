import { createApp, h } from "vue";
import PrimeVue from "primevue/config";
import ToastService from "primevue/toastservice";

import ResultsPage from "./pages/ResultsPage.vue";
import SettingsPage from "./pages/SettingsPage.vue";
import { resultsStore } from "./stores/results";
import { settingsStore } from "./stores/settings";
import type { FrontendSDK } from "./types";

const Commands = {
  runBypass: "bypass-403.run",
  openResults: "bypass-403.open-results",
  openSettings: "bypass-403.open-settings",
} as const;

const PATH_RESULTS = "/bypass-403";
const PATH_SETTINGS = "/bypass-403/settings";

const mountPage = (sdk: FrontendSDK, path: string, component: typeof ResultsPage): void => {
  const root = document.createElement("div");
  root.style.height = "100%";

  const app = createApp({
    render: () => h(component, { sdk }),
  });
  app.use(PrimeVue, { unstyled: false });
  app.use(ToastService);
  app.mount(root);

  sdk.navigation.addPage(path, { body: root });
};

const runOnRequest = async (sdk: FrontendSDK, requestId: string | undefined): Promise<void> => {
  if (requestId === undefined) {
    sdk.window.showToast("Select a request first", { variant: "warning" });
    return;
  }
  sdk.window.showToast("Bypass started…", { variant: "info" });
  const res = await sdk.backend.runBypassOn({ requestId });
  if (res.kind === "Error") {
    sdk.window.showToast(res.error, { variant: "error" });
    return;
  }
  sdk.navigation.goTo(PATH_RESULTS);
};

export const init = (sdk: FrontendSDK): void => {
  mountPage(sdk, PATH_RESULTS, ResultsPage);
  mountPage(sdk, PATH_SETTINGS, SettingsPage);

  sdk.sidebar.registerItem("Bypass 403", PATH_RESULTS, { icon: "fas fa-unlock" });

  sdk.commands.register(Commands.runBypass, {
    name: "Run 403/401 bypass on this request",
    group: "Bypass 403",
    run: async (context) => {
      const requestId =
        context !== undefined && context.type === "RequestRowContext"
          ? context.requests[0]?.id
          : context !== undefined && context.type === "RequestContext"
            ? context.request.id
            : undefined;
      await runOnRequest(sdk, requestId);
    },
  });

  sdk.commands.register(Commands.openResults, {
    name: "Bypass 403 — open results",
    group: "Bypass 403",
    run: () => sdk.navigation.goTo(PATH_RESULTS),
  });

  sdk.commands.register(Commands.openSettings, {
    name: "Bypass 403 — open settings",
    group: "Bypass 403",
    run: () => sdk.navigation.goTo(PATH_SETTINGS),
  });

  sdk.commandPalette.register(Commands.runBypass);
  sdk.commandPalette.register(Commands.openResults);
  sdk.commandPalette.register(Commands.openSettings);

  sdk.menu.registerItem({
    type: "Request",
    commandId: Commands.runBypass,
    leadingIcon: "fas fa-unlock",
  });
  sdk.menu.registerItem({
    type: "RequestRow",
    commandId: Commands.runBypass,
    leadingIcon: "fas fa-unlock",
  });

  sdk.backend.onEvent("bypass-403:job-start", (data) => {
    resultsStore.registerJob({
      jobId: data.jobId,
      targetUrl: data.targetUrl,
      total: data.total,
      baselineStatus: data.baselineStatus,
      baselineLength: data.baselineLength,
      startedAt: Date.now(),
    });
    sdk.window.showToast(
      `Bypass running: ${data.total} probes against ${data.targetUrl}`,
      { variant: "info" },
    );
  });

  sdk.backend.onEvent("bypass-403:result", (row) => {
    resultsStore.pushRow({ ...row, receivedAt: Date.now() });
  });

  sdk.backend.onEvent("bypass-403:job-done", (data) => {
    resultsStore.finishJob(data.jobId, data.interestingCount, Date.now());
    const variant = data.interestingCount > 0 ? "success" : "info";
    sdk.window.showToast(
      `Bypass done: ${data.interestingCount}/${data.totalCount} interesting`,
      { variant },
    );
  });

  sdk.backend.onEvent("bypass-403:error", (data) => {
    sdk.window.showToast(`Bypass error: ${data.message}`, { variant: "error" });
  });

  settingsStore.load(sdk).catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    sdk.window.showToast(`Failed to load settings: ${message}`, { variant: "error" });
  });
};
