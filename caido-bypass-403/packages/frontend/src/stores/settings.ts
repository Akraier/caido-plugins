import { reactive, readonly } from "vue";

import type { FrontendSDK } from "../types";

export type Settings = {
  headers: string[];
  ips: string[];
  pathMutationIds: string[];
  autoMode: boolean;
  scopeGated: boolean;
  concurrency: number;
};

export type PathMutationDef = { id: string; label: string };

type State = {
  settings: Settings;
  defaults: {
    headers: string[];
    ips: string[];
    pathMutations: PathMutationDef[];
  };
  loaded: boolean;
};

const state = reactive<State>({
  settings: {
    headers: [],
    ips: [],
    pathMutationIds: [],
    autoMode: false,
    scopeGated: true,
    concurrency: 8,
  },
  defaults: { headers: [], ips: [], pathMutations: [] },
  loaded: false,
});

export const settingsStore = {
  state: readonly(state),

  async load(sdk: FrontendSDK): Promise<void> {
    const [defaults, current] = await Promise.all([
      sdk.backend.getDefaults(),
      sdk.backend.getSettings(),
    ]);
    state.defaults = defaults;
    state.settings = { ...current };
    state.loaded = true;
  },

  async save(sdk: FrontendSDK, next: Settings): Promise<void> {
    const result = await sdk.backend.setSettings(next);
    if (result.kind === "Error") {
      sdk.window.showToast(result.error, { variant: "error" });
      return;
    }
    state.settings = { ...result.value };
    sdk.window.showToast("Settings saved", { variant: "success" });
  },

  resetToDefaults(): Settings {
    return {
      headers: [...state.defaults.headers],
      ips: [...state.defaults.ips],
      pathMutationIds: state.defaults.pathMutations.map((m) => m.id),
      autoMode: false,
      scopeGated: true,
      concurrency: 8,
    };
  },
};
