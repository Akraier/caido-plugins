import type { RawConfigurationOrFn } from "knip/dist/types/config.js";

const config: RawConfigurationOrFn = {
  ignore: ["**/dist/**"],
  workspaces: {
    ".": {
      entry: ["caido.config.ts", "eslint.config.mjs"],
    },
    "packages/backend": {
      entry: ["src/index.ts"],
      project: ["src/**/*.ts"],
      ignoreDependencies: ["caido"],
    },
  },
};

export default config;
