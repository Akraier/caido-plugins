import { builtinModules } from "node:module";
import { resolve } from "node:path";

import { defineConfig } from "vite";

export default defineConfig({
  build: {
    lib: {
      entry: resolve(import.meta.dirname, "src/index.ts"),
      name: "caido-backslash-backend",
      fileName: () => "script.js",
      formats: ["es"],
    },
    outDir: "../../dist/backend",
    emptyOutDir: true,
    // The backend runs in QuickJS, not Node. `caido:` modules are host-provided and must stay
    // external; anything else is bundled because the runtime has no module resolution.
    rollupOptions: {
      external: [/^caido:.+/, ...builtinModules],
      output: { manualChunks: undefined },
    },
    target: "es2023",
    minify: false,
  },
});
