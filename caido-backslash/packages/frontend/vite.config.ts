import { resolve } from "node:path";

import { defineConfig } from "vite";

export default defineConfig({
  build: {
    lib: {
      entry: resolve(import.meta.dirname, "src/index.ts"),
      name: "caido-backslash-frontend",
      fileName: () => "script.js",
      formats: ["es"],
    },
    outDir: "../../dist/frontend",
    emptyOutDir: true,
    rollupOptions: { external: [/^@caido\/sdk-frontend/] },
    target: "es2023",
    minify: false,
  },
});
