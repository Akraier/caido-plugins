import { defineConfig } from "@caido-community/dev";

export default defineConfig({
  id: "cache-profiler",
  name: "Cache Profiler",
  description:
    "Profiles HTTP caching behaviour: passively flags cached responses, then on demand classifies the cache rule (static extension / directory / file / origin-directed), maps the cache key vs Vary, derives the origin-vs-edge intent, and probes delimiter-based path confusion. Reports a single structured Finding per request.",
  version: "0.4.1",
  author: {
    name: "Akraier",
    url: "https://github.com/akraier",
  },
  plugins: [
    {
      kind: "frontend",
      id: "cache-profiler-frontend",
      name: "Cache Profiler",
      root: "packages/frontend",
      backend: { id: "cache-profiler-backend" },
    },
    {
      kind: "backend",
      id: "cache-profiler-backend",
      name: "Cache Profiler Backend",
      root: "packages/backend",
    },
  ],
});
