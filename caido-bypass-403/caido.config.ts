import { defineConfig } from "@caido-community/dev";

export default defineConfig({
  id: "bypass-403",
  name: "Bypass 403/401",
  description:
    "Automatic 403/401 bypass via header injection (IP spoofing), path mutations, and host overrides. Manual right-click or opt-in auto-mode on intercepted responses.",
  version: "0.1.0",
  author: {
    name: "Akraier",
    url: "https://github.com/akraier",
  },
  plugins: [
    {
      kind: "frontend",
      id: "bypass-403-frontend",
      name: "Bypass 403/401",
      root: "packages/frontend",
      backend: { id: "bypass-403-backend" },
    },
    {
      kind: "backend",
      id: "bypass-403-backend",
      name: "Bypass 403/401 Backend",
      root: "packages/backend",
    },
  ],
});
