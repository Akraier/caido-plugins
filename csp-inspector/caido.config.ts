import { defineConfig } from "@caido-community/dev";

export default defineConfig({
  id: "csp-inspector",
  name: "CSP Inspector",
  description:
    "Passively inspects every response's Content-Security-Policy and reports subdomains, same-brand hosts, internal IPs and possible origin IPs as Findings.",
  version: "0.1.0",
  author: {
    name: "Akraier",
    email: "72752917+Akraier@users.noreply.github.com",
    url: "https://github.com/akraier",
  },
  plugins: [
    {
      kind: "backend",
      id: "backend",
      root: "packages/backend",
    },
  ],
});
