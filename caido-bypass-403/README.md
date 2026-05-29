# Bypass 403/401 — Caido plugin

Automatic 403/401 bypass for [Caido](https://caido.io). Detects auth-blocked responses and probes them with the classic header-injection / path-mutation matrix:

- IP-spoof headers paired with loopback / RFC1918 / cloud-metadata values
- URL-rewrite headers (`X-Original-URL`, `X-Rewrite-URL`, ...)
- Host-override headers (`X-Forwarded-Host`, `X-HTTP-Host-Override`, ...)
- Path mutations (`//`, `/./`, `/%2e/`, trailing `/`, case toggle, `%00`, `%23`, ...)

## Install (binary)

1. `pnpm install`
2. `pnpm build`
3. In Caido: **Plugins → Install from file → `dist/plugin_package.zip`**

> Requires Node 18+ and [pnpm](https://pnpm.io/installation). On macOS: `corepack enable && corepack prepare pnpm@latest --activate`.

## Use

### Manual (recommended)

Right-click any request returning 401 or 403 (in HTTP History, Replay, Search, Intercept) → **Run 403/401 bypass on this request**. The plugin runs the configured matrix and lands you on the **Bypass 403** tab.

### Auto mode

Open the plugin → **Settings → Engine** → enable **Auto-trigger**. Every 401/403 intercepted on an in-scope host will fire the matrix once. Auto-mode is rate-limited by:

- Per-URL deduplication (one in-flight job per target URL)
- Concurrency cap (default 8)
- Marker header `X-Bypass-403-Probe` — auto-mode never recurses on its own traffic
- Scope gating (toggle) — skips out-of-scope responses

## Results table

| Status | Len | Vector | Value | M | URL |
|--------|-----|--------|-------|---|-----|
| `200`  | 4821 | X-Original-URL | /admin | GET | https://target/x |
| `302`  | 0    | path   | `//<path>` | GET | https://target/x |

- **Status** color-coded: 2xx green, 3xx info, 4xx amber, 5xx red, error grey.
- **Interesting filter** is on by default — hides anything that matches the baseline status.
- **Send to Replay** button on each row to deep-dive a hit.

## Configuration

Settings page lets you edit:

- **Headers** — one per line. Each is paired with every IP/host.
- **IPs / Hostnames** — one per line. Includes `169.254.169.254` (AWS/GCP metadata) by default.
- **Path mutations** — toggleable list of URL rewrites.
- **Concurrency** — 1-32, raise it for fast targets, lower it for fragile ones.

Probe count = `len(headers) × len(IPs) + len(enabled path mutations)`. Shown live in the settings header.

## Safety

- Every probe carries `X-Bypass-403-Probe: <jobId>` — strip it server-side if it confuses your apps.
- Auto-mode is **off by default**. Even when enabled, it only fires on in-scope responses unless you flip the scope gate off.
- The plugin does not bypass Caido's match-and-replace, scope, or upstream rules.

## Dev

```
pnpm install
pnpm watch    # hot-reload via Caido Devtools
pnpm build    # dist/plugin_package.zip
pnpm typecheck
```

## License

MIT
