# CSP Inspector

A passive **Caido** backend plugin. It inspects the `Content-Security-Policy` of every
proxied response and reports the hosts and IP addresses it discloses, classified relative
to the request's own host. The goal is to turn CSP allow-lists into recon: subdomains,
sibling brand domains, internal/intranet IPs, and — when exposed — a possible **origin IP**
behind a CDN.

The plugin is read-only. It never sends a request of its own; it only reads traffic already
flowing through the proxy.

## What it extracts

For each response carrying a CSP, it parses the source list and sorts every host/IP token
into five buckets, then emits a single **Finding**:

| Category | Meaning |
| --- | --- |
| Subdomains / same-domain hosts | Same registrable domain as the request host (e.g. `api.target.com` for `www.target.com`). Wildcards like `*.target.com` are kept. |
| Same-brand, different TLD | Same brand label, different TLD (e.g. `target.dev`, `target.dev:8443`). |
| Internal IPs | RFC1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`, `::1`), link-local (`169.254/16`, `fe80::/10`), CGNAT (`100.64/10`), IPv6 ULA (`fc00::/7`). Ports preserved. |
| Public / possible origin IPs | Any public IPv4/IPv6 literal — often the real origin of a CDN-fronted target. |
| Third-party hosts | Unrelated hosts (CDNs, analytics, SaaS). |

Recognized CSP headers (case-insensitive): `content-security-policy`,
`content-security-policy-report-only`, `x-content-security-policy`,
`x-content-security-policy-report-only`, `x-webkit-csp`.

### Example

Request `Host: www.target.com`, response:

```
Content-Security-Policy: default-src 'self'; connect-src https://api.target.com
  https://target.dev:8443 https://10.0.0.5:9200 https://203.0.113.42
  https://[fd00::1] https://[2606:4700::1]:443 https://cdn.thirdparty.net
```

Produces one Finding `CSP host/IP disclosure — www.target.com`:

```
Subdomains / same-domain hosts:
  api.target.com
Same-brand, different TLD:
  target.dev:8443
Internal IPs:
  10.0.0.5:9200
  [fd00::1]
Public / possible origin IPs:
  203.0.113.42
  [2606:4700::1]:443
Third-party hosts:
  cdn.thirdparty.net
```

## Settings

| Environment variable | Effect |
| --- | --- |
| `CSP_INSPECTOR_SCOPE` | Comma-separated registrable domains (e.g. `target.com,target.dev`). When set, only responses whose request host matches one of them are processed. When unset, **all** responses are processed. |

Set it under Caido's Environment (the global environment, or a project-scoped one).

Findings are deduplicated by request host plus the sorted set of extracted values: an
identical CSP never spams new Findings, while a changed CSP produces a fresh one.

## Build

Requires Node 20+ and pnpm.

```bash
pnpm install
pnpm build      # -> dist/plugin_package.zip
```

Install the resulting `dist/plugin_package.zip` in Caido via **Plugins -> Install Package**.

For iterative development, `pnpm watch` rebuilds on change (pair with the Caido Devtools plugin).

## Layout

```
caido.config.ts                 plugin id / name / metadata
packages/backend/src/index.ts   all logic (CSP parsing, classification, Finding output)
```

## License

MIT — see [LICENSE](../LICENSE).
