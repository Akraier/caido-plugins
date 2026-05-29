# caido-plugins

Caido plugins for security testing and recon.

## Plugins

| Plugin | Description |
| --- | --- |
| [csp-inspector](./csp-inspector) | Passively inspects every response's Content-Security-Policy and reports subdomains, same-brand hosts, internal IPs and possible origin IPs as Findings. |
| [caido-bypass-403](./caido-bypass-403) | Automatic 403/401 bypass via header injection (IP spoofing), path mutations, and host overrides. Manual right-click or opt-in auto-mode. |
| [caido-reflector](./caido-reflector) | Passive parameter-reflection detection with HTML / JS / attribute / URL context classification. |

## Building

Each plugin is a self-contained workspace in its own directory with its own README and
toolchain. Build from inside the plugin directory, then install the resulting
`dist/plugin_package.zip` in Caido via **Plugins -> Install Package**. See each plugin's
README for exact build commands (`csp-inspector` and `caido-bypass-403` use pnpm).

## License

[MIT](./LICENSE) — applies to the plugins authored in this repository.
