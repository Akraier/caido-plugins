import type { FindingRow, FrontendSDK, ReflectorConfig } from "./types";

const PATH = "/reflector";
const MAX_FINDINGS = 500;
const MAX_LOGS = 500;

const Commands = {
  enable: "reflector.enable",
  disable: "reflector.disable",
} as const;

// Live state, updated by backend events regardless of whether the page is open.
const state = {
  findings: [] as FindingRow[],
  logs: [] as string[],
};

// Set by the page while mounted so events can trigger re-renders.
let onFindingsChanged: (() => void) | null = null;
let onLogsChanged: (() => void) | null = null;

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  style?: Partial<CSSStyleDeclaration>,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (style) Object.assign(node.style, style);
  if (text !== undefined) node.textContent = text;
  return node;
}

function label(text: string): HTMLElement {
  return el("div", { fontWeight: "600", margin: "0 0 0.25rem 0" }, text);
}

// Native form controls (select / input / textarea) must set BOTH background and color explicitly,
// from Caido theme tokens. Unlike an sdk.ui component, a bare native control takes its background
// from the user-agent `Field` colour -- white under a light colour-scheme -- while its `color`
// inherits from the page, which under Caido's dark theme is near-white. The result is white text on
// a white field: a control that looks blank even while holding a value. `color-scheme` is set too so
// the dropdown popup and number spinners (browser chrome that CSS variables cannot reach) also match.
function styleControl(node: HTMLSelectElement | HTMLInputElement | HTMLTextAreaElement): void {
  node.style.background = "var(--c-bg-subtle, #161b22)";
  node.style.color = "var(--c-fg-default, #e6edf3)";
  node.style.border = "1px solid var(--c-border, #333)";
  node.style.borderRadius = "4px";
  node.style.colorScheme = "dark light";
}

// ---- Toggle section -------------------------------------------------------

function buildToggle(sdk: FrontendSDK, getCfg: () => ReflectorConfig, setEnabled: (v: boolean) => Promise<void>): { card: HTMLElement; render: () => void } {
  const status = el("p", { margin: "0", fontWeight: "600" });
  const hint = el("p", { margin: "0.25rem 0 0 0", opacity: "0.7", fontSize: "0.85rem" });
  const btnHost = el("div", { marginTop: "0.75rem" });

  const render = (): void => {
    const enabled = getCfg().enabled;
    status.textContent = enabled ? "Status: ACTIVE" : "Status: PAUSED";
    status.style.color = enabled ? "var(--c-success, #3fb950)" : "var(--c-fg-secondary, #888)";
    hint.textContent = enabled
      ? "Scanning intercepted responses and probing reflected parameters."
      : "Ignoring all responses — no scanning, no probes are sent.";

    btnHost.replaceChildren();
    const btn = sdk.ui.button({
      variant: enabled ? "secondary" : "primary",
      label: enabled ? "Disable" : "Enable",
      leadingIcon: enabled ? "fas fa-pause" : "fas fa-play",
    });
    btn.addEventListener("click", () => {
      void setEnabled(!getCfg().enabled).then(render);
    });
    btnHost.appendChild(btn);
  };

  const body = el("div");
  body.append(status, hint, btnHost);
  render();
  return { card: sdk.ui.card({ header: el("h2", { margin: "0" }, "Toggle"), body }), render };
}

// ---- Config section -------------------------------------------------------

function buildConfig(sdk: FrontendSDK, getCfg: () => ReflectorConfig, save: (patch: Partial<ReflectorConfig>) => Promise<void>): { card: HTMLElement; render: () => void } {
  const verbose = el("input") as HTMLInputElement;
  verbose.type = "checkbox";
  // A native checkbox is UA chrome; the light-scheme default renders wrong against the dark theme,
  // so hint the scheme (no bg/color -- a checkbox holds no text, so the white-on-white trap does not
  // apply, but the box itself must match).
  verbose.style.colorScheme = "dark light";
  const verboseWrap = el("label", { display: "flex", alignItems: "center", gap: "0.5rem", margin: "0 0 0.75rem 0" });
  verboseWrap.append(verbose, el("span", undefined, "Verbose console logging"));

  const maxBody = el("input", { width: "12rem" }) as HTMLInputElement;
  maxBody.type = "number";
  maxBody.min = "1024";
  // Was set only for width, so it inherited near-white page text on the UA white field: invisible.
  styleControl(maxBody);

  const cts = el("textarea", { width: "100%", minHeight: "7rem", fontFamily: "monospace", boxSizing: "border-box" }) as HTMLTextAreaElement;
  // Same UA trap as the input above: the allow-list text was near-white on the white textarea field.
  styleControl(cts);

  const btnHost = el("div", { marginTop: "0.75rem" });

  const render = (): void => {
    const cfg = getCfg();
    verbose.checked = cfg.verbose;
    maxBody.value = String(cfg.maxBodyBytes);
    cts.value = cfg.contentTypeAllow.join("\n");
  };

  const btn = sdk.ui.button({ variant: "primary", label: "Save settings", leadingIcon: "fas fa-floppy-disk" });
  btn.addEventListener("click", () => {
    const n = parseInt(maxBody.value, 10);
    const patch: Partial<ReflectorConfig> = {
      verbose: verbose.checked,
      contentTypeAllow: cts.value.split(/[\n,]/).map((s) => s.trim()).filter((s) => s.length > 0),
    };
    if (Number.isFinite(n) && n > 0) patch.maxBodyBytes = n;
    void save(patch).then(() => {
      render();
      sdk.window.showToast("Settings saved", { variant: "success" });
    });
  });
  btnHost.appendChild(btn);

  const body = el("div");
  body.append(
    verboseWrap,
    label("Max response body (bytes)"),
    maxBody,
    el("div", { height: "0.75rem" }),
    label("Analysed Content-Type allow-list (one per line)"),
    cts,
    btnHost,
  );
  render();
  return { card: sdk.ui.card({ header: el("h2", { margin: "0" }, "Settings"), body }), render };
}

// ---- Scan-cache section ---------------------------------------------------

function buildCache(sdk: FrontendSDK): { card: HTMLElement; refresh: () => void } {
  const count = el("p", { margin: "0", fontWeight: "600" }, "Cached pages: …");
  const btnHost = el("div", { marginTop: "0.75rem", display: "flex", gap: "0.5rem" });

  const refresh = (): void => {
    void sdk.backend.getCacheSize().then((n) => {
      count.textContent = `Cached pages: ${n}`;
    });
  };

  const clearBtn = sdk.ui.button({ variant: "secondary", label: "Clear cache", leadingIcon: "fas fa-trash-can" });
  clearBtn.addEventListener("click", () => {
    void sdk.backend.clearCache().then((n) => {
      count.textContent = `Cached pages: ${n}`;
      sdk.window.showToast("Scan cache cleared", { variant: "info" });
    });
  });

  const refreshBtn = sdk.ui.button({ variant: "tertiary", label: "Refresh", leadingIcon: "fas fa-rotate" });
  refreshBtn.addEventListener("click", refresh);

  btnHost.append(clearBtn, refreshBtn);
  const body = el("div");
  const hint = el("p", { margin: "0.25rem 0 0 0", opacity: "0.7", fontSize: "0.85rem" }, "A page is scanned once per (method, host, path, param-names). Clear to force a re-scan.");
  body.append(count, hint, btnHost);
  return { card: sdk.ui.card({ header: el("h2", { margin: "0" }, "Scan cache"), body }), refresh };
}

// ---- Findings table -------------------------------------------------------

const STATE_COLORS: Record<string, string> = {
  CONFIRMED: "var(--c-danger, #f85149)",
  ATTEMPT: "var(--c-warning, #d29922)",
  REFLECTED: "var(--c-fg-secondary, #888)",
};

function buildFindings(sdk: FrontendSDK): HTMLElement {
  const filter = el("select", { marginBottom: "0.5rem" }) as HTMLSelectElement;
  for (const opt of ["All", "CONFIRMED", "ATTEMPT", "REFLECTED"]) {
    const o = el("option", undefined, opt) as HTMLOptionElement;
    o.value = opt;
    // Options are drawn by the OS popup, which ignores inherited colour, so set both directly.
    o.style.background = "var(--c-bg-subtle, #161b22)";
    o.style.color = "var(--c-fg-default, #e6edf3)";
    filter.appendChild(o);
  }
  // The select itself had only a margin, so the collapsed value was near-white on the UA white field.
  styleControl(filter);
  const counter = el("span", { marginLeft: "0.75rem", opacity: "0.7", fontSize: "0.85rem" });

  const table = el("table", { width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" });
  const clearBtn = sdk.ui.button({ variant: "tertiary", label: "Clear", leadingIcon: "fas fa-eraser" });
  clearBtn.addEventListener("click", () => {
    state.findings.length = 0;
    render();
  });

  const cell = (text: string, style?: Partial<CSSStyleDeclaration>): HTMLElement => {
    const td = el("td", { padding: "0.25rem 0.5rem", borderBottom: "1px solid var(--c-border, #333)", verticalAlign: "top", ...style });
    td.textContent = text;
    return td;
  };

  const render = (): void => {
    const f = filter.value;
    const rows = state.findings.filter((r) => f === "All" || r.state === f);
    counter.textContent = `${rows.length} shown / ${state.findings.length} total`;

    table.replaceChildren();
    const head = el("tr");
    for (const h of ["State", "Param", "Context", "URL", "PoC"]) {
      const th = el("th", { textAlign: "left", padding: "0.25rem 0.5rem", borderBottom: "2px solid var(--c-border, #444)", position: "sticky", top: "0" });
      th.textContent = h;
      head.appendChild(th);
    }
    table.appendChild(head);

    for (const r of rows) {
      const tr = el("tr");
      tr.append(
        cell(r.state, { color: STATE_COLORS[r.state] ?? "inherit", fontWeight: "600", whiteSpace: "nowrap" }),
        cell(`${r.param} (${r.source})`, { whiteSpace: "nowrap" }),
        cell(r.context, { whiteSpace: "nowrap", fontFamily: "monospace" }),
        cell(r.url, { wordBreak: "break-all" }),
      );

      const pocTd = el("td", { padding: "0.25rem 0.5rem", borderBottom: "1px solid var(--c-border, #333)", verticalAlign: "top" });
      if (r.poc) {
        const code = el("code", { wordBreak: "break-all" }, r.poc);
        const copy = sdk.ui.button({ variant: "tertiary", label: "Copy", size: "small", leadingIcon: "fas fa-copy" });
        copy.style.marginLeft = "0.5rem";
        copy.addEventListener("click", () => {
          void navigator.clipboard.writeText(r.poc).then(
            () => sdk.window.showToast("PoC copied", { variant: "success" }),
            () => sdk.window.showToast("Copy failed", { variant: "error" }),
          );
        });
        pocTd.append(code, copy);
      } else {
        pocTd.textContent = "—";
      }
      tr.appendChild(pocTd);
      table.appendChild(tr);
    }
  };

  filter.addEventListener("change", render);
  onFindingsChanged = render;
  render();

  const controls = el("div", { display: "flex", alignItems: "center", marginBottom: "0.5rem" });
  const controlsRight = el("div", { marginLeft: "auto" });
  controlsRight.appendChild(clearBtn);
  controls.append(filter, counter, controlsRight);

  const scroll = el("div", { maxHeight: "22rem", overflow: "auto", border: "1px solid var(--c-border, #333)", borderRadius: "4px" });
  scroll.appendChild(table);

  const body = el("div");
  body.append(controls, scroll);
  return sdk.ui.card({ header: el("h2", { margin: "0" }, "Live findings"), body });
}

// ---- Log feed -------------------------------------------------------------

function buildLog(sdk: FrontendSDK): HTMLElement {
  const pre = el("pre", {
    margin: "0",
    maxHeight: "16rem",
    overflow: "auto",
    fontSize: "0.78rem",
    fontFamily: "monospace",
    whiteSpace: "pre-wrap",
    wordBreak: "break-all",
    border: "1px solid var(--c-border, #333)",
    borderRadius: "4px",
    padding: "0.5rem",
  });

  const render = (): void => {
    pre.textContent = state.logs.join("\n");
    pre.scrollTop = pre.scrollHeight;
  };

  const clearBtn = sdk.ui.button({ variant: "tertiary", label: "Clear", leadingIcon: "fas fa-eraser" });
  clearBtn.addEventListener("click", () => {
    state.logs.length = 0;
    render();
  });

  onLogsChanged = render;
  render();

  const controls = el("div", { display: "flex", marginBottom: "0.5rem" });
  const right = el("div", { marginLeft: "auto" });
  right.appendChild(clearBtn);
  controls.append(el("span", { opacity: "0.7", fontSize: "0.85rem" }, "Live scanner log (mirrors console)."), right);

  const body = el("div");
  body.append(controls, pre);
  return sdk.ui.card({ header: el("h2", { margin: "0" }, "Log feed"), body });
}

// ---- Page assembly --------------------------------------------------------

const mountPage = (sdk: FrontendSDK): void => {
  const root = el("div", { padding: "1.5rem", minHeight: "100%", boxSizing: "border-box", overflowY: "auto" });

  const title = el("h1", { margin: "0 0 0.25rem 0" }, "Reflector");
  const subtitle = el("p", { margin: "0 0 1rem 0", opacity: "0.7", fontSize: "0.85rem" }, "Passive parameter-reflection detection with aggressive canary probing.");

  let cfg: ReflectorConfig = { enabled: true, verbose: true, maxBodyBytes: 2 * 1024 * 1024, contentTypeAllow: [] };
  const getCfg = (): ReflectorConfig => cfg;

  const setEnabled = async (v: boolean): Promise<void> => {
    cfg.enabled = await sdk.backend.setEnabled(v);
    sdk.window.showToast(cfg.enabled ? "Reflector enabled" : "Reflector disabled", {
      variant: cfg.enabled ? "success" : "info",
    });
  };

  const save = async (patch: Partial<ReflectorConfig>): Promise<void> => {
    cfg = await sdk.backend.setConfig(patch);
  };

  const toggle = buildToggle(sdk, getCfg, setEnabled);
  const config = buildConfig(sdk, getCfg, save);
  const cache = buildCache(sdk);
  const findings = buildFindings(sdk);
  const logCard = buildLog(sdk);

  const gap = (): HTMLElement => el("div", { height: "1rem" });
  root.append(title, subtitle, toggle.card, gap(), config.card, gap(), cache.card, gap(), findings, gap(), logCard);

  const refreshAll = (): void => {
    void sdk.backend.getConfig().then((c) => {
      cfg = c;
      toggle.render();
      config.render();
    });
    cache.refresh();
  };

  sdk.navigation.addPage(PATH, {
    body: root,
    onEnter: refreshAll,
  });

  refreshAll();
};

export const init = (sdk: FrontendSDK): void => {
  sdk.backend.onEvent("reflector:finding", (row) => {
    state.findings.unshift(row);
    if (state.findings.length > MAX_FINDINGS) state.findings.length = MAX_FINDINGS;
    onFindingsChanged?.();
  });
  sdk.backend.onEvent("reflector:log", (line) => {
    state.logs.push(line);
    if (state.logs.length > MAX_LOGS) state.logs.splice(0, state.logs.length - MAX_LOGS);
    onLogsChanged?.();
  });

  mountPage(sdk);

  sdk.sidebar.registerItem("Reflector", PATH, { icon: "fas fa-magnifying-glass" });

  sdk.commands.register(Commands.enable, {
    name: "Reflector — enable",
    group: "Reflector",
    run: async () => {
      await sdk.backend.setEnabled(true);
      sdk.window.showToast("Reflector enabled", { variant: "success" });
    },
  });
  sdk.commands.register(Commands.disable, {
    name: "Reflector — disable",
    group: "Reflector",
    run: async () => {
      await sdk.backend.setEnabled(false);
      sdk.window.showToast("Reflector disabled", { variant: "info" });
    },
  });

  sdk.commandPalette.register(Commands.enable);
  sdk.commandPalette.register(Commands.disable);
};
