import type { ConfirmMode, DedupeMode, RuntimeConfig } from "@cache-profiler/backend";

import type { FrontendSDK } from "./types";

const PAGE_PATH = "/cache-profiler";

// A stored config is just the RuntimeConfig shape persisted in frontend storage. It takes
// precedence over the env-seeded backend config and is re-applied to the backend on load.
function readStored(sdk: FrontendSDK): Partial<RuntimeConfig> | undefined {
  const raw = sdk.storage.get();
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  return raw as Partial<RuntimeConfig>;
}

function row(label: string, control: HTMLElement): HTMLElement {
  const wrap = document.createElement("div");
  wrap.style.display = "flex";
  wrap.style.alignItems = "center";
  wrap.style.gap = "12px";
  wrap.style.margin = "8px 0";
  const l = document.createElement("label");
  l.textContent = label;
  l.style.width = "180px";
  l.style.fontWeight = "600";
  wrap.append(l, control);
  return wrap;
}

// Explicit control colors — native select/option otherwise render with the browser default
// white background while inheriting Caido's light text, giving unreadable white-on-white.
const CTRL_BG = "#1e1e2a";
const CTRL_FG = "#e6e6e6";
const CTRL_BORDER = "1px solid #4a4a5a";

function styleControl(el: HTMLElement): void {
  el.style.padding = "4px 8px";
  el.style.background = CTRL_BG;
  el.style.color = CTRL_FG;
  el.style.border = CTRL_BORDER;
  el.style.borderRadius = "4px";
  el.style.colorScheme = "dark"; // render the native dropdown chrome dark too
}

function select(options: string[], value: string): HTMLSelectElement {
  const s = document.createElement("select");
  for (const o of options) {
    const opt = document.createElement("option");
    opt.value = o;
    opt.textContent = o;
    opt.style.background = CTRL_BG;
    opt.style.color = CTRL_FG;
    if (o === value) opt.selected = true;
    s.append(opt);
  }
  styleControl(s);
  return s;
}

function input(type: string, value: string): HTMLInputElement {
  const i = document.createElement("input");
  i.type = type;
  i.value = value;
  styleControl(i);
  i.style.minWidth = "260px";
  return i;
}

function button(label: string, primary = false): HTMLButtonElement {
  const b = document.createElement("button");
  b.textContent = label;
  b.style.padding = primary ? "8px 20px" : "6px 12px";
  b.style.cursor = "pointer";
  if (primary) b.style.fontWeight = "600";
  return b;
}

export function mountSettingsPage(sdk: FrontendSDK): void {
  const body = document.createElement("div");
  body.style.padding = "20px";
  body.style.maxWidth = "720px";
  body.style.fontFamily = "inherit";

  const h = document.createElement("h2");
  h.textContent = "Cache Profiler — Settings";
  body.append(h);

  // ---- live status -----------------------------------------------------
  const status = document.createElement("div");
  status.style.margin = "12px 0 20px";
  status.style.padding = "10px 12px";
  status.style.borderRadius = "6px";
  status.style.background = "rgba(127,127,127,0.12)";
  status.style.fontFamily = "monospace";
  status.style.whiteSpace = "pre-wrap";
  status.textContent = "status: loading…";

  const resumeBtn = document.createElement("button");
  resumeBtn.textContent = "Resume (clear throttle halt)";
  resumeBtn.style.margin = "0 0 16px";
  resumeBtn.style.padding = "6px 12px";
  resumeBtn.style.cursor = "pointer";
  resumeBtn.addEventListener("click", () => {
    void sdk.backend.resumeConfirm().then(() => {
      sdk.window.showToast("Confirmation resumed", { variant: "info" });
      void refreshStatus();
    });
  });

  // ---- form controls ---------------------------------------------------
  const confirmSel = select(["auto", "on", "off"], "auto");
  const scopeInp = input("text", "");
  scopeInp.placeholder = "example.com, api.example.com";
  const rateInp = input("number", "30");
  const maxInp = input("number", "200");
  const dedupeSel = select(["smart", "host", "path"], "smart");

  const help = document.createElement("div");
  help.style.fontSize = "12px";
  help.style.opacity = "0.7";
  help.style.margin = "4px 0 16px";
  help.innerHTML =
    "<b>confirm</b>: auto = run the probe machine when a scope is set; on/off force it.<br>" +
    "<b>scope</b>: comma-separated domains; also limits which hosts are processed passively.<br>" +
    "<b>rate</b>: resources probed per minute (each ≤ 2 requests). <b>max</b>: session probe ceiling.<br>" +
    "<b>dedupe</b>: smart = static collapses per host, dynamic per path.";

  const saveBtn = button("Save", true);

  // ---- OOB (interactsh) controls ---------------------------------------
  const oobServerInp = input("text", "");
  oobServerInp.placeholder = "https://oast.example.com (interactsh server URL)";
  const oobTokenInp = input("password", "");
  oobTokenInp.placeholder = "optional auth token (self-hosted)";
  const oobPollInp = input("number", "5000");
  const oobWindowInp = input("number", "10");

  const oobStatus = document.createElement("div");
  oobStatus.style.margin = "8px 0";
  oobStatus.style.padding = "10px 12px";
  oobStatus.style.borderRadius = "6px";
  oobStatus.style.background = "rgba(127,127,127,0.12)";
  oobStatus.style.fontFamily = "monospace";
  oobStatus.style.whiteSpace = "pre-wrap";
  oobStatus.textContent = "oob: loading…";

  const enableOobBtn = button("Enable OOB client");
  const disableOobBtn = button("Disable");
  const extendOobBtn = button("Extend window");
  const oobBtns = document.createElement("div");
  oobBtns.style.display = "flex";
  oobBtns.style.gap = "10px";
  oobBtns.style.margin = "8px 0 16px";
  oobBtns.append(enableOobBtn, disableOobBtn, extendOobBtn);

  const oobHeader = document.createElement("h3");
  oobHeader.textContent = "OOB — interactsh (SSRF / blind channel)";
  oobHeader.style.margin = "24px 0 4px";
  const oobHelp = document.createElement("div");
  oobHelp.style.fontSize = "12px";
  oobHelp.style.opacity = "0.7";
  oobHelp.style.margin = "0 0 8px";
  oobHelp.innerHTML =
    "Enable to run a native interactsh client: it registers, <b>self-tests</b> the round-trip, " +
    "then auto-polls. Toggle off to inject payloads only and watch your own server. " +
    "<b>window</b>: minutes to keep correlating callbacks after a scan (Extend to prolong).";

  body.append(
    status,
    resumeBtn,
    row("Confirm mode", confirmSel),
    row("Scope (domains)", scopeInp),
    row("Rate (per min)", rateInp),
    row("Session max", maxInp),
    row("Dedupe mode", dedupeSel),
    help,
    saveBtn,
    oobHeader,
    oobHelp,
    oobStatus,
    row("interactsh URL", oobServerInp),
    row("Auth token", oobTokenInp),
    row("Poll interval (ms)", oobPollInp),
    row("Window (min)", oobWindowInp),
    oobBtns,
  );

  // ---- behaviour -------------------------------------------------------
  const fill = (c: RuntimeConfig): void => {
    confirmSel.value = c.confirm;
    scopeInp.value = c.scope.join(", ");
    rateInp.value = String(c.rate);
    maxInp.value = String(c.max);
    dedupeSel.value = c.dedupe;
    oobServerInp.value = c.oobServer;
    oobTokenInp.value = c.oobToken;
    oobPollInp.value = String(c.oobPollMs);
    oobWindowInp.value = String(c.oobWindowMin);
  };

  const collect = (): Partial<RuntimeConfig> => ({
    confirm: confirmSel.value as ConfirmMode,
    scope: scopeInp.value
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
    rate: Number(rateInp.value) || 30,
    max: Number(maxInp.value) || 200,
    dedupe: dedupeSel.value as DedupeMode,
    oobServer: oobServerInp.value.trim(),
    oobToken: oobTokenInp.value,
    oobPollMs: Number(oobPollInp.value) || 5000,
    oobWindowMin: Number(oobWindowInp.value) || 10,
  });

  const refreshStatus = async (): Promise<void> => {
    try {
      const s = await sdk.backend.getStatus();
      status.textContent =
        `mode:     ${s.mode}\n` +
        `scope:    ${s.scope.length > 0 ? s.scope.join(", ") : "(all hosts)"}\n` +
        `probed:   ${s.probed} / ${s.sessionMax}\n` +
        `queued:   ${s.queued}\n` +
        `halted:   ${s.halted ? "YES — rate-limit/bot; press Resume" : "no"}`;
      resumeBtn.style.display = s.halted ? "inline-block" : "none";
    } catch (err) {
      status.textContent = `status unavailable: ${String(err)}`;
    }
  };

  const refreshOob = async (): Promise<void> => {
    try {
      const s = await sdk.backend.getOobStatus();
      oobStatus.textContent =
        `client:       ${s.enabled ? "ENABLED" : "disabled"}\n` +
        `server:       ${s.serverHost.length > 0 ? s.serverHost : "(none)"}\n` +
        `interactions: ${s.interactions}\n` +
        `window:       ${s.enabled ? `${Math.ceil(s.windowEndsInMs / 60000)}m left` : "-"}\n` +
        `error:        ${s.lastError ?? "none"}`;
      disableOobBtn.style.display = s.enabled ? "inline-block" : "none";
      extendOobBtn.style.display = s.enabled ? "inline-block" : "none";
    } catch (err) {
      oobStatus.textContent = `oob status unavailable: ${String(err)}`;
    }
  };

  saveBtn.addEventListener("click", () => {
    const patch = collect();
    void sdk.storage.set(patch);
    void sdk.backend.setConfig(patch).then((applied) => {
      fill(applied);
      sdk.window.showToast("Cache Profiler settings saved", { variant: "success" });
      void refreshStatus();
    });
  });

  // Enable: persist the OOB config, then register + self-test. The failure reason is surfaced.
  enableOobBtn.addEventListener("click", () => {
    const patch = collect();
    patch.oobClient = true;
    void sdk.storage.set(patch);
    sdk.window.showToast("Enabling OOB client (register + self-test)…", { variant: "info" });
    void sdk.backend.setConfig(patch).then(async () => {
      const res = await sdk.backend.enableOob();
      if (res.ok) {
        sdk.window.showToast("OOB client enabled", { variant: "success" });
      } else {
        sdk.window.showToast(`OOB enable failed: ${res.error ?? "unknown"}`, {
          variant: "error",
        });
      }
      await refreshOob();
    });
  });

  disableOobBtn.addEventListener("click", () => {
    void sdk.backend.setConfig({ oobClient: false });
    void sdk.backend.disableOob().then(() => {
      sdk.window.showToast("OOB client disabled", { variant: "info" });
      void refreshOob();
    });
  });

  extendOobBtn.addEventListener("click", () => {
    void sdk.backend.extendOob().then(() => {
      sdk.window.showToast("OOB correlation window extended", { variant: "info" });
      void refreshOob();
    });
  });

  // Seed the form: stored config wins, else the backend's env-seeded config.
  void (async () => {
    try {
      const applied = await sdk.backend.getConfig();
      fill(applied);
      await refreshStatus();
      await refreshOob();
    } catch {
      /* backend not ready yet */
    }
  })();

  // ---- register page + sidebar + status polling ------------------------
  sdk.navigation.addPage(PAGE_PATH, { body });
  sdk.sidebar.registerItem("Cache Profiler", PAGE_PATH, { icon: "fas fa-database" });

  let active = false;
  let timer: ReturnType<typeof setInterval> | undefined;
  const startPolling = (): void => {
    if (timer !== undefined) return;
    timer = setInterval(() => {
      if (active) {
        void refreshStatus();
        void refreshOob();
      }
    }, 3000);
  };
  sdk.navigation.onPageChange((e) => {
    active = e.type === "Plugin" && e.path === PAGE_PATH;
    if (active) {
      void refreshStatus();
      startPolling();
    }
  });

  // On load, re-apply any stored overrides to the backend so they take effect without opening
  // the page (storage precedence over env).
  const stored = readStored(sdk);
  if (stored !== undefined) {
    void sdk.backend.setConfig(stored).then((applied) => fill(applied)).catch(() => {});
  }
}
