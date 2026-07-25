/**
 * Caido frontend plugin.
 *
 * Two things this file is careful about, both learned from bugs:
 *
 * 1. **One pane per scan, events routed by scanId.** An earlier version kept a single results
 *    container and called `replaceChildren()` when a scan started, so a second scan wiped the first
 *    and their event streams interleaved into the same DOM. Concurrent scans are legitimate, so the
 *    fix is a tab per scan and a strict `scanId` lookup: an event for an unknown scan is dropped
 *    rather than sprayed into whichever tab happens to be visible.
 *
 * 2. **Nothing is sent until the operator presses Start.** Previously the context menu fired a scan
 *    immediately using whatever settings were persisted from last time, which is the wrong default
 *    for a tool that sends hundreds of requests at a third-party target. Selecting a request now
 *    opens a pending tab showing what will be scanned, with the settings editable, and the traffic
 *    begins only on an explicit click.
 */

import type { Caido } from "@caido/sdk-frontend";

import type {
  BackslashApi,
  BackslashEvents,
  ScanFinding,
  ScanProgress,
  ScanRequestInput,
  ScanResult,
} from "../../shared/src/api.ts";
import { EVENT_DONE, EVENT_FINDING, EVENT_PROGRESS } from "../../shared/src/api.ts";

type App = Caido<BackslashApi, BackslashEvents>;

const PAGE = "/backslash";
const STORAGE_KEY = "backslash:defaults";

interface Settings {
  aggressivity: "low" | "medium" | "high";
  delayMs: number;
  maxConcurrent: number;
  slotFilter: string;
}

const DEFAULTS: Settings = {
  aggressivity: "medium",
  delayMs: 150,
  maxConcurrent: 2,
  slotFilter: "",
};

interface Target {
  readonly requestId: string;
  readonly host: string;
  readonly port: number;
  readonly path: string;
  readonly query: string;
  readonly isTls: boolean;
}

type TabState = "pending" | "running" | "finished" | "halted" | "error";

interface ScanTab {
  readonly key: string;
  scanId?: string;
  state: TabState;
  readonly target: Target;
  settings: Settings;
  readonly tabButton: HTMLButtonElement;
  readonly pane: HTMLDivElement;
  readonly statusLine: HTMLDivElement;
  readonly findingsBox: HTMLDivElement;
  findingCount: number;
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  text?: string,
  css?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (css !== undefined) node.style.cssText = css;
  return node;
}

const MONO = "font-family:monospace;font-size:12px;";

function loadDefaults(sdk: App): Settings {
  try {
    const stored = (sdk.storage.get() as Record<string, unknown> | undefined)?.[STORAGE_KEY];
    if (typeof stored === "object" && stored !== null) {
      return { ...DEFAULTS, ...(stored as Partial<Settings>) };
    }
  } catch {
    // A corrupt stored setting must never stop the plugin loading.
  }
  return DEFAULTS;
}

function saveDefaults(sdk: App, settings: Settings): void {
  const existing = (sdk.storage.get() as Record<string, unknown> | undefined) ?? {};
  void sdk.storage.set({ ...existing, [STORAGE_KEY]: settings });
}

function confidenceBadge(confidence: string): HTMLElement {
  const palette: Record<string, string> = {
    firm: "background:#7f1d1d;color:#fecaca;",
    probable: "background:#78350f;color:#fde68a;",
    tentative: "background:#374151;color:#d1d5db;",
  };
  return el(
    "span",
    confidence.toUpperCase(),
    "display:inline-block;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:600;" +
      (palette[confidence] ?? palette["tentative"]!),
  );
}

function renderFinding(finding: ScanFinding): HTMLElement {
  const card = el(
    "div",
    undefined,
    `border:1px solid #374151;border-radius:4px;padding:10px;margin-bottom:10px;${MONO}`,
  );

  const head = el("div", undefined, "display:flex;gap:8px;align-items:center;margin-bottom:6px;");
  head.append(confidenceBadge(finding.confidence));
  head.append(el("strong", finding.probeName));
  head.append(el("span", `${finding.surface} ${finding.slotName}`, "opacity:0.8;"));
  card.append(head);

  const payloads = el("div", undefined, "margin-bottom:6px;opacity:0.9;");
  payloads.append(el("div", `break   ${JSON.stringify(finding.breakPayload)}`));
  payloads.append(el("div", `escape  ${JSON.stringify(finding.escapePayload)}`));
  card.append(payloads);

  card.append(el("div", "witnesses"));
  for (const w of finding.witnesses) {
    card.append(el("div", `  ${w.name} (${w.featureClass}): ${w.breakValue} vs ${w.escapeValue}`));
  }

  if (finding.attributedElsewhere.length > 0) {
    const ruled = el("div", undefined, "margin-top:6px;opacity:0.65;");
    ruled.append(el("div", "ruled out by a control arm"));
    for (const a of finding.attributedElsewhere) {
      ruled.append(el("div", `  ${a.witness}: ${a.by} — ${a.explains}`));
    }
    card.append(ruled);
  }

  if (finding.evidenceRequestId !== undefined) {
    card.append(
      el("div", `evidence request #${finding.evidenceRequestId}`, "margin-top:6px;opacity:0.7;"),
    );
  }

  return card;
}

export function init(sdk: App): void {
  let defaults = loadDefaults(sdk);
  let tabCounter = 0;

  const tabs: ScanTab[] = [];
  /** Live scans by their backend id. Events are routed strictly through this. */
  const byScanId = new Map<string, ScanTab>();
  let activeTab: ScanTab | undefined;

  const body = el("div", undefined, "padding:14px;height:100%;display:flex;flex-direction:column;");
  const tabBar = el(
    "div",
    undefined,
    "display:flex;gap:4px;flex-wrap:wrap;margin-bottom:10px;border-bottom:1px solid #374151;padding-bottom:8px;",
  );
  const paneHost = el("div", undefined, "flex:1;overflow:auto;");
  const emptyState = el(
    "div",
    "No scans. Right-click a request in HTTP History and choose Backslash.",
    `${MONO}opacity:0.75;`,
  );
  paneHost.append(emptyState);
  body.append(tabBar, paneHost);

  function select(tab: ScanTab): void {
    activeTab = tab;
    for (const other of tabs) {
      other.pane.style.display = other === tab ? "block" : "none";
      other.tabButton.style.background = other === tab ? "#1f2937" : "transparent";
      other.tabButton.style.fontWeight = other === tab ? "600" : "400";
    }
  }

  function tabLabel(tab: ScanTab): string {
    const marker =
      tab.state === "pending"
        ? "draft"
        : tab.state === "running"
          ? "running"
          : tab.state === "halted"
            ? "halted"
            : tab.state === "error"
              ? "error"
              : `${tab.findingCount} found`;
    return `${tab.target.path.slice(0, 24)} [${marker}]`;
  }

  function refreshTabButton(tab: ScanTab): void {
    tab.tabButton.textContent = tabLabel(tab);
  }

  function closeTab(tab: ScanTab): void {
    if (tab.state === "running" && tab.scanId !== undefined) {
      // Do not orphan a running scan: stopping the traffic matters more than tidying the UI.
      void sdk.backend.cancelScan(tab.scanId);
    }
    const index = tabs.indexOf(tab);
    if (index !== -1) tabs.splice(index, 1);
    if (tab.scanId !== undefined) byScanId.delete(tab.scanId);
    tab.tabButton.remove();
    tab.pane.remove();
    if (tabs.length === 0) {
      activeTab = undefined;
      paneHost.append(emptyState);
    } else if (activeTab === tab) {
      select(tabs[Math.max(0, index - 1)]!);
    }
  }

  /** The settings form shown on a pending tab. Nothing is sent while this is on screen. */
  function buildLaunchForm(tab: ScanTab): HTMLElement {
    const form = el("div", undefined, `${MONO}`);

    const summary = el(
      "div",
      undefined,
      "border:1px solid #374151;border-radius:4px;padding:10px;margin-bottom:12px;",
    );
    summary.append(el("div", "target", "opacity:0.7;margin-bottom:4px;"));
    summary.append(
      el(
        "div",
        `${tab.target.isTls ? "https" : "http"}://${tab.target.host}:${tab.target.port}${tab.target.path}` +
          (tab.target.query === "" ? "" : `?${tab.target.query}`),
      ),
    );
    summary.append(el("div", `request #${tab.target.requestId}`, "opacity:0.7;margin-top:4px;"));
    form.append(summary);

    const row = (label: string, control: HTMLElement, hint?: string): HTMLElement => {
      const wrapper = el("div", undefined, "margin-bottom:10px;");
      const line = el("div", undefined, "display:flex;gap:8px;align-items:center;");
      line.append(el("label", label, "width:120px;opacity:0.85;"));
      line.append(control);
      wrapper.append(line);
      if (hint !== undefined) {
        wrapper.append(el("div", hint, "opacity:0.6;font-size:11px;margin:2px 0 0 128px;"));
      }
      return wrapper;
    };

    const aggressivity = el("select");
    for (const level of ["low", "medium", "high"] as const) {
      const option = el("option", level);
      option.value = level;
      if (level === tab.settings.aggressivity) option.selected = true;
      aggressivity.append(option);
    }
    aggressivity.onchange = () => {
      tab.settings = {
        ...tab.settings,
        aggressivity: aggressivity.value as Settings["aggressivity"],
      };
    };

    const delay = el("input");
    delay.type = "number";
    delay.min = "0";
    delay.value = String(tab.settings.delayMs);
    delay.style.width = "80px";
    delay.onchange = () => {
      tab.settings = {
        ...tab.settings,
        delayMs: Math.max(0, Number.parseInt(delay.value, 10) || 0),
      };
    };

    const concurrency = el("input");
    concurrency.type = "number";
    concurrency.min = "1";
    concurrency.value = String(tab.settings.maxConcurrent);
    concurrency.style.width = "80px";
    concurrency.onchange = () => {
      tab.settings = {
        ...tab.settings,
        maxConcurrent: Math.max(1, Number.parseInt(concurrency.value, 10) || 1),
      };
    };

    const slot = el("input");
    slot.type = "text";
    slot.placeholder = "all parameters";
    slot.value = tab.settings.slotFilter;
    slot.style.width = "180px";
    slot.onchange = () => {
      tab.settings = { ...tab.settings, slotFilter: slot.value.trim() };
    };

    form.append(
      row("aggressivity", aggressivity, "probe and parameter budget: low 4, medium 12, high all 24"),
    );
    form.append(row("delay ms", delay, "minimum gap between requests"));
    form.append(row("concurrency", concurrency, "requests in flight at once"));
    form.append(row("parameter", slot, "leave empty to scan every enumerated surface"));

    // Two concurrent scans have independent throttles, so the combined rate against one host is the
    // sum. Worth saying out loud before the operator doubles their own request rate by accident.
    const sameHostRunning = tabs.some(
      (other) =>
        other !== tab && other.state === "running" && other.target.host === tab.target.host,
    );
    if (sameHostRunning) {
      form.append(
        el(
          "div",
          `A scan is already running against ${tab.target.host}. Each scan throttles independently, ` +
            "so the combined request rate will be the sum of both.",
          "border:1px solid #78350f;background:#1c1917;color:#fde68a;border-radius:4px;padding:8px;margin-bottom:10px;font-size:11px;",
        ),
      );
    }

    const actions = el("div", undefined, "display:flex;gap:8px;align-items:center;");
    const startButton = el("button", "Start scan");
    startButton.style.cssText =
      "padding:5px 14px;border-radius:4px;border:1px solid #4b5563;background:#1f2937;cursor:pointer;font-weight:600;";
    const rememberButton = el("button", "Save as defaults");
    rememberButton.style.cssText =
      "padding:5px 10px;border-radius:4px;border:1px solid #374151;background:transparent;cursor:pointer;";
    rememberButton.onclick = () => {
      defaults = { ...tab.settings };
      saveDefaults(sdk, defaults);
      rememberButton.textContent = "saved";
      setTimeout(() => (rememberButton.textContent = "Save as defaults"), 1200);
    };

    startButton.onclick = () => {
      startButton.disabled = true;
      startButton.textContent = "starting...";
      void launch(tab, form);
    };

    actions.append(startButton, rememberButton);
    form.append(actions);
    return form;
  }

  async function launch(tab: ScanTab, form: HTMLElement): Promise<void> {
    const input: ScanRequestInput = {
      requestId: tab.target.requestId,
      aggressivity: tab.settings.aggressivity,
      delayMs: tab.settings.delayMs,
      maxConcurrent: tab.settings.maxConcurrent,
      ...(tab.settings.slotFilter === "" ? {} : { slotFilter: tab.settings.slotFilter }),
    };

    const response = await sdk.backend.startScan(input);
    if (response.kind === "error") {
      tab.state = "error";
      refreshTabButton(tab);
      tab.statusLine.textContent = `error: ${response.error}`;
      tab.statusLine.style.display = "block";
      return;
    }

    tab.scanId = response.value.scanId;
    tab.state = "running";
    byScanId.set(tab.scanId, tab);
    refreshTabButton(tab);

    form.remove();
    tab.statusLine.style.display = "block";
    tab.statusLine.textContent = `${tab.scanId} starting`;
    tab.findingsBox.style.display = "block";
  }

  function createTab(target: Target): ScanTab {
    tabCounter += 1;
    emptyState.remove();

    const tabButton = el("button");
    tabButton.style.cssText =
      "padding:4px 10px;border-radius:4px 4px 0 0;border:1px solid #374151;border-bottom:none;background:transparent;cursor:pointer;font-size:12px;";

    const closeButton = el("span", " x", "margin-left:6px;opacity:0.6;");

    const pane = el("div", undefined, "display:none;");
    const statusLine = el("div", undefined, `${MONO}margin-bottom:10px;opacity:0.85;display:none;`);
    const findingsBox = el("div", undefined, "display:none;");
    pane.append(statusLine, findingsBox);

    const tab: ScanTab = {
      key: `tab-${tabCounter}`,
      state: "pending",
      target,
      settings: { ...defaults },
      tabButton,
      pane,
      statusLine,
      findingsBox,
      findingCount: 0,
    };

    tabButton.onclick = () => select(tab);
    closeButton.onclick = (event) => {
      event.stopPropagation();
      closeTab(tab);
    };
    tabButton.textContent = tabLabel(tab);
    tabButton.append(closeButton);

    pane.prepend(buildLaunchForm(tab));

    tabs.push(tab);
    tabBar.append(tabButton);
    paneHost.append(pane);
    select(tab);
    return tab;
  }

  sdk.navigation.addPage(PAGE, { body });
  sdk.sidebar.registerItem("Backslash", PAGE, { icon: "fas fa-backward-fast" });

  // Every handler resolves the tab through byScanId. An event for a scan this page does not know
  // about is dropped, which is what stops concurrent scans bleeding into each other.
  sdk.backend.onEvent(EVENT_PROGRESS, (progress: ScanProgress) => {
    const tab = byScanId.get(progress.scanId);
    if (tab === undefined) return;
    tab.statusLine.textContent =
      `${progress.scanId}  ${progress.phase}  ` +
      `probes ${progress.probesDone}/${progress.probesTotal}  ` +
      `sends ${progress.sends}  findings ${progress.findings}`;
  });

  sdk.backend.onEvent(EVENT_FINDING, (finding: ScanFinding) => {
    const tab = byScanId.get(finding.scanId);
    if (tab === undefined) return;
    tab.findingCount += 1;
    refreshTabButton(tab);
    tab.findingsBox.prepend(renderFinding(finding));
  });

  sdk.backend.onEvent(EVENT_DONE, (result: ScanResult) => {
    const tab = byScanId.get(result.scanId);
    if (tab === undefined) return;
    tab.state = result.haltReason === undefined ? "finished" : "halted";
    refreshTabButton(tab);

    const halted = result.haltReason === undefined ? "" : `  HALTED (${result.haltReason})`;
    tab.statusLine.textContent =
      `${result.scanId} finished  sends ${result.sends}  findings ${result.findings.length}${halted}`;

    if (result.deferredSurfaces.length > 0) {
      const deferred = el("div", undefined, `margin:10px 0;${MONO}font-size:11px;opacity:0.7;`);
      deferred.append(el("div", "surfaces not probed:"));
      for (const item of result.deferredSurfaces) {
        deferred.append(el("div", `  ${item.kind}: ${item.reason}`));
      }
      tab.findingsBox.append(deferred);
    }

    if (result.findings.length === 0) {
      const unmeasured = result.diagnostics.filter((d) => d.kind !== "boring");
      tab.findingsBox.append(
        el(
          "div",
          unmeasured.length === 0
            ? "No anomalies. Every probe was measured and found nothing."
            : `No findings, but ${unmeasured.length} probe(s) could not be measured cleanly. A blinded measurement is not a clean result — see the backend log.`,
          `${MONO}opacity:0.8;`,
        ),
      );
    }
  });

  const stage = (target: Target): void => {
    createTab(target);
    void sdk.navigation.goTo(PAGE);
  };

  sdk.commands.register("backslash.scan", {
    name: "Backslash: scan this request",
    run: (context) => {
      if (context.type === "RequestRowContext") {
        // Multi-select gets one tab each: they are independent scans, not one merged run.
        for (const request of context.requests) {
          stage({
            requestId: request.id,
            host: request.host,
            port: request.port,
            path: request.path,
            query: request.query,
            isTls: request.isTls,
          });
        }
        return;
      }
      if (context.type === "RequestContext" && context.request.type === "RequestFull") {
        // A draft request has no id and is not in the database, so there is nothing to scan yet.
        const request = context.request;
        stage({
          requestId: request.id,
          host: request.host,
          port: request.port,
          path: request.path,
          query: request.query,
          isTls: request.isTls,
        });
      }
    },
  });

  sdk.menu.registerItem({ type: "RequestRow", commandId: "backslash.scan" });
  sdk.menu.registerItem({ type: "Request", commandId: "backslash.scan" });
}
