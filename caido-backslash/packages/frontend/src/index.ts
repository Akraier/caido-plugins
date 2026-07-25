/**
 * Caido frontend plugin.
 *
 * Entry points and a results page. No detection logic: a confidence-scored differential claim is not
 * renderable as a row in a generic list, so the page shows the witness table and, just as
 * importantly, what each control arm ruled out.
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
const STORAGE_KEY = "backslash:settings";

interface Settings {
  aggressivity: "low" | "medium" | "high";
  delayMs: number;
  maxConcurrent: number;
}

const DEFAULTS: Settings = { aggressivity: "medium", delayMs: 150, maxConcurrent: 2 };

function loadSettings(sdk: App): Settings {
  try {
    const raw = (sdk.storage.get() as Record<string, unknown> | undefined)?.[STORAGE_KEY];
    if (typeof raw === "object" && raw !== null) return { ...DEFAULTS, ...(raw as Settings) };
  } catch {
    // Fall through to defaults: a corrupt setting must not stop the plugin loading.
  }
  return DEFAULTS;
}

function saveSettings(sdk: App, settings: Settings): void {
  const existing = (sdk.storage.get() as Record<string, unknown> | undefined) ?? {};
  void sdk.storage.set({ ...existing, [STORAGE_KEY]: settings });
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className !== undefined) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function confidenceBadge(confidence: string): HTMLElement {
  const badge = el("span", "c-badge", confidence.toUpperCase());
  badge.style.cssText =
    "display:inline-block;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:600;" +
    (confidence === "firm"
      ? "background:#7f1d1d;color:#fecaca;"
      : confidence === "probable"
        ? "background:#78350f;color:#fde68a;"
        : "background:#374151;color:#d1d5db;");
  return badge;
}

function renderFinding(finding: ScanFinding): HTMLElement {
  const card = el("div");
  card.style.cssText =
    "border:1px solid #374151;border-radius:4px;padding:10px;margin-bottom:10px;font-family:monospace;font-size:12px;";

  const head = el("div");
  head.style.cssText = "display:flex;gap:8px;align-items:center;margin-bottom:6px;";
  head.append(confidenceBadge(finding.confidence));
  head.append(el("strong", undefined, finding.probeName));
  head.append(el("span", undefined, `${finding.surface} ${finding.slotName}`));
  card.append(head);

  const payloads = el("div");
  payloads.style.cssText = "margin-bottom:6px;opacity:0.9;";
  payloads.append(el("div", undefined, `break   ${JSON.stringify(finding.breakPayload)}`));
  payloads.append(el("div", undefined, `escape  ${JSON.stringify(finding.escapePayload)}`));
  card.append(payloads);

  card.append(el("div", undefined, "witnesses"));
  for (const w of finding.witnesses) {
    card.append(
      el("div", undefined, `  ${w.name} (${w.featureClass}): ${w.breakValue} vs ${w.escapeValue}`),
    );
  }

  if (finding.attributedElsewhere.length > 0) {
    const ruled = el("div");
    ruled.style.cssText = "margin-top:6px;opacity:0.65;";
    ruled.append(el("div", undefined, "ruled out by a control arm"));
    for (const a of finding.attributedElsewhere) {
      ruled.append(el("div", undefined, `  ${a.witness}: ${a.by} — ${a.explains}`));
    }
    card.append(ruled);
  }

  if (finding.evidenceRequestId !== undefined) {
    const link = el("div", undefined, `evidence request #${finding.evidenceRequestId}`);
    link.style.cssText = "margin-top:6px;opacity:0.7;";
    card.append(link);
  }

  return card;
}

export function init(sdk: App): void {
  let settings = loadSettings(sdk);

  const body = el("div");
  body.style.cssText = "padding:14px;height:100%;overflow:auto;";

  const status = el("div", undefined, "No scan started. Right-click a request in HTTP History.");
  status.style.cssText = "margin-bottom:12px;font-family:monospace;font-size:12px;opacity:0.85;";
  body.append(status);

  const controls = el("div");
  controls.style.cssText = "margin-bottom:12px;display:flex;gap:10px;align-items:center;font-size:12px;";

  const aggressivity = el("select");
  for (const level of ["low", "medium", "high"]) {
    const option = el("option", undefined, level);
    option.value = level;
    if (level === settings.aggressivity) option.selected = true;
    aggressivity.append(option);
  }
  aggressivity.onchange = () => {
    settings = { ...settings, aggressivity: aggressivity.value as Settings["aggressivity"] };
    saveSettings(sdk, settings);
  };

  const delay = el("input");
  delay.type = "number";
  delay.value = String(settings.delayMs);
  delay.style.width = "70px";
  delay.onchange = () => {
    settings = { ...settings, delayMs: Math.max(0, Number.parseInt(delay.value, 10) || 0) };
    saveSettings(sdk, settings);
  };

  controls.append(el("span", undefined, "aggressivity"), aggressivity);
  controls.append(el("span", undefined, "delay ms"), delay);
  body.append(controls);

  const results = el("div");
  body.append(results);

  sdk.navigation.addPage(PAGE, { body });
  sdk.sidebar.registerItem("Backslash", PAGE, { icon: "fas fa-backward-fast" });

  sdk.backend.onEvent(EVENT_PROGRESS, (progress: ScanProgress) => {
    status.textContent =
      `${progress.scanId}  ${progress.phase}  ` +
      `probes ${progress.probesDone}/${progress.probesTotal}  ` +
      `sends ${progress.sends}  findings ${progress.findings}`;
  });

  sdk.backend.onEvent(EVENT_FINDING, (finding: ScanFinding) => {
    results.prepend(renderFinding(finding));
  });

  sdk.backend.onEvent(EVENT_DONE, (result: ScanResult) => {
    const halted = result.haltReason === undefined ? "" : `  HALTED (${result.haltReason})`;
    status.textContent =
      `${result.scanId} finished  sends ${result.sends}  findings ${result.findings.length}${halted}`;

    // Surfaces that exist on the request but were not probed are stated, never silently dropped.
    if (result.deferredSurfaces.length > 0) {
      const deferred = el("div");
      deferred.style.cssText =
        "margin:10px 0;font-family:monospace;font-size:11px;opacity:0.7;";
      deferred.append(el("div", undefined, "surfaces not probed:"));
      for (const item of result.deferredSurfaces) {
        deferred.append(el("div", undefined, `  ${item.kind}: ${item.reason}`));
      }
      results.append(deferred);
    }
    if (result.findings.length === 0) {
      const inconclusive = result.diagnostics.filter((d) => d.kind !== "boring");
      const summary = el(
        "div",
        undefined,
        inconclusive.length === 0
          ? "No anomalies. Every probe was measured and found nothing."
          : `No findings, but ${inconclusive.length} probe(s) could not be measured cleanly — see the backend log. A blinded measurement is not a clean result.`,
      );
      summary.style.cssText = "font-family:monospace;font-size:12px;opacity:0.8;";
      results.append(summary);
    }
  });

  const start = async (requestId: string): Promise<void> => {
    results.replaceChildren();
    status.textContent = "starting...";
    const input: ScanRequestInput = {
      requestId,
      aggressivity: settings.aggressivity,
      delayMs: settings.delayMs,
      maxConcurrent: settings.maxConcurrent,
    };
    const result = await sdk.backend.startScan(input);
    if (result.kind === "error") {
      status.textContent = `error: ${result.error}`;
      return;
    }
    void sdk.navigation.goTo(PAGE);
  };

  sdk.commands.register("backslash.scan", {
    name: "Backslash: scan this request",
    run: (context) => {
      if (context.type === "RequestRowContext" && context.requests.length > 0) {
        void start(context.requests[0]!.id);
        return;
      }
      if (context.type === "RequestContext" && context.request.type === "RequestFull") {
        // A draft request has no id and is not in history, so there is nothing to scan yet.
        void start(context.request.id);
      }
    },
  });

  sdk.menu.registerItem({ type: "RequestRow", commandId: "backslash.scan" });
  sdk.menu.registerItem({ type: "Request", commandId: "backslash.scan" });
}
