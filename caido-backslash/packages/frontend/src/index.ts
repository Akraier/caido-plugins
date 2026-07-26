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
 * 2. **Buttons and colours come from Caido, not from hardcoded hex.** Buttons are built with
 *    `sdk.ui.button`, which is themed by the host, and every colour that remains is a
 *    `var(--c-*)` token with a fallback. Hand-styling a `<button>` with a dark `background` and no
 *    `color` was unreadable in dark mode: the user-agent default `color: buttontext` is near-black
 *    and beats theme inheritance, so the label vanished into the background.
 *
 * 3. **Nothing is sent until the operator presses Start.** Previously the context menu fired a scan
 *    immediately using whatever settings were persisted from last time, which is the wrong default
 *    for a tool that sends hundreds of requests at a third-party target. Selecting a request now
 *    opens a pending tab showing what will be scanned, with the settings editable, and the traffic
 *    begins only on an explicit click.
 */

import type { Caido } from "@caido/sdk-frontend";

import { AGGRESSIVITY_BUDGET } from "../../shared/src/api.ts";
import type {
  BackslashApi,
  BackslashEvents,
  RequestSummary,
  ScanFinding,
  ScanProgress,
  ScanRequestInput,
  ScanResult,
  SendLogBatch,
  SendLogEntry,
} from "../../shared/src/api.ts";
import {
  EVENT_DONE,
  EVENT_FINDING,
  EVENT_PROGRESS,
  EVENT_SENDS,
} from "../../shared/src/api.ts";

type App = Caido<BackslashApi, BackslashEvents>;

const PAGE = "/backslash";
const STORAGE_KEY = "backslash:defaults";

interface Settings {
  aggressivity: "low" | "medium" | "high";
  delayMs: number;
  maxConcurrent: number;
  slotFilter: string;
  /** Surface kind of the chosen parameter. Disambiguates a name shared across surfaces. */
  slotKind: string;
  /** Measure the redirect target rather than the 3xx. Same-origin hops only. */
  followRedirects: boolean;
  maxRedirectHops: number;
  /** Fetch this after every probe and measure it instead. Empty means no observation URL. */
  observationUrl: string;
}

/**
 * Maximum log lines kept in the DOM per scan.
 *
 * A scan can emit thousands of sends. Rendering them all would make the page unusable, so the view
 * is a tail and states how many lines it is not showing rather than pretending it has everything.
 */
const LOG_VIEW_CAP = 500;

const DEFAULTS: Settings = {
  aggressivity: "medium",
  // 150ms was far too conservative once it became clear the suite was fully sequential: throughput
  // was pinned at 1/(latency + gap) with nothing in flight alongside. Pairs now run concurrently, so
  // a small gap plus real concurrency gives a usable rate while still pacing the target.
  delayMs: 25,
  maxConcurrent: 4,
  slotFilter: "",
  slotKind: "",
  // Off by default: it doubles the request count on any endpoint that redirects, and that is the
  // operator's call to make per target rather than something to spend silently.
  followRedirects: false,
  maxRedirectHops: 3,
  observationUrl: "",
};

interface Target {
  readonly requestId: string;
  readonly host: string;
  readonly port: number;
  readonly path: string;
  readonly query: string;
  readonly isTls: boolean;
}

type TabState = "pending" | "running" | "stopping" | "stopped" | "finished" | "halted" | "error";

/**
 * The persistent settings panel belonging to a tab.
 *
 * A tab used to throw its launch form away on start (`form.remove()`), which had two consequences
 * the operator hit immediately. Changing a setting meant abandoning the tab and re-launching from the
 * context menu as a brand-new scan, and the only Stop control lived in a row that appeared alongside
 * that teardown, so there was no stable place to look for it. The panel now lives for as long as the
 * tab does: disabled while a scan runs, re-enabled and re-usable when it ends.
 */
interface TabControls {
  readonly root: HTMLElement;
  /** Wraps every setting. `disabled` on a fieldset disables all descendants natively. */
  readonly fields: HTMLFieldSetElement;
  readonly startButton: HTMLButtonElement;
  /** Re-evaluates text that depends on other tabs' state, e.g. the same-host rate warning. */
  readonly refreshContext: () => void;
}

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
  readonly logBox: HTMLDivElement;
  readonly viewToggle: HTMLDivElement;
  readonly stopButton: HTMLButtonElement;
  readonly settingsToggle: HTMLButtonElement;
  /** Assigned by createTab immediately after construction, before any event can arrive. */
  controls?: TabControls;
  /** Keys of findings already drawn, so reconciliation cannot duplicate them. */
  readonly rendered: Set<string>;
  findingCount: number;
  logShown: number;
  logTotal: number;
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

/**
 * Caido theme tokens, with fallbacks for the case where a token is absent.
 *
 * Never hardcode a foreground or background: the host themes both, and a fixed hex is wrong in at
 * least one of light and dark mode.
 */
const T = {
  fg: "var(--c-fg-default, #e6edf3)",
  fgMuted: "var(--c-fg-secondary, #8b949e)",
  border: "var(--c-border, #30363d)",
  /** Input and select field background. Distinct from the page so a control reads as editable. */
  bg: "var(--c-bg-subtle, #161b22)",
  surface: "var(--c-bg-subtle, rgba(127,127,127,0.10))",
  /** The page background. Needed by the sticky status row, which must not be seen through. */
  bgDefault: "var(--c-bg-default, #0d1117)",
  danger: "var(--c-danger, #f85149)",
  warning: "var(--c-warning, #d29922)",
  success: "var(--c-success, #3fb950)",
} as const;

/**
 * Button styling, from theme tokens only.
 *
 * Outlined rather than filled, deliberately. A filled button forces you to pick a foreground that
 * contrasts with your chosen background, and that pairing is what breaks when the host switches
 * theme. An outlined button sets `color` explicitly and leaves the background transparent, so it
 * inherits whatever the host is actually using and cannot become invisible.
 *
 * Setting `color` is the part that was missing: a `<button>` carries the user-agent default
 * `color: buttontext`, which is near-black and beats inherited theme colour. A dark custom
 * background with no explicit colour therefore renders black-on-dark.
 */
function buttonStyle(kind: "primary" | "neutral" | "danger", active = true): string {
  const accent = kind === "danger" ? T.danger : kind === "primary" ? T.success : T.fgMuted;
  return (
    "padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px;background:transparent;" +
    `color:${active ? accent : T.fgMuted};border:1px solid ${active ? accent : T.border};` +
    (kind === "neutral" ? "" : "font-weight:600;")
  );
}

/**
 * Native form controls: select, input, textarea.
 *
 * These were the actual reported bug and my first pass missed them entirely. Unlike a button, a
 * `<select>` or `<input>` takes its BACKGROUND from the user agent -- the `Field` system colour,
 * which is white under a light colour-scheme -- while its `color` inherits from the page. Under
 * Caido's dark theme that inherited colour is near-white, so the result is white text on a white
 * field: the control looks blank even though it holds a value.
 *
 * Both halves therefore have to be set explicitly, and `color-scheme` too, because the dropdown
 * popup and the spinner arrows are browser chrome that CSS variables cannot reach.
 */
function styleControl(el: HTMLSelectElement | HTMLInputElement): void {
  el.style.cssText =
    `padding:4px 8px;border-radius:4px;font-size:12px;font-family:inherit;` +
    `background:${T.bg};color:${T.fg};border:1px solid ${T.border};`;
  // Tells the browser to render native chrome (dropdown list, number spinners, caret) to match.
  el.style.colorScheme = "dark light";
}

/** A tab or view-toggle: state shown by weight and an accent underline, never by a fill. */
function toggleStyle(active: boolean): string {
  return (
    "padding:4px 10px;border-radius:4px 4px 0 0;cursor:pointer;font-size:12px;" +
    `background:transparent;color:${active ? T.fg : T.fgMuted};` +
    `border:1px solid ${T.border};border-bottom:2px solid ${active ? T.success : "transparent"};` +
    (active ? "font-weight:600;" : "")
  );
}

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
  // Colour the TEXT and the border rather than filling a background. A filled badge needs a
  // foreground chosen to contrast with it, which is exactly the guess that breaks under a theme
  // change; an outlined badge inherits the theme's own foreground and cannot go unreadable.
  const accent =
    confidence === "firm" ? T.danger : confidence === "probable" ? T.warning : T.fgMuted;
  return el(
    "span",
    confidence.toUpperCase(),
    "display:inline-block;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:600;" +
      `color:${accent};border:1px solid ${accent};`,
  );
}

function renderFinding(finding: ScanFinding): HTMLElement {
  const card = el(
    "div",
    undefined,
    `border:1px solid ${T.border};border-radius:4px;padding:10px;margin-bottom:10px;${MONO}`,
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

  // Second-order findings must not read like direct ones: the anomaly was seen on another response,
  // and reproducing it by hand means knowing that. Called out in the accent colour rather than
  // buried, because "injected here, broke there" is the whole claim.
  if (finding.observedVia !== undefined && finding.observedVia.length > 0) {
    const via = el(
      "div",
      undefined,
      `margin-bottom:6px;padding:6px 8px;border-radius:4px;border:1px solid ${T.warning};color:${T.warning};`,
    );
    via.append(el("div", "measured on another response, not this endpoint's reply"));
    for (const hop of finding.observedVia) via.append(el("div", `  -> ${hop}`));
    card.append(via);
  }

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

/**
 * One transport-log line.
 *
 * Colour carries the outcome because that is the thing worth scanning for by eye: a wall of plain
 * lines with amber and red among them tells you instantly whether the target started refusing.
 */
function renderSend(entry: SendLogEntry): HTMLElement {
  const colour =
    entry.outcome === "usable"
      ? `color:${T.fgMuted};`
      : entry.outcome === "soft-fail"
        ? `color:${T.warning};`
        : `color:${T.danger};font-weight:600;`;

  const time = new Date(entry.atMs).toISOString().slice(11, 23);
  const status = entry.status === undefined ? "---" : String(entry.status);
  const size = entry.bodyLength === undefined ? "" : `${entry.bodyLength}b`;
  const rtt = entry.rttMs === undefined ? "" : `${entry.rttMs}ms`;
  const note = entry.reason === undefined ? "" : ` ${entry.reason}`;
  const saved = entry.persisted ? " [saved]" : "";
  const target = entry.target.length > 96 ? `${entry.target.slice(0, 93)}...` : entry.target;

  return el(
    "div",
    `${time}  ${String(entry.seq).padStart(5)}  ${status}  ${size.padStart(7)} ${rtt.padStart(6)}  ` +
      `${(entry.label ?? "-").padEnd(30)} ${entry.method} ${target}${note}${saved}`,
    `white-space:pre;${colour}`,
  );
}

export function init(sdk: App): void {
  let defaults = loadDefaults(sdk);
  let tabCounter = 0;

  const tabs: ScanTab[] = [];
  /** Live scans by their backend id. Events are routed strictly through this. */
  const byScanId = new Map<string, ScanTab>();

  /**
   * Events that arrived before their tab was registered.
   *
   * The backend starts the scan and begins emitting BEFORE the startScan call returns the id, while
   * the frontend can only register the id once that call resolves. Anything emitted in that window
   * used to hit the unknown-scan guard and be dropped silently -- including findings, so a scan could
   * detect something and display nothing. Buffer instead of dropping, and flush on registration.
   */
  const pending = new Map<string, ((tab: ScanTab) => void)[]>();

  /**
   * Scans whose tab has moved on: closed, or re-run with a fresh id.
   *
   * A cancelled scan keeps emitting until its in-flight pairs drain, and its DONE arrives after the
   * operator has already started the next run in the same tab. Without this, those late events either
   * repaint the new run's status with the old run's totals, or pile up in `pending` for an id that
   * will never be registered.
   */
  const retired = new Set<string>();

  function withTab(scanId: string, apply: (tab: ScanTab) => void): void {
    if (retired.has(scanId)) return;
    const tab = byScanId.get(scanId);
    if (tab !== undefined) {
      apply(tab);
      return;
    }
    const queue = pending.get(scanId) ?? [];
    queue.push(apply);
    pending.set(scanId, queue);
  }

  /** Draw a finding unless it is already on screen. Keyed so reconciliation is idempotent. */
  function showFinding(tab: ScanTab, finding: ScanFinding): void {
    const key = `${finding.probeId}|${finding.surface}|${finding.slotName}`;
    if (tab.rendered.has(key)) return;
    tab.rendered.add(key);
    tab.findingCount += 1;
    refreshTabButton(tab);
    tab.findingsBox.prepend(renderFinding(finding));
  }
  let activeTab: ScanTab | undefined;

  const body = el("div", undefined, "padding:14px;height:100%;display:flex;flex-direction:column;");
  const tabBar = el(
    "div",
    undefined,
    `display:flex;gap:4px;flex-wrap:wrap;margin-bottom:10px;border-bottom:1px solid ${T.border};padding-bottom:8px;`,
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
      other.tabButton.style.cssText = toggleStyle(other === tab);
    }
  }

  function tabLabel(tab: ScanTab): string {
    const marker =
      tab.state === "pending"
        ? "draft"
        : tab.state === "running"
          ? "running"
          : tab.state === "stopping"
            ? "stopping"
            : tab.state === "stopped"
              ? "stopped"
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
    if ((tab.state === "running" || tab.state === "stopping") && tab.scanId !== undefined) {
      // Do not orphan a running scan: stopping the traffic matters more than tidying the UI.
      void sdk.backend.cancelScan(tab.scanId);
    }
    const index = tabs.indexOf(tab);
    if (index !== -1) tabs.splice(index, 1);
    if (tab.scanId !== undefined) {
      // The scan keeps emitting until it drains; its events now have nowhere to go.
      retired.add(tab.scanId);
      byScanId.delete(tab.scanId);
      pending.delete(tab.scanId);
    }
    tab.tabButton.remove();
    tab.pane.remove();
    if (tabs.length === 0) {
      activeTab = undefined;
      paneHost.append(emptyState);
    } else if (activeTab === tab) {
      select(tabs[Math.max(0, index - 1)]!);
    }
  }

  /**
   * The tab's settings panel. Built once and kept for the life of the tab.
   *
   * Every control writes straight into `tab.settings`, so whatever is on screen when Start is pressed
   * is what gets sent. That is what makes re-running with a changed setting work without rebuilding
   * anything: the panel is the single source of truth, not a snapshot taken at launch.
   */
  function buildLaunchForm(tab: ScanTab): TabControls {
    const form = el("div", undefined, `${MONO}`);
    // Layout only. A fieldset carries a UA border, margin and padding that would draw a stray box.
    const fields = el("fieldset", undefined, "border:none;margin:0;padding:0;min-width:0;");

    const summary = el(
      "div",
      undefined,
      `border:1px solid ${T.border};border-radius:4px;padding:10px;margin-bottom:12px;`,
    );
    summary.append(el("div", "target", "opacity:0.7;margin-bottom:4px;"));
    summary.append(
      el(
        "div",
        `${tab.target.isTls ? "https" : "http"}://${tab.target.host}:${tab.target.port}${tab.target.path}` +
          (tab.target.query === "" ? "" : `?${tab.target.query}`),
      ),
    );
    summary.append(
      el("div", `request #${tab.target.requestId}`, `color:${T.fgMuted};margin-top:4px;`),
    );
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
    styleControl(aggressivity);
    for (const option of Array.from(aggressivity.options)) {
      // Options are rendered by the OS popup, which ignores inherited colour, so set them directly.
      option.style.background = T.bg;
      option.style.color = T.fg;
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
    styleControl(delay);
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
    styleControl(concurrency);
    concurrency.style.width = "80px";
    concurrency.onchange = () => {
      tab.settings = {
        ...tab.settings,
        maxConcurrent: Math.max(1, Number.parseInt(concurrency.value, 10) || 1),
      };
    };

    /**
     * The parameter picker.
     *
     * Populated from the backend, because enumeration needs the raw request bytes and only the backend
     * can fetch them. Starts as a one-option select saying so: a picker that appears empty is
     * indistinguishable from a request with nothing injectable.
     */
    const slot = el("select");
    styleControl(slot);
    slot.style.maxWidth = "420px";

    const slotOption = (label: string, value: string): HTMLOptionElement => {
      const option = el("option", label) as HTMLOptionElement;
      option.value = value;
      // The OS popup ignores inherited colour, so options are painted directly.
      option.style.background = T.bg;
      option.style.color = T.fg;
      return option;
    };

    // Value encoding: "" is all parameters, otherwise "kind name". The kind travels with the name
    // because names are not unique across surfaces -- `?q=` and a body `q=` are both "q".
    const setSlotOptions = (summary?: RequestSummary): void => {
      slot.replaceChildren();
      slot.append(slotOption("all parameters", ""));
      for (const s of summary?.slots ?? []) {
        const shown =
          s.preview === ""
            ? `${s.name}  [${s.kind}]`
            : `${s.name} = ${s.preview}  [${s.kind}]`;
        slot.append(slotOption(shown, `${s.kind} ${s.name}`));
      }
      const wanted =
        tab.settings.slotFilter === ""
          ? ""
          : `${tab.settings.slotKind} ${tab.settings.slotFilter}`;
      // Only re-select a remembered choice if this request actually has it.
      slot.value = Array.from(slot.options).some((o) => o.value === wanted) ? wanted : "";
      if (slot.value === "") {
        tab.settings = { ...tab.settings, slotFilter: "", slotKind: "" };
      }
    };

    slot.onchange = () => {
      const [kind, name] = slot.value === "" ? ["", ""] : slot.value.split(" ");
      tab.settings = { ...tab.settings, slotFilter: name ?? "", slotKind: kind ?? "" };
    };

    setSlotOptions();

    /** Body shape, deferred surfaces, and parse errors: why an expected parameter is not listed. */
    const surfaceNote = el("div", undefined, "opacity:0.7;font-size:11px;margin:2px 0 0 128px;");

    void (async () => {
      const result = await sdk.backend.inspectRequest(tab.target.requestId);
      if (result.kind === "error") {
        // Say it plainly. Silently leaving "all parameters" would let a scan run against a request the
        // parser could not read, and report nothing found.
        slot.replaceChildren();
        slot.append(slotOption("could not read this request", ""));
        surfaceNote.textContent = result.error;
        surfaceNote.style.color = T.danger;
        return;
      }
      const summary = result.value;
      setSlotOptions(summary);

      const notes: string[] = [
        `${summary.slots.length} injectable parameter(s) on this ${summary.method} request`,
      ];
      if (summary.bodyLength > 0) {
        notes.push(`body ${summary.bodyLength} bytes${summary.contentType === undefined ? "" : ` (${summary.contentType})`}`);
      }
      if (summary.slots.length === 0) {
        notes.push("nothing to scan: no parameter on this request is injectable yet");
      }
      for (const d of summary.deferred) notes.push(`not injectable — ${d.kind}: ${d.reason}`);
      surfaceNote.textContent = notes.join(". ");
      surfaceNote.style.color =
        summary.slots.length === 0 || summary.deferred.length > 0 ? T.warning : T.fgMuted;
    })();

    const budgetHint = (["low", "medium", "high"] as const)
      .map((level) => {
        const b = AGGRESSIVITY_BUDGET[level];
        return `${level} ${b.probes ?? "all"} probes / ${b.slots} params`;
      })
      .join(", ");
    fields.append(row("aggressivity", aggressivity, budgetHint));
    fields.append(
      row("delay ms", delay, "minimum gap between the START of one request and the next"),
    );
    fields.append(
      row(
        "concurrency",
        concurrency,
        "independent probe pairs in flight at once. The two arms of a pair are always sent " +
          "back-to-back, so this is how many pairs overlap, not how many requests split a pair.",
      ),
    );
    const slotRow = row("parameter", slot, undefined);
    slotRow.append(surfaceNote);
    fields.append(slotRow);

    // ---- Where the result is measured ----
    // Template injection often renders somewhere other than where it was injected. These two options
    // point the measurement at that other place; everything else about detection is unchanged.
    const follow = el("input");
    follow.type = "checkbox";
    follow.checked = tab.settings.followRedirects;
    // A checkbox holds no text, so it needs the colour-scheme hint only: a background would paint a
    // filled box behind the checkmark.
    follow.style.colorScheme = "dark light";

    const hops = el("input");
    hops.type = "number";
    hops.min = "1";
    hops.max = "10";
    hops.value = String(tab.settings.maxRedirectHops);
    styleControl(hops);
    hops.style.width = "70px";
    hops.onchange = () => {
      tab.settings = {
        ...tab.settings,
        maxRedirectHops: Math.max(1, Math.min(10, Number.parseInt(hops.value, 10) || 3)),
      };
    };

    const observe = el("input");
    observe.type = "text";
    observe.placeholder = "/profile or https://host/page";
    observe.value = tab.settings.observationUrl;
    styleControl(observe);
    observe.style.width = "280px";
    observe.onchange = () => {
      tab.settings = { ...tab.settings, observationUrl: observe.value.trim() };
      refreshPlan();
    };

    const syncHops = (): void => {
      hops.disabled = !follow.checked;
      hops.style.opacity = follow.checked ? "1" : "0.5";
    };
    follow.onchange = () => {
      tab.settings = { ...tab.settings, followRedirects: follow.checked };
      syncHops();
      refreshPlan();
    };
    syncHops();

    fields.append(
      row(
        "follow redirects",
        follow,
        "measure the redirect target instead of the 3xx. Same-origin hops only: a Location is " +
          "attacker-controlled in exactly these bugs, so an off-origin hop is never followed.",
      ),
    );
    fields.append(row("max hops", hops, "how far to follow a redirect chain"));
    fields.append(
      row(
        "observe URL",
        observe,
        "fetch this after every probe and measure IT — the stored case, injected at A and rendered " +
          "at B. A bare path resolves against this request's origin. Forces one pair at a time.",
      ),
    );
    form.append(fields);

    // Not a choice: every request is saved. Stated so the volume is not a surprise.
    form.append(
      el(
        "div",
        `Every request is saved to Caido's HTTP history and is replayable there. Expect roughly ` +
          `50-150 requests per parameter, so a full scan of this request will add a few hundred to ` +
          `a few thousand entries.`,
        "opacity:0.6;font-size:11px;margin-bottom:10px;",
      ),
    );

    // Two concurrent scans have independent throttles, so the combined rate against one host is the
    // sum. Worth saying out loud before the operator doubles their own request rate by accident.
    // Re-evaluated on every re-run rather than fixed at build time: the panel now outlives the launch,
    // so a warning captured once would go stale the moment another tab started or finished.
    const hostWarning = el(
      "div",
      `A scan is already running against ${tab.target.host}. Each scan throttles independently, ` +
        "so the combined request rate will be the sum of both.",
      `border:1px solid ${T.warning};color:${T.warning};background:transparent;` +
        "border-radius:4px;padding:8px;margin-bottom:10px;font-size:11px;display:none;",
    );
    form.append(hostWarning);

    // What this scan will actually do, restated for the chosen level. The operator reported that
    // "high" seemed to probe less than expected; making the resolved budget visible removes the
    // guesswork rather than asking them to infer it from the send counter.
    const plan = el("div", undefined, `color:${T.fgMuted};font-size:11px;margin-bottom:10px;`);
    const refreshPlan = (): void => {
      const b = AGGRESSIVITY_BUDGET[tab.settings.aggressivity];
      const lines = [
        `At ${tab.settings.aggressivity}: up to ${b.probes ?? "all"} probes ` +
          `against up to ${b.slots} parameter(s).`,
      ];
      // Say the cost out loud. Observation is a second request per arm, so it roughly doubles the
      // traffic, and the operator should see that before starting rather than infer it from the
      // send counter afterwards.
      if (tab.settings.observationUrl !== "") {
        lines.push(
          `Measuring ${tab.settings.observationUrl} after every probe: about 2x the requests, ` +
            "and pairs run ONE AT A TIME because a shared page cannot be measured in parallel.",
        );
      } else if (tab.settings.followRedirects) {
        lines.push(
          `Measuring the redirect target where one is returned: up to ${tab.settings.maxRedirectHops} ` +
            "extra request(s) per arm on endpoints that redirect, none on those that do not.",
        );
      }
      plan.textContent = lines.join(" ");
    };
    refreshPlan();
    aggressivity.addEventListener("change", refreshPlan);
    form.append(plan);

    const actions = el("div", undefined, "display:flex;gap:8px;align-items:center;");
    const startButton = el("button", "Start scan");
    startButton.style.cssText = buttonStyle("primary");
    const rememberButton = el("button", "Save as defaults");
    rememberButton.style.cssText = buttonStyle("neutral");
    rememberButton.onclick = () => {
      defaults = { ...tab.settings };
      saveDefaults(sdk, defaults);
      rememberButton.textContent = "saved";
      setTimeout(() => (rememberButton.textContent = "Save as defaults"), 1200);
    };

    startButton.onclick = () => {
      startButton.disabled = true;
      startButton.textContent = "starting...";
      void launch(tab);
    };

    actions.append(startButton, rememberButton);
    form.append(actions);

    const refreshContext = (): void => {
      refreshPlan();
      const sameHostRunning = tabs.some(
        (other) =>
          other !== tab &&
          (other.state === "running" || other.state === "stopping") &&
          other.target.host === tab.target.host,
      );
      hostWarning.style.display = sameHostRunning ? "block" : "none";
    };
    refreshContext();

    return { root: form, fields, startButton, refreshContext };
  }

  /**
   * Clear a previous run so the tab can be re-used.
   *
   * The old scan id is retired rather than merely unmapped: a stopped scan drains its in-flight pairs
   * and emits DONE afterwards, which would otherwise overwrite the new run's status with the old
   * run's totals.
   */
  function resetResults(tab: ScanTab): void {
    if (tab.scanId !== undefined) {
      retired.add(tab.scanId);
      byScanId.delete(tab.scanId);
      pending.delete(tab.scanId);
      delete tab.scanId;
    }
    tab.rendered.clear();
    tab.findingCount = 0;
    tab.logShown = 0;
    tab.logTotal = 0;
    tab.findingsBox.replaceChildren();
    tab.logBox.replaceChildren();
    tab.viewToggle.title = "";
  }

  /** Reflect a tab's state in its controls. The single place that decides what is clickable. */
  function applyState(tab: ScanTab, state: TabState): void {
    tab.state = state;
    const busy = state === "running" || state === "stopping";
    const controls = tab.controls;
    if (controls !== undefined) {
      controls.fields.disabled = busy;
      controls.startButton.disabled = busy;
      controls.startButton.textContent = busy
        ? state === "running"
          ? "scanning..."
          : "stopping..."
        : state === "pending"
          ? "Start scan"
          : "Re-run scan";
      controls.startButton.style.cssText = buttonStyle("primary", !busy);
      if (!busy) controls.refreshContext();
    }
    // Stop is always on screen, disabled when there is nothing to stop. An enabled-only control that
    // materialises and vanishes is a control the operator cannot find when they need it.
    tab.stopButton.disabled = state !== "running";
    tab.stopButton.textContent = state === "stopping" ? "stopping..." : "Stop";
    tab.stopButton.style.cssText = buttonStyle("danger", state === "running");
    refreshTabButton(tab);
  }

  function setSettingsVisible(tab: ScanTab, visible: boolean): void {
    const controls = tab.controls;
    if (controls === undefined) return;
    controls.root.style.display = visible ? "block" : "none";
    tab.settingsToggle.textContent = visible ? "Hide settings" : "Settings";
    tab.settingsToggle.style.cssText = buttonStyle("neutral");
    if (visible) controls.refreshContext();
  }

  async function launch(tab: ScanTab): Promise<void> {
    resetResults(tab);
    const input: ScanRequestInput = {
      requestId: tab.target.requestId,
      aggressivity: tab.settings.aggressivity,
      delayMs: tab.settings.delayMs,
      maxConcurrent: tab.settings.maxConcurrent,
      ...(tab.settings.slotFilter === ""
        ? {}
        : {
            slotFilter: tab.settings.slotFilter,
            ...(tab.settings.slotKind === "" ? {} : { slotKind: tab.settings.slotKind }),
          }),
      ...(tab.settings.followRedirects
        ? { followRedirects: true, maxRedirectHops: tab.settings.maxRedirectHops }
        : {}),
      ...(tab.settings.observationUrl === ""
        ? {}
        : { observationUrl: tab.settings.observationUrl }),
    };

    // Mark the tab busy before awaiting: the operator has committed, and Stop has to be live for the
    // whole window in which requests can be in flight, not only after the id comes back.
    applyState(tab, "running");
    tab.statusLine.style.display = "block";
    tab.statusLine.textContent = "starting";

    const response = await sdk.backend.startScan(input);
    if (response.kind === "error") {
      applyState(tab, "error");
      tab.statusLine.textContent = `error: ${response.error}`;
      setSettingsVisible(tab, true);
      return;
    }

    tab.scanId = response.value.scanId;
    // A late Stop, pressed while the id was still in flight, has already been recorded as a state
    // change; honour it now that there is something to cancel.
    if (tab.state === "stopping") void sdk.backend.cancelScan(tab.scanId);

    tab.statusLine.textContent = `${tab.scanId} starting`;
    tab.viewToggle.style.display = "flex";
    tab.findingsBox.style.display = "block";
    // Collapse the settings while the scan runs so the status and Stop stay at the top of the pane
    // without scrolling. Re-opened when the run ends, which is when they become useful again.
    setSettingsVisible(tab, false);

    // Registration and replay go LAST. A short scan can complete before startScan resolves, so its
    // DONE is already buffered here; replaying it before the lines above would let them overwrite a
    // finished run with "starting" and re-hide the settings on a tab that is no longer busy.
    byScanId.set(tab.scanId, tab);
    for (const apply of pending.get(tab.scanId) ?? []) apply(tab);
    pending.delete(tab.scanId);
  }

  function createTab(target: Target): ScanTab {
    tabCounter += 1;
    emptyState.remove();

    const tabButton = el("button");
    tabButton.style.cssText = toggleStyle(false);

    const closeButton = el("span", " x", "margin-left:6px;opacity:0.6;");

    const pane = el("div", undefined, "display:none;");
    // Sticky so the run controls stay reachable while the operator scrolls a long findings list. This
    // row is the tab's permanent control surface: status, settings toggle and Stop, always present.
    const statusRow = el(
      "div",
      undefined,
      "display:flex;gap:10px;align-items:center;margin-bottom:10px;position:sticky;top:0;" +
        `background:${T.bgDefault};padding:4px 0;z-index:1;`,
    );
    const statusLine = el("div", undefined, `${MONO}opacity:0.85;display:none;flex:1;`);
    const settingsToggle = el("button", "Settings");
    settingsToggle.style.cssText = buttonStyle("neutral");
    const stopButton = el("button", "Stop");
    stopButton.style.cssText = buttonStyle("danger", false);
    stopButton.disabled = true;
    statusRow.append(statusLine, settingsToggle, stopButton);
    const viewToggle = el("div", undefined, "display:none;gap:6px;margin-bottom:8px;");
    const findingsBox = el("div", undefined, "display:none;");
    const logBox = el("div", undefined, `display:none;${MONO}font-size:11px;line-height:1.45;`);

    const tab: ScanTab = {
      key: `tab-${tabCounter}`,
      state: "pending",
      target,
      settings: { ...defaults },
      tabButton,
      pane,
      statusLine,
      findingsBox,
      logBox,
      viewToggle,
      stopButton,
      settingsToggle,
      rendered: new Set<string>(),
      findingCount: 0,
      logShown: 0,
      logTotal: 0,
    };

    // Findings and the raw transport log are different questions: "what did you conclude" and
    // "what did you actually send". Both matter, so they are peers rather than one nested in the other.
    const showFindings = el("button", "Findings");
    const showLog = el("button", "Requests");
    const setView = (view: "findings" | "requests"): void => {
      findingsBox.style.display = view === "findings" ? "block" : "none";
      logBox.style.display = view === "requests" ? "block" : "none";
      showFindings.style.cssText = toggleStyle(view === "findings");
      showLog.style.cssText = toggleStyle(view === "requests");
    };
    showFindings.onclick = () => setView("findings");
    showLog.onclick = () => setView("requests");
    setView("findings");
    viewToggle.append(showFindings, showLog);

    stopButton.onclick = () => {
      if (tab.state !== "running") return;
      // Optimistic state change: the operator pressed Stop and must see it took effect immediately,
      // even though the run finishes asynchronously once the transport stops accepting work.
      applyState(tab, "stopping");
      tab.statusLine.textContent =
        tab.scanId === undefined
          ? "stopping — no further requests will be sent"
          : `${tab.scanId} stopping — no further requests will be sent`;
      // Undefined only in the window before startScan resolves; launch() honours the pending stop.
      if (tab.scanId !== undefined) void sdk.backend.cancelScan(tab.scanId);
    };

    settingsToggle.onclick = () => {
      setSettingsVisible(tab, tab.controls?.root.style.display === "none");
    };

    tabButton.onclick = () => select(tab);
    closeButton.onclick = (event) => {
      event.stopPropagation();
      closeTab(tab);
    };
    tabButton.textContent = tabLabel(tab);
    tabButton.append(closeButton);

    tab.controls = buildLaunchForm(tab);
    pane.append(statusRow, tab.controls.root, viewToggle, findingsBox, logBox);
    applyState(tab, "pending");
    // Sets display explicitly rather than leaving it unset, so the toggle's read of it is unambiguous.
    setSettingsVisible(tab, true);

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
    withTab(progress.scanId, (tab) => {
    tab.statusLine.textContent =
      `${progress.scanId}  ${progress.phase}  ` +
      `probes ${progress.probesDone}/${progress.probesTotal}  ` +
      `sends ${progress.sends}  findings ${progress.findings}`;
    });
  });

  sdk.backend.onEvent(EVENT_FINDING, (finding: ScanFinding) => {
    withTab(finding.scanId, (tab) => showFinding(tab, finding));
  });

  sdk.backend.onEvent(EVENT_SENDS, (batch: SendLogBatch) => {
    withTab(batch.scanId, (tab) => {
    for (const entry of batch.entries) {
      tab.logBox.append(renderSend(entry));
      tab.logShown += 1;
    }
    tab.logTotal = batch.totalSends;

    // Trim the oldest lines rather than letting the DOM grow without bound.
    while (tab.logShown > LOG_VIEW_CAP && tab.logBox.firstChild !== null) {
      tab.logBox.firstChild.remove();
      tab.logShown -= 1;
    }

    // Say plainly when the view is a tail: a truncated log that looks complete is worse than none.
    const hidden = tab.logTotal - tab.logShown;
    tab.viewToggle.title =
      hidden > 0
        ? `showing the last ${tab.logShown} of ${tab.logTotal} sends`
        : `${tab.logTotal} sends`;
    });
  });

  sdk.backend.onEvent(EVENT_DONE, (result: ScanResult) => {
    withTab(result.scanId, (tab) => {
    // Reconcile: the completion payload carries every finding, so anything whose live event was
    // missed for any reason still gets drawn. showFinding dedupes, so this is safe to run always.
    for (const finding of result.findings) showFinding(tab, finding);

    // Re-opens the settings and turns Start into Re-run: the tab becomes reusable rather than spent.
    applyState(
      tab,
      result.haltReason === undefined
        ? "finished"
        : result.haltReason === "cancelled"
          ? "stopped"
          : "halted",
    );
    setSettingsVisible(tab, true);
    // Another tab waiting on this host may now be clear to run.
    for (const other of tabs) other.controls?.refreshContext();

    // An operator stop and a target that stopped answering are different outcomes and must not read
    // the same: one is a decision, the other is a warning about the measurement.
    const suffix =
      result.haltReason === undefined
        ? ""
        : result.haltReason === "cancelled"
          ? "  STOPPED by operator"
          : `  HALTED (${result.haltReason})`;
    tab.statusLine.textContent =
      `${result.scanId} ${tab.state}  sends ${result.sends}  findings ${result.findings.length}${suffix}`;

    if (tab.logTotal > tab.logShown) {
      tab.logBox.prepend(
        el(
          "div",
          `... ${tab.logTotal - tab.logShown} earlier sends not shown (view keeps the last ${LOG_VIEW_CAP})`,
          "opacity:0.6;margin-bottom:6px;",
        ),
      );
    }

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
      const message =
        tab.state === "stopped"
          ? "Stopped before finishing. Nothing found so far, which says nothing about what was not reached."
          : unmeasured.length === 0
            ? "No anomalies. Every probe was measured and found nothing."
            : `No findings, but ${unmeasured.length} probe(s) could not be measured cleanly. A blinded measurement is not a clean result — see the Requests tab.`;
      tab.findingsBox.append(el("div", message, `${MONO}opacity:0.8;`));
    }
    });
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
