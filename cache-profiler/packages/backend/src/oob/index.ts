// OOB controller: owns the interactsh session, persists the RSA keypair under the plugin data
// dir, mints per-core payloads, polls on a timer within an extendable window, and correlates
// inbound interactions back to the dot-free `core` token that names a probed header.
import { fetch } from "caido:http";
import type { SDK } from "caido:plugin";
import { access, mkdir, readFile, rename, writeFile } from "fs/promises";

import type { BackendEvents } from "../types.js";
import { ensureKeysWithStorage, generateRandomString } from "./crypto.js";
import { interactshProvider } from "./interactsh.js";
import type { Interaction, ProviderSession } from "./types.js";

type AnySDK = SDK<never, BackendEvents>;

const KEY_FILE = "oob-rsa-keypair.json";

export type OobStatus = {
  enabled: boolean;
  serverHost: string;
  correlationId: string;
  interactions: number;
  windowEndsInMs: number;
  lastError?: string; // last enable/poll failure, surfaced to the operator
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class OobController {
  private session: ProviderSession | undefined;
  private serverHost = "";
  private correlationId = "";
  private pollMs = 5000;
  private readonly interactions: Interaction[] = [];
  private readonly seen = new Set<string>();
  private timer: ReturnType<typeof setInterval> | undefined;
  private windowUntil = 0;
  private lastError: string | undefined;
  private readonly listeners: ((i: Interaction) => void)[] = [];

  constructor(
    private readonly sdk: AnySDK,
    private readonly log: (m: string) => void,
  ) {}

  ready(): boolean {
    return this.session !== undefined;
  }

  onInteraction(cb: (i: Interaction) => void): void {
    this.listeners.push(cb);
  }

  // A payload routed to our session for a dot-free `core` token. interactsh routes any label
  // prefixed with the correlationId, so the core rides as the attributable suffix.
  mintPayload(core: string): string {
    return `${this.correlationId}${core}.${this.serverHost}`;
  }

  // Interactions attributed to a core (its token appears in the hit's id / request).
  interactionsFor(core: string): Interaction[] {
    const c = core.toLowerCase();
    return this.interactions.filter(
      (i) =>
        i.fullId.toLowerCase().includes(c) ||
        i.uniqueId.toLowerCase().includes(c) ||
        i.rawRequest.toLowerCase().includes(c),
    );
  }

  // Keep polling/correlating until now + ms (scan start/end, and the Extend button).
  keepAlive(ms: number): void {
    this.windowUntil = Math.max(this.windowUntil, Date.now() + ms);
    this.startLoop();
  }

  status(): OobStatus {
    return {
      enabled: this.ready(),
      serverHost: this.serverHost,
      correlationId: this.correlationId,
      interactions: this.interactions.length,
      windowEndsInMs: this.ready() ? Math.max(0, this.windowUntil - Date.now()) : 0,
      lastError: this.lastError,
    };
  }

  // Register + self-test gate. Returns an error string on failure, undefined on success.
  async enable(
    serverUrl: string,
    token: string | undefined,
    pollMs: number,
  ): Promise<string | undefined> {
    this.lastError = undefined;
    try {
      await this.loadKeys();
      const reg = await interactshProvider.register({ serverUrl, token });
      if (!reg.ok) {
        this.lastError = `register failed: ${reg.error}`;
        return this.lastError;
      }

      this.session = reg.value.providerSession;
      this.correlationId = this.session.correlationId ?? "";
      this.serverHost = new URL(serverUrl).host;
      this.pollMs = pollMs > 0 ? pollMs : 5000;
      this.windowUntil = Date.now() + 60_000; // keep poll alive during the self-test

      const testErr = await this.selfTest();
      if (testErr !== undefined) {
        await this.disable();
        this.lastError = `self-test failed: ${testErr}`;
        return this.lastError;
      }
      this.keepAlive(this.pollMs * 2);
      this.log(`oob: enabled (server ${this.serverHost}, payload root ready)`);
      return undefined;
    } catch (e) {
      this.session = undefined;
      this.lastError = String(e);
      return this.lastError;
    }
  }

  async disable(): Promise<void> {
    this.stopLoop();
    const s = this.session;
    this.session = undefined;
    this.windowUntil = 0;
    if (s !== undefined) {
      try {
        await interactshProvider.deregister(s);
      } catch {
        /* best-effort */
      }
    }
  }

  // ---- internals -------------------------------------------------------

  // End-to-end "everything works" check: mint a payload, trigger a lookup against it, then poll
  // and confirm we decrypt our own interaction back.
  private async selfTest(): Promise<string | undefined> {
    const core = `selftest${generateRandomString(8)}`;
    const payload = this.mintPayload(core);
    try {
      await fetch(`http://${payload}/`, { method: "GET" });
    } catch {
      /* the DNS/HTTP lookup itself is the signal; response is irrelevant */
    }
    for (let attempt = 0; attempt < 6; attempt++) {
      await sleep(1000);
      await this.pollOnce();
      if (this.interactionsFor(core).length > 0) return undefined;
    }
    return "no interaction observed for the self-test payload (check server URL, token, network)";
  }

  private async loadKeys(): Promise<void> {
    const file = `${this.sdk.meta.path()}/${KEY_FILE}`;
    let cached: string | undefined;
    try {
      await access(file);
      cached = await readFile(file, "utf-8");
    } catch {
      cached = undefined;
    }
    await ensureKeysWithStorage(
      () => cached,
      async (data) => {
        try {
          await mkdir(this.sdk.meta.path(), { recursive: true });
          const tmp = `${file}.tmp`;
          await writeFile(tmp, data);
          await rename(tmp, file);
        } catch (e) {
          this.log(`oob: key persist failed: ${String(e)}`);
        }
      },
    );
  }

  private startLoop(): void {
    if (this.timer !== undefined || this.session === undefined) return;
    this.timer = setInterval(() => void this.tick(), this.pollMs);
  }

  private stopLoop(): void {
    if (this.timer !== undefined) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  private async tick(): Promise<void> {
    if (Date.now() > this.windowUntil) {
      this.stopLoop();
      return;
    }
    await this.pollOnce();
  }

  private async pollOnce(): Promise<void> {
    if (this.session === undefined) return;
    const r = await interactshProvider.poll(this.session);
    if (!r.ok) {
      if (r.error === "SESSION_EXPIRED") {
        this.lastError = "interactsh session expired — re-enable to resume";
        this.log("oob: interactsh session expired — stopping poller");
        this.stopLoop();
        this.session = undefined;
      }
      return;
    }
    for (const it of r.value) {
      if (this.seen.has(it.id)) continue;
      this.seen.add(it.id);
      this.interactions.push(it);
      for (const cb of this.listeners) {
        try {
          cb(it);
        } catch {
          /* listener errors must not break polling */
        }
      }
    }
  }
}
