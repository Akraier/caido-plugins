import type { Database } from "sqlite";
import type { ReflectorConfig, ReflectorSDK } from "./api";

// Runtime configuration, persisted in the plugin's sqlite DB (settings key/value
// table) so choices survive Caido restarts / plugin reloads. Defaults keep the
// original hard-coded behaviour until the operator changes anything.
const DEFAULT_CONTENT_TYPES = [
  "text/html",
  "application/xhtml",
  "application/xml",
  "text/xml",
  "application/json",
  "text/plain",
  "application/javascript",
  "text/javascript",
];

const config: ReflectorConfig = {
  enabled: true,
  verbose: true,
  maxBodyBytes: 2 * 1024 * 1024,
  contentTypeAllow: [...DEFAULT_CONTENT_TYPES],
};

let dbPromise: Promise<Database> | null = null;

async function getDb(sdk: ReflectorSDK): Promise<Database> {
  if (!dbPromise) {
    dbPromise = (async () => {
      const db = await sdk.meta.db();
      await db.exec(
        "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
      );
      return db;
    })();
  }
  return dbPromise;
}

function snapshot(): ReflectorConfig {
  return {
    enabled: config.enabled,
    verbose: config.verbose,
    maxBodyBytes: config.maxBodyBytes,
    contentTypeAllow: [...config.contentTypeAllow],
  };
}

function applyRow(key: string, value: string): void {
  switch (key) {
    case "enabled":
      config.enabled = value === "1";
      break;
    case "verbose":
      config.verbose = value === "1";
      break;
    case "maxBodyBytes": {
      const n = parseInt(value, 10);
      if (Number.isFinite(n) && n > 0) config.maxBodyBytes = n;
      break;
    }
    case "contentTypeAllow": {
      try {
        const arr = JSON.parse(value);
        if (Array.isArray(arr)) config.contentTypeAllow = arr.map(String);
      } catch {
        // ignore malformed row
      }
      break;
    }
    default:
      break;
  }
}

function serialize(key: keyof ReflectorConfig): string {
  switch (key) {
    case "enabled":
      return config.enabled ? "1" : "0";
    case "verbose":
      return config.verbose ? "1" : "0";
    case "maxBodyBytes":
      return String(config.maxBodyBytes);
    case "contentTypeAllow":
      return JSON.stringify(config.contentTypeAllow);
    default:
      return "";
  }
}

async function persist(sdk: ReflectorSDK, keys: Array<keyof ReflectorConfig>): Promise<void> {
  if (keys.length === 0) return;
  try {
    const db = await getDb(sdk);
    for (const k of keys) {
      const stmt = await db.prepare(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
      );
      const v = serialize(k);
      await stmt.run(k, v, v);
    }
  } catch (e) {
    sdk.console.log(`[reflector] settings persist failed: ${String(e)}`);
  }
}

export async function loadConfig(sdk: ReflectorSDK): Promise<ReflectorConfig> {
  try {
    const db = await getDb(sdk);
    const stmt = await db.prepare("SELECT key, value FROM settings");
    const rows = await stmt.all<{ key: string; value: string }>();
    for (const r of rows) applyRow(r.key, r.value);
  } catch (e) {
    sdk.console.log(`[reflector] settings load failed: ${String(e)}`);
  }
  return snapshot();
}

export function getConfig(): ReflectorConfig {
  return snapshot();
}

export function isEnabled(): boolean {
  return config.enabled;
}

export function isVerbose(): boolean {
  return config.verbose;
}

// In-memory state is authoritative for behaviour and updated synchronously;
// the sqlite write is fired in the background (best-effort, non-blocking).
export function setConfig(sdk: ReflectorSDK, patch: Partial<ReflectorConfig>): ReflectorConfig {
  const changed: Array<keyof ReflectorConfig> = [];
  if (typeof patch.enabled === "boolean") {
    config.enabled = patch.enabled;
    changed.push("enabled");
  }
  if (typeof patch.verbose === "boolean") {
    config.verbose = patch.verbose;
    changed.push("verbose");
  }
  if (typeof patch.maxBodyBytes === "number" && Number.isFinite(patch.maxBodyBytes) && patch.maxBodyBytes > 0) {
    config.maxBodyBytes = Math.floor(patch.maxBodyBytes);
    changed.push("maxBodyBytes");
  }
  if (Array.isArray(patch.contentTypeAllow)) {
    config.contentTypeAllow = patch.contentTypeAllow
      .map((s) => String(s).trim().toLowerCase())
      .filter((s) => s.length > 0);
    changed.push("contentTypeAllow");
  }
  void persist(sdk, changed);
  return snapshot();
}

export function setEnabled(sdk: ReflectorSDK, value: boolean): boolean {
  return setConfig(sdk, { enabled: value }).enabled;
}
