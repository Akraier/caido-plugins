import type { Caido } from "@caido/sdk-frontend";

// Mirrors packages/backend/src/api.ts — keep in sync manually.
export type ReflectorConfig = {
  enabled: boolean;
  verbose: boolean;
  maxBodyBytes: number;
  contentTypeAllow: string[];
};

export type FindingRow = {
  state: string;
  method: string;
  url: string;
  source: string;
  param: string;
  context: string;
  poc: string;
};

export type BackendAPI = {
  getConfig: () => ReflectorConfig;
  setConfig: (patch: Partial<ReflectorConfig>) => ReflectorConfig;
  getEnabled: () => boolean;
  setEnabled: (value: boolean) => boolean;
  getCacheSize: () => number;
  clearCache: () => number;
};

export type BackendEvents = {
  "reflector:finding": (row: FindingRow) => void;
  "reflector:log": (line: string) => void;
};

export type FrontendSDK = Caido<BackendAPI, BackendEvents>;
