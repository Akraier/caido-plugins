import type { SDK } from "caido:plugin";

// Runtime-tunable configuration. Mirrored in the frontend (packages/frontend/src/types.ts).
export type ReflectorConfig = {
  enabled: boolean;
  verbose: boolean;
  maxBodyBytes: number;
  contentTypeAllow: string[];
};

// A reflection finding pushed live to the frontend table.
export type FindingRow = {
  state: string;
  method: string;
  url: string;
  source: string;
  param: string;
  context: string;
  poc: string;
};

// RPC surface exposed to the frontend via sdk.backend.*.
export type API = {
  getConfig: () => ReflectorConfig;
  setConfig: (patch: Partial<ReflectorConfig>) => ReflectorConfig;
  getEnabled: () => boolean;
  setEnabled: (value: boolean) => boolean;
  getCacheSize: () => number;
  clearCache: () => number;
};

// Events pushed from backend to frontend via sdk.api.send / sdk.backend.onEvent.
export type BackendEvents = {
  "reflector:finding": (row: FindingRow) => void;
  "reflector:log": (line: string) => void;
};

export type ReflectorSDK = SDK<API, BackendEvents>;
