import type { Caido } from "@caido/sdk-frontend";
import type { API, BackendEvents } from "@bypass-403/backend";

export type FrontendSDK = Caido<API, BackendEvents>;

export type ResultRow = {
  jobId: string;
  variation: string;
  detail: string;
  method: string;
  url: string;
  statusCode: number;
  contentLength: number;
  baselineStatus: number;
  baselineLength: number;
  interesting: boolean;
  requestId?: string;
  receivedAt: number;
};

export type JobMeta = {
  jobId: string;
  targetUrl: string;
  total: number;
  baselineStatus: number;
  baselineLength: number;
  startedAt: number;
  doneAt?: number;
  interestingCount?: number;
};
