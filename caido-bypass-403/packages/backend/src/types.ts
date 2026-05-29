export type Result<T> =
  | { kind: "Ok"; value: T }
  | { kind: "Error"; error: string };

export type BypassSettings = {
  headers: string[];
  ips: string[];
  pathMutationIds: string[];
  autoMode: boolean;
  scopeGated: boolean;
  concurrency: number;
};

export type BypassResultRow = {
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
};

export type BypassJobStart = {
  jobId: string;
  targetUrl: string;
  total: number;
  baselineStatus: number;
  baselineLength: number;
};

export type BypassJobDone = {
  jobId: string;
  interestingCount: number;
  totalCount: number;
};

export type BackendEvents = {
  "bypass-403:job-start": (data: BypassJobStart) => void;
  "bypass-403:result": (data: BypassResultRow) => void;
  "bypass-403:job-done": (data: BypassJobDone) => void;
  "bypass-403:error": (data: { jobId: string; message: string }) => void;
};
